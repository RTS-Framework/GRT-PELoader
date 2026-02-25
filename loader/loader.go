//go:build windows

package loader

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

const (
	null    = 0
	noError = 0
)

type errno struct {
	method string
	errno  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("PELoaderM.%s return errno: 0x%08X", e.method, e.errno)
}

// Config contains configuration about initialize PE Loader.
type Config struct {
	// use custom FindAPI from Gleam-RT for hook.
	FindAPI uintptr

	// PE image memory address.
	Image uintptr

	// for hook GetCommandLineA and GetCommandLineW,
	// if them are NULL, call original GetCommandLine.
	CommandLineA uintptr
	CommandLineW uintptr

	// wait main thread exit if it is an exe image.
	WaitMain bool

	// if failed to load library, can continue it.
	AllowSkipDLL bool

	// create NUL file for set StdInput, StdOutput and
	// StdError for ignore console input/output.
	// If it is true, it will overwrite standard handles.
	IgnoreStdIO bool

	// set standard handles for hook GetStdHandle,
	// if them are NULL, call original GetStdHandle.
	StdInput  uintptr
	StdOutput uintptr
	StdError  uintptr

	// not running PE image after load.
	NotAutoRun bool

	// not stop runtime when call ExitProcess.
	NotStopRuntime bool

	// not erase instructions after call functions about Init or Exit.
	NotEraseInstruction bool

	// adjust current memory page protect.
	NotAdjustProtect bool
}

// PELoaderM contains exported methods of PE Loader.
type PELoaderM struct {
	// absolute memory address about PE image base.
	ImageBase uintptr

	// absolute memory address about PE entry point.
	EntryPoint uintptr

	// is this PE image is a DLL image.
	IsDLL bool

	// runtime mutex, need lock it before call some loader methods.
	runtimeMu uintptr

	// get export method address if PE image is a DLL.
	getProc uintptr

	// get main thread return value or argument about call ExitProcess.
	exitCode uintptr

	// create a thread at EntryPoint, it useless for DLL image.
	// it can call multi times with Wait and Exit.
	start uintptr

	// wait the thread at EntryPoint, it useless for DLL image.
	// it can call multi times with Start.
	wait uintptr

	// create a thread at EntryPoint, it can call multi times.
	execute uintptr

	// release all resource, it can call multi times.
	exit uintptr

	// destroy all resource about PE loader, it can only call one time.
	destroy uintptr
}

// NewPELoader is used to create PELoader from initialized instance.
// It will copy memory for prevent runtime encrypt memory page when
// call loader or runtime methods.
func NewPELoader(ptr uintptr) *PELoaderM {
	ldr := *(*PELoaderM)(unsafe.Pointer(ptr)) // #nosec
	return &ldr
}

// InitPELoader is used to initialize PE Loader from shellcode instance.
// Each shellcode instance can only initialize once.
func InitPELoader(addr uintptr, runtime *gleamrt.RuntimeM, config *Config) (*PELoaderM, error) {
	ptr, _, err := syscall.SyscallN(
		addr, uintptr(unsafe.Pointer(runtime)), uintptr(unsafe.Pointer(config)),
	) // #nosec
	if ptr == null {
		return nil, fmt.Errorf("failed to initialize PE Loader: 0x%08X", int(err))
	}
	return NewPELoader(ptr), nil
}

func (ldr *PELoaderM) lock() {
	runtime.LockOSThread()
	hMutex := windows.Handle(ldr.runtimeMu)
	_, err := windows.WaitForSingleObject(hMutex, windows.INFINITE)
	if err != nil {
		panic(fmt.Sprintf("failed to lock runtime mutex: %s", err))
	}
}

func (ldr *PELoaderM) unlock() {
	hMutex := windows.Handle(ldr.runtimeMu)
	err := windows.ReleaseMutex(hMutex)
	if err != nil {
		panic(fmt.Sprintf("failed to release runtime mutex: %s", err))
	}
	runtime.UnlockOSThread()
}

// GetProcAddress is used to get procedure address by name.
func (ldr *PELoaderM) GetProcAddress(name string) (uintptr, error) {
	ldr.lock()
	defer ldr.unlock()
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	proc, _, en := syscall.SyscallN(ldr.getProc, uintptr(unsafe.Pointer(ptr))) // #nosec
	if proc == null {
		return 0, &errno{method: "GetProc", errno: uintptr(en)}
	}
	return proc, nil
}

// ExitCode is used to get the exit code, it from main thread return value or api.
func (ldr *PELoaderM) ExitCode() uint {
	ldr.lock()
	defer ldr.unlock()
	code, _, _ := syscall.SyscallN(ldr.exitCode)
	return uint(code)
}

// Start is used to create a thread at EntryPoint, it useless for DLL image.
// it can call multi times with Wait and Exit.
func (ldr *PELoaderM) Start() error {
	ldr.lock()
	defer ldr.unlock()
	en, _, _ := syscall.SyscallN(ldr.start)
	if en != noError {
		return &errno{method: "Start", errno: en}
	}
	return nil
}

// Wait is used to wait the thread at EntryPoint, it useless for DLL image.
// it can call multi times with Start.
func (ldr *PELoaderM) Wait() error {
	en, _, _ := syscall.SyscallN(ldr.wait)
	if en != noError {
		return &errno{method: "Wait", errno: en}
	}
	return nil
}

// Execute is used to execute exe or call DllMain with DLL_PROCESS_ATTACH.
// It can call multi times with Exit.
func (ldr *PELoaderM) Execute() error {
	en, _, _ := syscall.SyscallN(ldr.execute)
	if en != noError {
		return &errno{method: "Execute", errno: en}
	}
	return nil
}

// Exit is used to exit exe or call DllMain with DLL_PROCESS_DETACH.
// It can call multi times with Execute.
func (ldr *PELoaderM) Exit(code uint) error {
	ldr.lock()
	defer ldr.unlock()
	en, _, _ := syscall.SyscallN(ldr.exit, uintptr(code))
	if en != noError {
		return &errno{method: "Exit", errno: en}
	}
	return nil
}

// Destroy is used to destroy all resource about PE loader.
// It can only call one time.
func (ldr *PELoaderM) Destroy() error {
	ldr.lock()
	// defer ldr.unlock() runtime will close the mutex
	en, _, _ := syscall.SyscallN(ldr.destroy)
	if en != noError {
		return &errno{method: "Destroy", errno: en}
	}
	return nil
}
