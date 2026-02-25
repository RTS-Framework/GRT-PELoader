//go:build windows

package loader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx = modKernel32.NewProc("VirtualAllocEx")
)

// Instance contains the allocated memory page and pipe.
type Instance struct {
	*PELoaderM

	addr uintptr
	data []byte

	stdInputR  *os.File
	stdInputW  *os.File
	stdOutputR *os.File
	stdOutputW *os.File
	stdErrorR  *os.File
	stdErrorW  *os.File

	sameOutErr bool
	outErrMu   sync.Mutex
}

// LoadInMemoryEXE is used to load an unmanaged exe image to memory.
func LoadInMemoryEXE(image []byte, opts *Options) (*Instance, error) {
	return loadInMemoryImage(image, opts, false)
}

// LoadInMemoryDLL is used to load an unmanaged dll image to memory.
func LoadInMemoryDLL(image []byte, opts *Options) (*Instance, error) {
	return loadInMemoryImage(image, opts, true)
}

func loadInMemoryImage(image []byte, opts *Options, isDLL bool) (*Instance, error) {
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	if isDLL && (peFile.Characteristics&pe.IMAGE_FILE_DLL) == 0 {
		return nil, errors.New("pe image is not a dll")
	}
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	default:
		return nil, errors.New("unknown pe image architecture type")
	}
	if arch != runtime.GOARCH {
		return nil, errors.New("pe image architecture is mismatched")
	}
	return LoadInMemoryImage(NewEmbed(image), arch, opts)
}

// LoadInMemoryImage is used to load unmanaged pe image to memory.
func LoadInMemoryImage(image Image, arch string, opts *Options) (*Instance, error) {
	// copy options for overwrite
	if opts == nil {
		opts = new(Options)
	}
	options := *opts
	// process pipe for set standard handle
	instance := Instance{}
	err := instance.startPipe(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to start pipe: %s", err)
	}
	// overwrite options for modularization
	options.WaitMain = false
	options.NotAutoRun = true
	options.NotStopRuntime = true
	options.Runtime.NotAdjustProtect = true
	options.Runtime.TrackCurrentThread = false
	// create instance
	inst, err := CreateInstance(arch, image, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %s", err)
	}
	size := uintptr(len(inst))
	// prepare memory page for write instance
	var instAddr uintptr
	if opts.OnRuntime {
		// use VirtualAllocEx for let GleamRT not track these pages
		hProcess := uintptr(windows.CurrentProcess())
		mType := uintptr(windows.MEM_COMMIT | windows.MEM_RESERVE)
		mProtect := uintptr(windows.PAGE_READWRITE)
		instAddr, _, err = procVirtualAllocEx.Call(hProcess, 0, size, mType, mProtect)
		if instAddr == 0 {
			return nil, fmt.Errorf("failed to alloc memory for instance: %s", err)
		}
	} else {
		mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
		mProtect := uint32(windows.PAGE_READWRITE)
		instAddr, err = windows.VirtualAlloc(0, size, mType, mProtect)
		if err != nil {
			return nil, fmt.Errorf("failed to alloc memory for instance: %s", err)
		}
	}
	var old uint32
	err = windows.VirtualProtect(instAddr, size, windows.PAGE_EXECUTE_READWRITE, &old)
	if err != nil {
		return nil, fmt.Errorf("failed to change memory protect: %s", err)
	}
	instData := unsafe.Slice((*byte)(unsafe.Pointer(instAddr)), len(inst)) // #nosec
	copy(instData, inst)
	// record instance memory address
	instance.addr = instAddr
	instance.data = instData
	// load instance
	ptr, _, err := syscall.SyscallN(instAddr)
	if ptr == null {
		_ = instance.free()
		return nil, fmt.Errorf("failed to load instance: 0x%08X", uint(err.(syscall.Errno)))
	}
	instance.PELoaderM = NewPELoader(ptr)
	return &instance, nil
}

func (inst *Instance) startPipe(options *Options) error {
	if options.IgnoreStdIO {
		return nil
	}
	if options.Stdout != nil && options.Stdout == options.Stderr {
		inst.sameOutErr = true
	}
	var ok bool
	defer func() {
		if !ok {
			inst.closePipe()
		}
	}()
	err := inst.startStdinPipe(options)
	if err != nil {
		return err
	}
	err = inst.startStdoutPipe(options)
	if err != nil {
		return err
	}
	err = inst.startStderrPipe(options)
	if err != nil {
		return err
	}
	ok = true
	return nil
}

func (inst *Instance) startStdinPipe(options *Options) error {
	if options.StdInput != 0 || options.Stdin == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stdin: %s", err)
	}
	options.StdInput = uint64(r.Fd())
	inst.stdInputR = r
	inst.stdInputW = w
	go func() {
		_, _ = io.Copy(w, options.Stdin)
	}()
	return nil
}

func (inst *Instance) startStdoutPipe(options *Options) error {
	if options.StdOutput != 0 || options.Stdout == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stdout: %s", err)
	}
	options.StdOutput = uint64(w.Fd())
	inst.stdOutputR = r
	inst.stdOutputW = w
	go func() {
		if !inst.sameOutErr {
			_, _ = io.Copy(options.Stdout, r)
			return
		}
		inst.copyPipe(options.Stdout, r)
	}()
	return nil
}

func (inst *Instance) startStderrPipe(options *Options) error {
	if options.StdError != 0 || options.Stderr == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stderr: %s", err)
	}
	options.StdError = uint64(w.Fd())
	inst.stdErrorR = r
	inst.stdErrorW = w
	go func() {
		if !inst.sameOutErr {
			_, _ = io.Copy(options.Stderr, r)
			return
		}
		inst.copyPipe(options.Stderr, r)
	}()
	return nil
}

func (inst *Instance) copyPipe(dst io.Writer, src io.Reader) {
	buf := make([]byte, 4096)
	write := func(n int) error {
		inst.outErrMu.Lock()
		defer inst.outErrMu.Unlock()
		_, err := dst.Write(buf[:n])
		return err
	}
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		err = write(n)
		if err != nil {
			return
		}
	}
}

func (inst *Instance) closePipe() {
	if inst.stdInputR != nil {
		_ = inst.stdInputR.Close()
		_ = inst.stdInputW.Close()
	}
	if inst.stdOutputR != nil {
		_ = inst.stdOutputR.Close()
		_ = inst.stdOutputW.Close()
	}
	if inst.stdErrorR != nil {
		_ = inst.stdErrorR.Close()
		_ = inst.stdErrorW.Close()
	}
}

// Run is used to start and wait image or execute dll_main.
func (inst *Instance) Run() error {
	if inst.IsDLL {
		return inst.Execute()
	}
	err := inst.Start()
	if err != nil {
		return err
	}
	return inst.Wait()
}

// Restart is used to exit image and start image or execute dll_main.
func (inst *Instance) Restart() error {
	err1 := inst.Exit(0)
	var err2 error
	if inst.IsDLL {
		err2 = inst.Execute()
	} else {
		err2 = inst.Start()
	}
	if err2 != nil {
		return err2
	}
	return err1
}

// Free is used to destroy instance and free memory page about it.
func (inst *Instance) Free() error {
	err := inst.Destroy()
	if err != nil {
		return err
	}
	return inst.free()
}

func (inst *Instance) free() error {
	copy(inst.data, bytes.Repeat([]byte{0}, len(inst.data)))
	err := windows.VirtualFree(inst.addr, 0, windows.MEM_RELEASE)
	if err != nil {
		return err
	}
	inst.closePipe()
	return nil
}
