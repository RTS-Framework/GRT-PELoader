package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-PELoader/loader"
)

var (
	tplDir string
	pePath string
	proc   string
	wait   time.Duration

	options loader.Options
)

func init() {
	flag.StringVar(&tplDir, "tpl", "", "set custom shellcode templates directory")
	flag.StringVar(&pePath, "pe", "", "set the input PE image file path")
	flag.StringVar(&proc, "proc", "", "call the export procedure without argument for test")
	flag.DurationVar(&wait, "wait", 5*time.Second, "wait time after call DllMain for DLL")
	flag.StringVar(&options.ImageName, "in", "", "set the image name about command line")
	flag.StringVar(&options.CommandLine, "cmd", "", "set command line for exe")
	flag.BoolVar(&options.WaitMain, "wm", false, "wait for shellcode to exit")
	flag.BoolVar(&options.AllowSkipDLL, "skip-dll", false, "allow skip DLL if failed to load")
	flag.BoolVar(&options.IgnoreStdIO, "silent", false, "ignore input/output about console")
	flag.BoolVar(&options.NotStopRuntime, "nsr", false, "not stop runtime when call ExitProcess")
	option.Flag(&options.Runtime)
	flag.Parse()
}

func main() {
	if pePath == "" {
		flag.Usage()
		return
	}

	fmt.Println("----------------------------------------------------")
	fmt.Println("[WARNING]                                           ")
	fmt.Println("This program is only for test PE image is compatible")
	fmt.Println("----------------------------------------------------")

	// load custom loader template
	var (
		ldrX64 []byte
		ldrX86 []byte
	)
	if tplDir != "" {
		var err error
		fmt.Println("load custom PE Loader templates")
		ldrX64, err = os.ReadFile(filepath.Join(tplDir, "PELoader_x64.bin")) // #nosec
		checkError(err)
		ldrX86, err = os.ReadFile(filepath.Join(tplDir, "PELoader_x86.bin")) // #nosec
		checkError(err)
	}

	fmt.Println("parse PE image file")
	peData, err := os.ReadFile(pePath) // #nosec
	checkError(err)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	checkError(err)
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
		fmt.Println("image architecture: x86")
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
		fmt.Println("image architecture: x64")
	default:
		fmt.Println("unknown pe image architecture type")
		return
	}
	if arch != runtime.GOARCH {
		fmt.Println("PE image architecture is mismatched")
		return
	}

	// select custom shellcode template
	var template []byte
	switch arch {
	case "386":
		template = ldrX86
	case "amd64":
		template = ldrX64
	}
	if len(template) > 0 {
		options.Template = template
	}

	// process empty command line
	if options.ImageName == "" {
		options.ImageName = filepath.Base(pePath)
	}
	if options.CommandLine == "" {
		options.CommandLine = " "
	}

	fmt.Println("load PE image to memory")
	image := loader.NewFile(pePath)
	instance, err := loader.LoadInMemoryImage(image, arch, &options)
	checkError(err)

	fmt.Println("PE image is running")
	fmt.Println("================================")
	fmt.Println()

	err = instance.Run()
	checkError(err)

	if proc != "" {
		fmt.Println("call export procedure")
		p, err := instance.GetProcAddress(proc)
		checkError(err)
		ret, _, err := syscall.SyscallN(p)
		fmt.Println("return value:", ret)
		fmt.Println(err)
	}
	if instance.IsDLL {
		fmt.Println("DllMain is running")
		time.Sleep(wait)
	}

	err = instance.Free()
	checkError(err)
	fmt.Println()
	fmt.Println("================================")
	fmt.Println("free instance successfully")
	fmt.Println("================================")
	fmt.Println("")
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
