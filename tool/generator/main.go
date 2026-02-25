package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RTS-Framework/GRT-Develop/option"
	"github.com/RTS-Framework/GRT-PELoader/loader"
)

var (
	tplDir string
	mode   string
	arch   string
	pePath string

	compress  bool
	comWindow int
	httpOpts  loader.HTTPOptions
	options   loader.Options

	outPath string
)

func init() {
	flag.StringVar(&tplDir, "tpl", "", "set custom shellcode templates directory")
	flag.StringVar(&mode, "mode", "", "select the image load mode: embed, file and http")
	flag.StringVar(&arch, "arch", "amd64", "set shellcode template architecture")
	flag.StringVar(&pePath, "pe", "", "set the input PE image file path")
	flag.BoolVar(&compress, "compress", true, "compress image when use embed mode")
	flag.IntVar(&comWindow, "window", 4096, "set the window size when use compression")
	flag.DurationVar(&httpOpts.ConnectTimeout, "timeout", 0, "set the timeout when use http mode")
	flag.StringVar(&options.ImageName, "in", "", "set the image name about command line")
	flag.StringVar(&options.CommandLine, "cmd", "", "set command line for exe")
	flag.BoolVar(&options.WaitMain, "wait", false, "wait for shellcode to exit")
	flag.BoolVar(&options.AllowSkipDLL, "skip-dll", false, "allow skip DLL if failed to load")
	flag.BoolVar(&options.IgnoreStdIO, "silent", false, "ignore input/output about console")
	flag.BoolVar(&options.NotAutoRun, "nar", false, "not running PE image after load")
	flag.BoolVar(&options.NotStopRuntime, "nsr", false, "not stop runtime when call ExitProcess")
	flag.StringVar(&outPath, "o", "output.bin", "set output shellcode file path")
	option.Flag(&options.Runtime)
	flag.Parse()
}

func main() {
	if pePath == "" {
		flag.Usage()
		return
	}

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

	// create image configuration
	var image loader.Image
	switch mode {
	case "embed":
		fmt.Println("use embed image mode")
		fmt.Println("parse PE image file")
		peData, err := os.ReadFile(pePath) // #nosec
		checkError(err)
		peFile, err := pe.NewFile(bytes.NewReader(peData))
		checkError(err)
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
		if compress {
			fmt.Println("enable PE image compression")
			s := (len(peData) / (2 * 1024 * 1024)) + 1
			fmt.Printf("please wait for about %d seconds for compress\n", s)
			image = loader.NewEmbedCompress(peData, comWindow)
		} else {
			image = loader.NewEmbed(peData)
		}
	case "file":
		fmt.Println("use local file mode")
		image = loader.NewFile(pePath)
	case "http":
		fmt.Println("use http mode")
		image = loader.NewHTTP(pePath, &httpOpts)
	default:
		fmt.Println("unknown load mode")
		return
	}

	// select shellcode template
	var template []byte
	switch arch {
	case "386":
		template = ldrX86
		fmt.Println("select template for x86")
	case "amd64":
		template = ldrX64
		fmt.Println("select template for x64")
	default:
		fmt.Println("unknown template architecture")
		return
	}
	if len(template) > 0 {
		options.Template = template
	}

	fmt.Println("generate GRT-PELoader from template")
	instance, err := loader.CreateInstance(arch, image, &options)
	checkError(err)

	outPath, err = filepath.Abs(outPath)
	checkError(err)
	fmt.Println("save instance to:", outPath)
	err = os.WriteFile(outPath, instance, 0600) // #nosec
	checkError(err)

	fmt.Println("generate shellcode successfully")
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
