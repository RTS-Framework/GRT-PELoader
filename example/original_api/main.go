package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAlloc = modKernel32.NewProc("VirtualAlloc")
)

func main() {
	redirected := procVirtualAlloc.Addr()
	original, err := gleamrt.GetProcAddressOriginal(modKernel32.Handle(), "VirtualAlloc")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("redirected: 0x%X\n", redirected)
	fmt.Printf("original:   0x%X\n", original)

	if redirected == original {
		panic("redirected equal original procedure address")
	}
}
