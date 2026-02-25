package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/davecgh/go-spew/spew"

	"github.com/RTS-Framework/GRT-PELoader/loader"
)

func main() {
	image, err := os.ReadFile("C:\\Windows\\System32\\ws2_32.dll")
	checkError(err)

	instance, err := loader.LoadInMemoryDLL(image, nil)
	checkError(err)
	err = instance.Run()
	checkError(err)

	WSAStartup, err := instance.GetProcAddress("WSAStartup")
	checkError(err)

	var data syscall.WSAData
	ret, _, _ := syscall.SyscallN(
		WSAStartup, uintptr(0x202), uintptr(unsafe.Pointer(&data)),
	) // #nosec
	fmt.Println(ret)
	spew.Dump(data)

	err = instance.Free()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
