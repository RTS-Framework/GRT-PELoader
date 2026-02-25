package main

import (
	"fmt"
	"os"

	"github.com/RTS-Framework/GRT-PELoader/loader"
)

func main() {
	image, err := os.ReadFile("example.exe")
	checkError(err)

	opts := loader.Options{
		ImageName:   "test.exe",
		CommandLine: "-p1 1 -p2 \"abc\"",
	}
	instance, err := loader.LoadInMemoryEXE(image, &opts)
	checkError(err)

	err = instance.Run()
	checkError(err)

	fmt.Println(instance.ExitCode())

	err = instance.Free()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
