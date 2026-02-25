package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/RTS-Framework/GRT-PELoader/loader"
)

func main() {
	image, err := os.ReadFile("example.exe")
	checkError(err)

	input := bytes.NewBuffer(nil)
	output := bytes.NewBuffer(nil)

	input.WriteString("command\r\n")

	opts := loader.Options{
		ImageName:   "test.exe",
		CommandLine: "-p1 1 -p2 \"abc\"",

		Stdin:  input,
		Stdout: output,
		Stderr: output,
	}
	instance, err := loader.LoadInMemoryEXE(image, &opts)
	checkError(err)
	err = instance.Run()
	checkError(err)
	err = instance.Free()
	checkError(err)

	fmt.Println(output.String())
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
