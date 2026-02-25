package main

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/RTS-Framework/Gleam-RT/runtime/argument"
)

// arg id 2 is CommandLineA

func main() {
	getValue()
	getPointer()
	erase()
	eraseAll()
}

func getValue() {
	cmd, ok := argument.GetValue(2)
	if !ok {
		log.Fatal("failed to get CommandLineA")
	}
	fmt.Println("cmd:", string(cmd))
}

func getPointer() {
	pointer, size, ok := argument.GetPointer(2)
	if !ok {
		log.Fatal("failed to get CommandLineA pointer")
	}
	fmt.Printf("pointer: 0x%X\n", pointer)
	fmt.Println("size:   ", size)

	arg := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), size) // #nosec
	fmt.Println("cmd:", string(arg))
}

func erase() {
	if !argument.Erase(1) {
		log.Fatal("failed to erase argument with id: 1")
	}
	fmt.Println("erase argument with id: 1")
}

func eraseAll() {
	argument.EraseAll()
	fmt.Println("erase all arguments")
}
