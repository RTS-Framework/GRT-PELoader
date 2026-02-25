package main

import (
	"bytes"
	"fmt"
	"log"
	"unsafe"

	"github.com/RTS-Framework/Gleam-RT/runtime/storage"
)

func main() {
	setValue()
	getValue()
	getPointer()
	deleteVal()
	deleteAll()
}

func setValue() {
	data := []byte{0x01, 0x02, 0x03, 0x04}

	err := storage.SetValue(0, data)
	if err != nil {
		log.Printf("failed to set value to id 0: %s", err)
	}
	fmt.Println("set value:", data)
}

func getValue() {
	data, err := storage.GetValue(0)
	if err != nil {
		log.Printf("failed to get value with id 0: %s", err)
	}

	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(expected, data) {
		log.Fatal("get value with incorrect data")
	}
	fmt.Println("get value:", data)
}

func getPointer() {
	pointer, size, err := storage.GetPointer(0)
	if err != nil {
		log.Fatal("failed to get pointer:", err)
	}
	fmt.Printf("pointer: 0x%X\n", pointer)
	fmt.Println("size:   ", size)

	data := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), size) // #nosec
	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(expected, data) {
		log.Fatalln("get pointer with incorrect data")
	}
	fmt.Println("get pointer:", data)
}

func deleteVal() {
	err := storage.Delete(0)
	if err != nil {
		log.Fatal("failed to delete value:", err)
	}
	err = storage.Delete(0)
	if err == nil {
		log.Fatal("delete value twice")
	}
}

func deleteAll() {
	err := storage.DeleteAll()
	if err != nil {
		log.Fatal("failed to delete all:", err)
	}
}
