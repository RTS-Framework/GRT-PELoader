package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

var (
	modKernel32 = windows.NewLazyDLL("kernel32.dll")
	procSleep   = modKernel32.NewProc("Sleep")
)

func main() {
	// for allocate memory in go heap,
	// not only .text and .data section
	secret := strings.Repeat("secret", 1)

	for i := 0; i < 3; i++ {
		do()

		err := gleamrt.Sleep(time.Second)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("gleamrt.Sleep complete")
	}

	for i := 0; i < 3; i++ {
		do()

		kernel32Sleep()
		fmt.Println("kernel32.Sleep complete")
	}

	fmt.Println(secret)
}

func kernel32Sleep() {
	// trigger Gleam-RT SleepHR
	fmt.Println("call kernel32.Sleep [hooked]")
	now := time.Now()
	ret, _, _ := procSleep.Call(1000)
	if ret != 0 {
		log.Fatalf("occurred error when slept: 0x%X\n", ret)
	}
	fmt.Println("Sleep:", time.Since(now))
}

func do() {
	// plain memory data
	fmt.Println("simulate running")
	time.Sleep(3 * time.Second)
}
