package main

import (
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

func main() {
	goSleep()
	safeSleep()
	unsafeSleep()
}

// it will not call the kernel32.Sleep, so it will not trigger SleepHR.
func goSleep() {
	time.Sleep(time.Second)
}

// safeSleep like goSleep, use WaitableTimer with WaitForSingleObject.
// must cache the procedure address when development.
// you can reference the go method gleamrt.SleepSim.
func safeSleep() {
	hGleamRT, err := windows.LoadLibrary("GleamRT.dll")
	if err != nil {
		panic(err)
	}
	sleep, err := windows.GetProcAddress(hGleamRT, "RT_Sleep")
	if err != nil {
		panic(err)
	}
	_, _, _ = syscall.SyscallN(sleep, 1000)
}

// if you want to call the raw kernel32.Sleep, must get raw address first.
// must cache the procedure address when development.
// THIS BEHAVIOR IS VERY DANGEROUS.
func unsafeSleep() {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		panic(err)
	}
	sleep, err := gleamrt.GetProcAddressRaw(hKernel32, "Sleep")
	if err != nil {
		panic(err)
	}
	_, _, _ = syscall.SyscallN(sleep, 1000)
}
