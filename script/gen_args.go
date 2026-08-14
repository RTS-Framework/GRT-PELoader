package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/types"
)

func main() {
	cmdline := "test_x86.exe -arg 11"
	cmdlineA := []byte(cmdline + "\x00")
	cmdlineW := types.StringToUTF16(cmdline)
	args := []*argument.Arg{
		{ID: 1, Data: []byte{0xFF}},    // invalid PE image
		{ID: 2, Data: cmdlineA},        // command line ANSI
		{ID: 3, Data: cmdlineW},        // command line UTF16
		{ID: 4, Data: make([]byte, 4)}, // standard input handle
		{ID: 5, Data: make([]byte, 4)}, // standard output handle
		{ID: 6, Data: make([]byte, 4)}, // standard error handle
		{ID: 7, Data: []byte{0x01}},    // wait main thread
		{ID: 8, Data: []byte{0x01}},    // allow skip dll
		{ID: 9, Data: []byte{0x01}},    // ignore standard handle
		{ID: 10, Data: []byte{0x01}},   // not auto run
		{ID: 11, Data: []byte{0x01}},   // not stop runtime
	}
	stub, err := argument.Encode(args...)
	checkError(err)

	data := dumpBytesHex(stub)
	fmt.Println(data)
	err = os.WriteFile("../asm/inst/argument_x86.inst", []byte(data), 0644)
	checkError(err)

	cmdline = "test_x64.exe -arg 11"
	cmdlineA = []byte(cmdline + "\x00")
	cmdlineW = types.StringToUTF16(cmdline)
	args = []*argument.Arg{
		{ID: 1, Data: []byte{0xFF}},    // invalid PE image
		{ID: 2, Data: cmdlineA},        // command line ANSI
		{ID: 3, Data: cmdlineW},        // command line UTF16
		{ID: 4, Data: make([]byte, 8)}, // standard input handle
		{ID: 5, Data: make([]byte, 8)}, // standard output handle
		{ID: 6, Data: make([]byte, 8)}, // standard error handle
		{ID: 7, Data: []byte{0x01}},    // wait main thread
		{ID: 8, Data: []byte{0x01}},    // allow skip dll
		{ID: 9, Data: []byte{0x01}},    // ignore standard handle
		{ID: 10, Data: []byte{0x01}},   // not auto run
		{ID: 11, Data: []byte{0x01}},   // not stop runtime
	}
	stub, err = argument.Encode(args...)
	checkError(err)

	data = dumpBytesHex(stub)
	fmt.Println(data)
	err = os.WriteFile("../asm/inst/argument_x64.inst", []byte(data), 0644)
	checkError(err)
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 4 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.String()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
