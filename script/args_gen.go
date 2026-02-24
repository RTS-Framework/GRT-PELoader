package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"unicode/utf16"

	"github.com/RTS-Framework/GRT-Develop/argument"
)

func main() {
	cmdlineA := "test_x86.exe -arg 1234\x00"
	cmdlineW := stringToUTF16(cmdlineA)

	args := []*argument.Arg{
		{ID: 1, Data: []byte{0xFF}},     // invalid PE image
		{ID: 2, Data: []byte(cmdlineA)}, // command line ANSI
		{ID: 3, Data: []byte(cmdlineW)}, // command line UTF16
		{ID: 4, Data: []byte{0x01}},     // wait main thread
		{ID: 5, Data: []byte{0x01}},     // allow skip dll
		{ID: 6, Data: []byte{0x01}},     // ignore standard handle
		{ID: 7, Data: make([]byte, 4)},  // standard input handle
		{ID: 8, Data: make([]byte, 4)},  // standard output handle
		{ID: 9, Data: make([]byte, 4)},  // standard error handle
		{ID: 10, Data: []byte{0x01}},    // not auto run
		{ID: 11, Data: []byte{0x01}},    // not stop runtime
	}
	stub, err := argument.Encode(args...)
	checkError(err)

	fmt.Println("============x86============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")
	fmt.Println()

	cmdlineA = "test_x64.exe -arg 1234\x00"
	cmdlineW = stringToUTF16(cmdlineA)

	args = []*argument.Arg{
		{ID: 1, Data: []byte{0xFF}},     // invalid PE image
		{ID: 2, Data: []byte(cmdlineA)}, // command line ANSI
		{ID: 3, Data: []byte(cmdlineW)}, // command line UTF16
		{ID: 4, Data: []byte{0x01}},     // wait main thread
		{ID: 5, Data: []byte{0x01}},     // allow skip dll
		{ID: 6, Data: []byte{0x01}},     // ignore standard handle
		{ID: 7, Data: make([]byte, 8)},  // standard input handle
		{ID: 8, Data: make([]byte, 8)},  // standard output handle
		{ID: 9, Data: make([]byte, 8)},  // standard error handle
		{ID: 10, Data: []byte{0x01}},    // not auto run
		{ID: 11, Data: []byte{0x01}},    // not stop runtime
	}
	stub, err = argument.Encode(args...)
	checkError(err)

	fmt.Println("============x64============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")
}

func stringToUTF16(s string) string {
	w := utf16.Encode([]rune(s))
	output := make([]byte, len(w)*2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return string(output)
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
