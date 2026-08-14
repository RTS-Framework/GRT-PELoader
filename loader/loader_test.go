//go:build windows

package loader

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop/instance"
	"github.com/RTS-Framework/GRT-Develop/types"
	"github.com/RTS-Framework/Gleam-RT/runtime"
)

var (
	testModuleX86 []byte
	testModuleX64 []byte
)

func init() {
	var err error
	testModuleX86, err = os.ReadFile("../dist/module/PELoader_x86.bin")
	if err != nil {
		panic(err)
	}
	testModuleX64, err = os.ReadFile("../dist/module/PELoader_x64.bin")
	if err != nil {
		panic(err)
	}
}

func TestStandard(t *testing.T) {
	t.Run("exe", func(t *testing.T) {
		var image Image
		switch runtime.GOARCH {
		case "386":
			image = NewFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			image = NewFile("../test/image/x64/rust_msvc.exe")
		default:
			t.Fatal("unsupported architecture")
		}

		r, w, err := os.Pipe()
		require.NoError(t, err)
		go func() {
			reader := bufio.NewScanner(r)
			for reader.Scan() {
				fmt.Println(reader.Text())
			}
		}()

		opts := &Options{
			ImageName: "test.exe",
			WaitMain:  false,

			StdInput:  0,
			StdOutput: uint64(w.Fd()),
			StdError:  uint64(w.Fd()),
		}
		inst, err := CreateInstance(runtime.GOARCH, image, opts)
		require.NoError(t, err)

		addr := loadInstance(t, inst)
		ptr, _, err := syscallN(addr, 0)
		require.NotEqual(t, uintptr(0), ptr, err)
		PELoaderM := NewPELoader(ptr)
		spew.Dump(PELoaderM)

		time.Sleep(3 * time.Second)
	})

	t.Run("dll", func(t *testing.T) {
		image := NewFile("C:\\Windows\\System32\\ws2_32.dll")
		opts := &Options{
			WaitMain:     false,
			AllowSkipDLL: true,
		}
		inst, err := CreateInstance(runtime.GOARCH, image, opts)
		require.NoError(t, err)

		addr := loadInstance(t, inst)
		ptr, _, err := syscallN(addr, 0)
		require.NotEqual(t, uintptr(0), ptr, err)
		PELoaderM := NewPELoader(ptr)
		spew.Dump(PELoaderM)

		connect, err := PELoaderM.GetProcAddress("connect")
		require.NoError(t, err)
		fmt.Printf("ws2_32.connect: 0x%X\n", connect)

		// call DllMain DLL_PROCESS_DETACH
		err = PELoaderM.Exit(0)
		require.NoError(t, err)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})

	t.Run("ignore output", func(t *testing.T) {
		var image Image
		switch runtime.GOARCH {
		case "386":
			image = NewFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			image = NewFile("../test/image/x64/rust_msvc.exe")
		default:
			t.Fatal("unsupported architecture")
		}

		opts := &Options{
			ImageName: "test.exe",

			StdInput:  1, // will be overwritten
			StdOutput: 2, // will be overwritten
			StdError:  3, // will be overwritten

			WaitMain:    true,
			IgnoreStdIO: true,
		}
		inst, err := CreateInstance(runtime.GOARCH, image, opts)
		require.NoError(t, err)

		addr := loadInstance(t, inst)
		ptr, _, err := syscallN(addr, 0)
		require.NotEqual(t, uintptr(0), ptr, err)
	})

	t.Run("exit", func(t *testing.T) {
		var image Image
		switch runtime.GOARCH {
		case "386":
			image = NewFile("../test/image/x86/go.exe")
		case "amd64":
			image = NewFile("../test/image/x64/go.exe")
		default:
			t.Fatal("unsupported architecture")
		}

		opts := &Options{
			ImageName:      "test.exe",
			CommandLine:    "-kick 50",
			WaitMain:       false,
			NotStopRuntime: true,
		}
		inst, err := CreateInstance(runtime.GOARCH, image, opts)
		require.NoError(t, err)

		addr := loadInstance(t, inst)
		ptr, _, err := syscallN(addr, 0)
		require.NotEqual(t, uintptr(0), ptr, err)
		PELoaderM := NewPELoader(ptr)
		spew.Dump(PELoaderM)

		time.Sleep(3 * time.Second)

		err = PELoaderM.Exit(123)
		require.NoError(t, err)
		code := PELoaderM.ExitCode()
		require.Equal(t, uint(123), code)
	})
}

func TestPipeline(t *testing.T) {

}

func TestModule(t *testing.T) {
	// process Gleam-RT instruction
	var (
		ldr  []byte
		data []byte
		err  error
	)
	switch runtime.GOARCH {
	case "386":
		ldr = testModuleX86
		data, err = os.ReadFile("../asm/inst/runtime_x86.inst")
	case "amd64":
		ldr = testModuleX64
		data, err = os.ReadFile("../asm/inst/runtime_x64.inst")
	default:
		t.Fatal("unsupported architecture")
	}
	require.NoError(t, err)
	s := string(data)
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, " 0", "")
	s = strings.ReplaceAll(s, "db", "")
	s = strings.ReplaceAll(s, "h", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\r\n", "")
	tpl, err := hex.DecodeString(s)
	require.NoError(t, err)
	rt, err := instance.Instantiate(tpl, nil)
	require.NoError(t, err)

	t.Run("exe", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadInstance(t, rt)
		fmt.Printf("Runtime:   0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		var pe []byte
		switch runtime.GOARCH {
		case "386":
			pe, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			pe, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
		}
		require.NoError(t, err)
		config := Config{
			FindAPI:  RuntimeM.HashAPI.FindAPIMA,
			Image:    (uintptr)(unsafe.Pointer(&pe[0])),
			WaitMain: types.TRUE,
		}

		// initialize PELoader
		addr = loadInstance(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		err = PELoaderM.Execute()
		require.NoError(t, err)

		err = RuntimeM.Exit()
		require.NoError(t, err)
	})

	t.Run("dll", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadInstance(t, rt)
		fmt.Printf("Runtime:   0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		pe, err := os.ReadFile("C:\\Windows\\System32\\ws2_32.dll")
		require.NoError(t, err)
		config := Config{
			FindAPI:      RuntimeM.HashAPI.FindAPIMA,
			Image:        (uintptr)(unsafe.Pointer(&pe[0])),
			AllowSkipDLL: types.TRUE,
		}

		// initialize PELoader
		addr = loadInstance(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		// call DllMain DLL_PROCESS_ATTACH
		err = PELoaderM.Execute()
		require.NoError(t, err)

		proc, err := PELoaderM.GetProcAddress("connect")
		require.NoError(t, err)
		fmt.Printf("ws2_32.connect: 0x%X\n", proc)

		// call DllMain DLL_PROCESS_DETACH
		err = PELoaderM.Exit(0)
		require.NoError(t, err)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})

	t.Run("ignore output", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadInstance(t, rt)
		fmt.Printf("Runtime:   0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		var pe []byte
		switch runtime.GOARCH {
		case "386":
			pe, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			pe, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
		}
		require.NoError(t, err)
		config := Config{
			FindAPI:     RuntimeM.HashAPI.FindAPIMA,
			Image:       (uintptr)(unsafe.Pointer(&pe[0])),
			WaitMain:    types.TRUE,
			IgnoreStdIO: types.TRUE,

			StdInput:  1, // will be overwritten
			StdOutput: 2, // will be overwritten
			StdError:  3, // will be overwritten
		}

		// initialize PELoader
		addr = loadInstance(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		err = PELoaderM.Execute()
		require.NoError(t, err)

		err = RuntimeM.Exit()
		require.NoError(t, err)
	})

	t.Run("start and wait", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadInstance(t, rt)
		fmt.Printf("Runtime:   0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		var pe []byte
		switch runtime.GOARCH {
		case "386":
			pe, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			pe, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
		}
		require.NoError(t, err)
		config := Config{
			FindAPI:        RuntimeM.HashAPI.FindAPIMA,
			Image:          (uintptr)(unsafe.Pointer(&pe[0])),
			NotStopRuntime: types.TRUE,
		}

		// initialize PELoader
		addr = loadInstance(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		err = PELoaderM.Start()
		require.NoError(t, err)

		err = PELoaderM.Wait()
		require.NoError(t, err)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})

	t.Run("start only", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadInstance(t, rt)
		fmt.Printf("Runtime:   0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		var pe []byte
		switch runtime.GOARCH {
		case "386":
			pe, err = os.ReadFile("../test/image/x86/go.exe")
		case "amd64":
			pe, err = os.ReadFile("../test/image/x64/go.exe")
		}
		require.NoError(t, err)

		cmdLine := "-kick 50"
		cmdLineA := []byte(cmdLine + "\x00")
		cmdLineW := types.StringToUTF16(cmdLine)
		config := Config{
			FindAPI:      RuntimeM.HashAPI.FindAPIMA,
			Image:        (uintptr)(unsafe.Pointer(&pe[0])),
			CommandLineA: (uintptr)(unsafe.Pointer(&cmdLineA[0])),
			CommandLineW: (uintptr)(unsafe.Pointer(&cmdLineW[0])),
		}

		// initialize PELoader
		addr = loadInstance(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		err = PELoaderM.Start()
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		err = PELoaderM.Exit(123)
		require.NoError(t, err)
		code := PELoaderM.ExitCode()
		require.Equal(t, uint(123), code)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})
}
