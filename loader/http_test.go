package loader

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testURL = "https://github.com/RTS-Framework/GRT-PELoader"

func TestHTTP(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		image := NewHTTP(testURL, nil)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("with options", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Header1", "h1")
		headers.Set("Header2", "h2")
		opts := &HTTPOptions{
			Headers:   headers,
			UserAgent: "ua",
			ProxyURL:  "http://127.0.0.1:8080/",
		}
		image := NewHTTP(testURL, opts)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("invalid URL", func(t *testing.T) {
		image := NewHTTP("invalid url", nil)

		config, err := image.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("invalid proxy URL", func(t *testing.T) {
		opts := &HTTPOptions{
			ProxyURL: "invalid url",
		}
		image := NewHTTP(testURL, opts)

		config, err := image.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		image := NewHTTP(testURL, nil)
		require.Equal(t, ModeHTTP, image.Mode())
	})
}

func TestHTTPInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	// start a http server
	path, err := filepath.Abs("../test/image")
	require.NoError(t, err)
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Header1") != "h1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("Header2") != "h2" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.UserAgent() != "ua" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(path)).ServeHTTP(w, r)
	})
	server := http.Server{
		Handler: serverMux,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := listener.Addr().String()
	go func() {
		err = server.Serve(listener)
		require.NoError(t, err)
	}()
	defer func() {
		_ = server.Close()
	}()

	headers := make(http.Header)
	headers.Set("Header1", "h1")
	headers.Set("Header2", "h2")
	opts := &HTTPOptions{
		Headers:   headers,
		UserAgent: "ua",
	}
	opts.Headers.Set("Header1", "h1")

	wg := sync.WaitGroup{}
	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		for _, item := range images {
			URL := fmt.Sprintf("http://%s/x86/%s", httpAddr, item.path)
			image := NewHTTP(URL, opts)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance("386", image, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range images {
			URL := fmt.Sprintf("http://%s/x64/%s", httpAddr, item.path)
			image := NewHTTP(URL, opts)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance("amd64", image, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})
	wg.Wait()
}
