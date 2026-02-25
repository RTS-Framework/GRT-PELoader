package loader

import (
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/option"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// load mode about image source.
const (
	ModeEmbed = "embed"
	ModeFile  = "file"
	ModeHTTP  = "http"
)

var (
	//go:embed template/PELoader_x86.bin
	defaultTemplateX86 []byte

	//go:embed template/PELoader_x64.bin
	defaultTemplateX64 []byte
)

// Image contains the various load mode.
type Image interface {
	// Encode is used to encode image config to binary.
	Encode() ([]byte, error)

	// Mode is used to get the PE image load mode.
	Mode() string
}

// Options contains options about create instance.
type Options struct {
	// set the custom loader template.
	Template []byte `toml:"template" json:"template"`

	// set the custom image name about the command line prefix.
	ImageName string `toml:"image_name" json:"image_name"`

	// set the command line argument about the image.
	CommandLine string `toml:"cmd_line" json:"cmd_line"`

	// wait main thread exit, if it is an exe image.
	WaitMain bool `toml:"wait_main" json:"wait_main"`

	// if failed to load library, can continue it.
	AllowSkipDLL bool `toml:"allow_skip_dll" json:"allow_skip_dll"`

	// create NUL file for set StdInput, StdOutput and
	// StdError for ignore console input/output.
	// If it is true, it will overwrite standard handles.
	IgnoreStdIO bool `toml:"ignore_stdio" json:"ignore_stdio"`

	// set standard handles for hook GetStdHandle,
	// if them are NULL, call original GetStdHandle.
	StdInput  uint64 `toml:"std_input"  json:"std_input"`
	StdOutput uint64 `toml:"std_output" json:"std_output"`
	StdError  uint64 `toml:"std_error"  json:"std_error"`

	// not running PE image after load.
	NotAutoRun bool `toml:"not_auto_run" json:"not_auto_run"`

	// not stop runtime when call ExitProcess.
	NotStopRuntime bool `toml:"not_stop_runtime" json:"not_stop_runtime"`

	// set Gleam-RT options, usually keep the default value.
	Runtime option.Options `toml:"runtime" json:"runtime"`

	// set additional arguments for upper PE image.
	// all the ID must greater than 64.
	Arguments []*argument.Arg `toml:"arguments" json:"arguments"`

	// for interactive with current program.
	Stdin  io.Reader `toml:"-" json:"-"`
	Stdout io.Writer `toml:"-" json:"-"`
	Stderr io.Writer `toml:"-" json:"-"`

	// if current program is running on GleamRT, must enable it.
	OnRuntime bool `toml:"-" json:"-"`
}

// CreateInstance is used to create instance from PE Loader template.
func CreateInstance(arch string, image Image, opts *Options) ([]byte, error) {
	if opts == nil {
		opts = new(Options)
	}
	// encode PE image configuration
	peImage, err := image.Encode()
	if err != nil {
		return nil, fmt.Errorf("invalid %s mode config: %s", image.Mode(), err)
	}
	// process command line
	var (
		cmdLineA []byte
		cmdLineW []byte
	)
	cmdLine := opts.CommandLine
	if cmdLine != "" {
		imageName := opts.ImageName
		if imageName == "" {
			imageName = "GRT-PELoader.exe"
		}
		if strings.Contains(imageName, " ") {
			imageName = "\"" + imageName + "\""
		}
		imageName += " "
		cmdLine = imageName + cmdLine
		cmdLineA = []byte(cmdLine + "\x00")
		cmdLineW = []byte(stringToUTF16(cmdLine))
	}
	// process switch about loader config
	var (
		waitMain       = make([]byte, 1)
		allowSkipDLL   = make([]byte, 1)
		ignoreStdIO    = make([]byte, 1)
		notAutoRun     = make([]byte, 1)
		notStopRuntime = make([]byte, 1)
	)
	for _, item := range [...]struct {
		data []byte
		opt  bool
	}{
		{data: waitMain, opt: opts.WaitMain},
		{data: allowSkipDLL, opt: opts.AllowSkipDLL},
		{data: ignoreStdIO, opt: opts.IgnoreStdIO},
		{data: notAutoRun, opt: opts.NotAutoRun},
		{data: notStopRuntime, opt: opts.NotStopRuntime},
	} {
		if item.opt {
			item.data[0] = 1
		}
	}
	// process standard handle and default template
	stdInput := binary.LittleEndian.AppendUint64(nil, opts.StdInput)
	stdOutput := binary.LittleEndian.AppendUint64(nil, opts.StdOutput)
	stdError := binary.LittleEndian.AppendUint64(nil, opts.StdError)
	var defaultTemplate []byte
	switch arch {
	case "386":
		stdInput = stdInput[:4]
		stdOutput = stdOutput[:4]
		stdError = stdError[:4]
		defaultTemplate = defaultTemplateX86
	case "amd64":
		defaultTemplate = defaultTemplateX64
	default:
		return nil, fmt.Errorf("invalid architecture: %s", arch)
	}
	// select PE loader template
	template := opts.Template
	if template == nil {
		template = defaultTemplate
	}
	// process runtime options and encode arguments
	template, err = option.Set(template, &opts.Runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to set runtime option: %s", err)
	}
	args := []*argument.Arg{
		{ID: 1, Data: peImage},
		{ID: 2, Data: cmdLineA},
		{ID: 3, Data: cmdLineW},
		{ID: 4, Data: waitMain},
		{ID: 5, Data: allowSkipDLL},
		{ID: 6, Data: ignoreStdIO},
		{ID: 7, Data: stdInput},
		{ID: 8, Data: stdOutput},
		{ID: 9, Data: stdError},
		{ID: 10, Data: notAutoRun},
		{ID: 11, Data: notStopRuntime},
	}
	// process additional arguments
	for _, arg := range opts.Arguments {
		if arg.ID <= 64 {
			return nil, errors.New("additional argument id must greater than 64")
		}
		args = append(args, arg)
	}
	stub, err := argument.Encode(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode argument: %s", err)
	}
	return append(template, stub...), nil
}

func stringToUTF16(s string) string {
	w := utf16.Encode([]rune(s))
	output := make([]byte, len(w)*2+2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return string(output)
}
