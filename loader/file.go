package loader

import (
	"bytes"
)

// +-----------+-----------+
// | mode flag | file path |
// +-----------+-----------+
// |   byte    |    var    |
// +-----------+-----------+

const modeFile = 2

// File is the local file mode.
type File struct {
	Path string `toml:"path" json:"path"`
}

// NewFile is used to create image with local file mode.
func NewFile(path string) Image {
	return &File{Path: path}
}

// Encode implement Image interface.
func (f *File) Encode() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	// write the mode
	buffer.WriteByte(modeFile)
	// write the file path
	buffer.WriteString(stringToUTF16(f.Path))
	return buffer.Bytes(), nil
}

// Mode implement Image interface.
func (f *File) Mode() string {
	return ModeFile
}
