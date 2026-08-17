package loader

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/For-ACGN/LZSS"
)

// enable compression
// +-----------+----------+----------+-----------------+-------+
// | mode flag | compress | raw size | compressed size | image |
// +-----------+----------+----------+-----------------+-------+
// |   byte    |   bool   |  uint32  |     uint32      |  var  |
// +-----------+----------+----------+-----------------+-------+

// disable compression
// +-----------+----------+--------+-------+
// | mode flag | compress |  size  | image |
// +-----------+----------+--------+-------+
// |   byte    |   bool   | uint32 |  var  |
// +-----------+----------+--------+-------+

const modeEmbed = 1

const (
	enableCompression  = 1
	disableCompression = 0
)

// Embed is the embed mode.
type Embed struct {
	image []byte

	compress   bool
	windowSize int

	preCompress bool
}

// NewEmbed is used to create image with embed mode.
func NewEmbed(image []byte) Image {
	return &Embed{image: image}
}

// NewEmbedCompress is used to create embed with compression.
func NewEmbedCompress(image []byte, windowSize int) Image {
	return &Embed{
		image:      image,
		compress:   true,
		windowSize: windowSize,
	}
}

// NewEmbedPreCompress is used to create embed with pre-compression.
func NewEmbedPreCompress(image []byte) Image {
	return &Embed{
		image:       image,
		compress:    true,
		preCompress: true,
	}
}

// Encode implement Image interface.
func (e *Embed) Encode() ([]byte, error) {
	// check PE image is valid
	image := e.image
	if e.preCompress {
		image = lzss.Decompress(image)
	}
	_, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %s", err)
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 16*1024))
	// write the mode
	buffer.WriteByte(modeEmbed)
	// need use compress mode
	if !e.compress {
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.image))) // #nosec
		buffer.WriteByte(disableCompression)
		buffer.Write(size)
		buffer.Write(e.image)
		return buffer.Bytes(), nil
	}
	// set the compressed flag
	buffer.WriteByte(enableCompression)
	// compress PE image
	var compressed []byte
	if !e.preCompress {
		compressed, err = lzss.Compress(e.image, e.windowSize)
		if err != nil {
			return nil, fmt.Errorf("failed to compress PE image: %s", err)
		}
	} else {
		compressed = e.image
	}
	// write raw size
	size := binary.LittleEndian.AppendUint32(nil, uint32(len(image))) // #nosec
	buffer.Write(size)
	// write compressed size
	size = binary.LittleEndian.AppendUint32(nil, uint32(len(compressed))) // #nosec
	buffer.Write(size)
	// write compressed PE image
	buffer.Write(compressed)
	return buffer.Bytes(), nil
}

// Mode implement Image interface.
func (e *Embed) Mode() string {
	return ModeEmbed
}
