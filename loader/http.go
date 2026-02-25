package loader

import (
	"bytes"
	"net/http"
	"net/url"
	"time"

	"github.com/RTS-Framework/GRT-Develop/serialization"
	"github.com/RTS-Framework/GRT-Develop/winhttp"
)

// +-----------+-----------------+
// | mode flag | WinHTTP Request |
// +-----------+-----------------+
// |   byte    |       var       |
// +-----------+-----------------+

const modeHTTP = 3

// HTTP is the HTTP mode.
type HTTP struct {
	URL  string
	Opts *HTTPOptions
}

// HTTPOptions contains HTTP mode options.
type HTTPOptions struct {
	Headers   http.Header
	UserAgent string
	ProxyURL  string
	ProxyUser string
	ProxyPass string

	ConnectTimeout time.Duration
	SendTimeout    time.Duration
	ReceiveTimeout time.Duration

	MaxBodySize uint32
	AccessType  uint8
}

// NewHTTP is used to create image with HTTP mode.
func NewHTTP(url string, opts *HTTPOptions) Image {
	if opts == nil {
		opts = &HTTPOptions{}
	}
	return &HTTP{URL: url, Opts: opts}
}

// Encode implement Image interface.
func (h *HTTP) Encode() ([]byte, error) {
	req, err := url.ParseRequestURI(h.URL)
	if err != nil {
		return nil, err
	}
	connectTimeout := uint32(h.Opts.ConnectTimeout.Milliseconds()) // #nosec G115
	sendTimeout := uint32(h.Opts.SendTimeout.Milliseconds())       // #nosec G115
	receiveTimeout := uint32(h.Opts.ReceiveTimeout.Milliseconds()) // #nosec G115
	request := winhttp.Request{
		URL:            req.String(),
		UserAgent:      h.Opts.UserAgent,
		ProxyUser:      h.Opts.ProxyUser,
		ProxyPass:      h.Opts.ProxyPass,
		ConnectTimeout: connectTimeout,
		SendTimeout:    sendTimeout,
		ReceiveTimeout: receiveTimeout,
		MaxBodySize:    h.Opts.MaxBodySize,
		AccessType:     h.Opts.AccessType,
	}
	if h.Opts.Headers != nil {
		buf := bytes.Buffer{}
		_ = h.Opts.Headers.Write(&buf)
		request.Headers = buf.String()
	}
	if h.Opts.ProxyURL != "" {
		req, err = url.ParseRequestURI(h.Opts.ProxyURL)
		if err != nil {
			return nil, err
		}
		URL := req.String()
		// remove the last "/"
		if URL[len(URL)-1] == '/' {
			URL = URL[:len(URL)-1]
		}
		request.ProxyURL = URL
	}
	data, err := serialization.Marshal(&request)
	if err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 512))
	// write the mode
	buffer.WriteByte(modeHTTP)
	// write the winhttp request
	buffer.Write(data)
	return buffer.Bytes(), nil
}

// Mode implement Image interface.
func (h *HTTP) Mode() string {
	return ModeHTTP
}
