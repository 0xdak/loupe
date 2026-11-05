// Package rawhttp converts between HTTP/1.1 message text and net/http values.
// It owns the text form shown to people and parsed back after they edit it.
package rawhttp

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// RequestHead renders the request line and headers. Header order and case
// are normalised by net/http, so this is close to, not identical to, the wire.
func RequestHead(r *http.Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	r.Header.Write(&b)
	b.WriteString("\r\n")
	return b.Bytes()
}

// ResponseHead renders the status line and headers.
func ResponseHead(resp *http.Response) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	resp.Header.Write(&b)
	b.WriteString("\r\n")
	return b.Bytes()
}

// ParseRequest parses request text written or edited by a person, ready to
// be sent with an http.RoundTripper.
//
// The head may use LF line endings, as text from a browser textarea does.
// Everything after the first blank line is the body, whatever Content-Length
// said, and Content-Length is recomputed. Transfer-Encoding is dropped since
// the body is sent as typed. The URL keeps the form of the request line, so
// an origin-form target has no scheme or host; the caller supplies them.
func ParseRequest(raw []byte) (*http.Request, error) {
	head, body := Split(bytes.TrimLeft(raw, "\r\n\t "))
	if len(head) == 0 {
		return nil, fmt.Errorf("the request is empty")
	}
	req, err := http.ReadRequest(headReader(head))
	if err != nil {
		return nil, fmt.Errorf("parsing the request: %w", err)
	}
	req.RequestURI = "" // set by ReadRequest, but not allowed in client requests
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	SetBody(req, body)
	return req, nil
}

// ParseResponse parses response text edited by a person, with the same
// rules as ParseRequest.
func ParseResponse(raw []byte) (*http.Response, error) {
	head, body := Split(bytes.TrimLeft(raw, "\r\n\t "))
	if len(head) == 0 {
		return nil, fmt.Errorf("the response is empty")
	}
	resp, err := http.ReadResponse(headReader(head), nil)
	if err != nil {
		return nil, fmt.Errorf("parsing the response: %w", err)
	}
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	SetResponseBody(resp, body)
	return resp, nil
}

func headReader(head []byte) *bufio.Reader {
	return bufio.NewReader(io.MultiReader(bytes.NewReader(head), strings.NewReader("\r\n\r\n")))
}

// SetBody replaces the request body with b and makes the length headers match.
func SetBody(req *http.Request, b []byte) {
	req.ContentLength = int64(len(b))
	req.Header.Del("Content-Length")
	if len(b) == 0 {
		req.Body, req.GetBody = http.NoBody, func() (io.ReadCloser, error) { return http.NoBody, nil }
		return
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(b)))
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

// SetResponseBody replaces the response body with b and sets Content-Length.
func SetResponseBody(resp *http.Response, b []byte) {
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Body = io.NopCloser(bytes.NewReader(b))
}

// ReadBody reads up to limit bytes of a request body. If the body is whole,
// it is replaced by the bytes read; otherwise the bytes are put back in front
// of the rest so the request is still sent in full, and whole is false.
func ReadBody(req *http.Request, limit int64) (body []byte, whole bool, err error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true, nil
	}
	body, rest, whole, err := readUpTo(req.Body, limit)
	if err != nil || !whole {
		req.Body = rest
		return nil, false, err
	}
	SetBody(req, body)
	return body, true, nil
}

// ReadResponseBody is ReadBody for a response.
func ReadResponseBody(resp *http.Response, limit int64) (body []byte, whole bool, err error) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return nil, true, nil
	}
	body, rest, whole, err := readUpTo(resp.Body, limit)
	if err != nil || !whole {
		resp.Body = rest
		return nil, false, err
	}
	// Keep a chunked response chunked; only a known length is rewritten.
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if resp.ContentLength >= 0 {
		SetResponseBody(resp, body)
	}
	return body, true, nil
}

func readUpTo(rc io.ReadCloser, limit int64) (body []byte, rest io.ReadCloser, whole bool, err error) {
	body, err = io.ReadAll(io.LimitReader(rc, limit+1))
	rest = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), rc), rc}
	if err != nil {
		return nil, rest, false, err
	}
	if int64(len(body)) > limit {
		return nil, rest, false, nil
	}
	return body, nil, true, nil
}

// ReplaceRequest makes dst the edited request src. An origin-form request
// line keeps dst's scheme and host, so editing the Host header alone does not
// change where the request goes.
func ReplaceRequest(dst, src *http.Request) {
	u := *src.URL
	if !u.IsAbs() {
		u.Scheme, u.Host = dst.URL.Scheme, dst.URL.Host
	}
	dst.Method, dst.URL, dst.Host, dst.Header = src.Method, &u, src.Host, src.Header
	dst.Body, dst.GetBody, dst.ContentLength = src.Body, src.GetBody, src.ContentLength
	dst.TransferEncoding, dst.Close = nil, src.Close
}

// ReplaceResponse makes dst the edited response src.
func ReplaceResponse(dst, src *http.Response) {
	dst.Status, dst.StatusCode = src.Status, src.StatusCode
	dst.Proto, dst.ProtoMajor, dst.ProtoMinor = src.Proto, src.ProtoMajor, src.ProtoMinor
	dst.Header, dst.Body, dst.ContentLength = src.Header, src.Body, src.ContentLength
	dst.TransferEncoding = nil
}

// Split cuts a message at the first blank line, accepting CRLF and LF line
// ends. Without a blank line the whole message is the head.
func Split(raw []byte) (head, body []byte) {
	cut, sep := -1, 0
	for _, s := range []string{"\r\n\r\n", "\n\n", "\n\r\n"} {
		if i := bytes.Index(raw, []byte(s)); i >= 0 && (cut < 0 || i < cut) {
			cut, sep = i, len(s)
		}
	}
	if cut < 0 {
		return bytes.TrimRight(raw, "\r\n\t "), nil
	}
	return raw[:cut], raw[cut+sep:]
}

// Decompressed returns msg with a gzip or deflate body inflated and the
// Content-Encoding header removed, with Content-Length matching, so it can be
// read and edited as text. It returns nil when there is nothing to decode.
func Decompressed(msg []byte) []byte {
	d := Decode(msg)
	if d == nil {
		return nil
	}
	cut := bytes.Index(d, []byte("\r\n\r\n"))
	head, body := string(d[:cut]), d[cut+4:]
	var lines []string
	for i, line := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		switch {
		case i > 0 && strings.EqualFold(strings.TrimSpace(name), "Content-Encoding"):
			continue
		case i > 0 && strings.EqualFold(strings.TrimSpace(name), "Content-Length"):
			line = "Content-Length: " + strconv.Itoa(len(body))
		}
		lines = append(lines, line)
	}
	return append([]byte(strings.Join(lines, "\r\n")+"\r\n\r\n"), body...)
}

// Decode returns msg with its body decompressed when Content-Encoding is
// gzip or deflate, for display. It returns nil when there is nothing to
// decode. A truncated body yields as much as could be decoded.
func Decode(msg []byte) []byte {
	cut := bytes.Index(msg, []byte("\r\n\r\n"))
	if cut < 0 {
		return nil
	}
	head, body := msg[:cut+4], msg[cut+4:]
	var enc string
	for _, line := range strings.Split(string(head), "\r\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Content-Encoding") {
			enc = strings.ToLower(strings.TrimSpace(value))
		}
	}
	var r io.Reader
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil
		}
		r = zr
	case "deflate":
		// Servers send either zlib-wrapped or raw deflate data.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(body))
		}
	default:
		return nil
	}
	out, _ := io.ReadAll(io.LimitReader(r, 32<<20))
	if len(out) == 0 && len(body) > 0 {
		return nil
	}
	return append(bytes.Clone(head), out...)
}
