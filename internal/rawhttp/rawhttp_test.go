package rawhttp

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"testing"
)

func TestParseRequestFromEditedText(t *testing.T) {
	// LF line ends, a stale Content-Length and a body containing a blank line.
	raw := "\nPOST /login?next=%2F HTTP/1.1\nHost: example.com\nContent-Length: 999\nX-A: 1\n\nuser=a\n\npass=b"
	req, err := ParseRequest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.RequestURI() != "/login?next=%2F" || req.Host != "example.com" {
		t.Errorf("method %q uri %q host %q", req.Method, req.URL.RequestURI(), req.Host)
	}
	if req.RequestURI != "" || req.URL.IsAbs() {
		t.Error("request must be usable as a client request with a caller-supplied target")
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "user=a\n\npass=b" || req.ContentLength != int64(len(body)) {
		t.Errorf("body %q, content length %d", body, req.ContentLength)
	}
	if got := req.Header.Get("Content-Length"); got != "14" {
		t.Errorf("Content-Length header = %q", got)
	}
	if req.Header.Get("X-A") != "1" {
		t.Error("header lost")
	}
}

func TestParseRequestWithoutBody(t *testing.T) {
	req, err := ParseRequest([]byte("GET / HTTP/1.1\r\nHost: a\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if req.ContentLength != 0 || req.Header.Get("Content-Length") != "" {
		t.Errorf("unexpected length: %d %q", req.ContentLength, req.Header.Get("Content-Length"))
	}
}

func TestParseRequestRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"", "  \n", "not a request"} {
		if _, err := ParseRequest([]byte(raw)); err == nil {
			t.Errorf("%q: expected an error", raw)
		}
	}
}

func TestDecompressed(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write([]byte("hello world"))
	zw.Close()
	msg := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "+strconv.Itoa(z.Len())+"\r\nX-A: 1\r\n\r\n"), z.Bytes()...)
	got := string(Decompressed(msg))
	if got != "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-A: 1\r\n\r\nhello world" {
		t.Errorf("Decompressed = %q", got)
	}
	if Decompressed([]byte("HTTP/1.1 200 OK\r\n\r\nplain")) != nil {
		t.Error("an uncompressed message has nothing to decode")
	}
}
