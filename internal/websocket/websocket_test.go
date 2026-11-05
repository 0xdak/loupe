package websocket

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func frame(fin bool, op byte, mask []byte, payload []byte) []byte {
	var b bytes.Buffer
	first := op
	if fin {
		first |= 0x80
	}
	b.WriteByte(first)
	m := byte(0)
	if mask != nil {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b.WriteByte(m | byte(n))
	case n < 1<<16:
		b.WriteByte(m | 126)
		b.Write([]byte{byte(n >> 8), byte(n)})
	default:
		b.WriteByte(m | 127)
		b.Write([]byte{0, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
	if mask != nil {
		b.Write(mask)
		p := bytes.Clone(payload)
		for i := range p {
			p[i] ^= mask[i%4]
		}
		payload = p
	}
	b.Write(payload)
	return b.Bytes()
}

func TestRelayCopiesBytesAndRecordsMessages(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	big := strings.Repeat("x", 70000)
	var in bytes.Buffer
	in.Write(frame(true, OpText, key, []byte("hello")))
	in.Write(frame(false, OpText, nil, []byte("frag-")))
	in.Write(frame(true, 9, nil, []byte("ping"))) // control frame between fragments
	in.Write(frame(true, 0, nil, []byte("mented")))
	in.Write(frame(true, OpBinary, key, []byte(big)))
	wire := bytes.Clone(in.Bytes())

	var out bytes.Buffer
	var got []string
	err := Relay(&out, bufio.NewReader(&in), func(op int, data []byte, n int, trunc bool) {
		if n != len(data) || trunc {
			t.Errorf("length %d for %d bytes, truncated %v", n, len(data), trunc)
		}
		got = append(got, string(data))
	})
	if err != io.EOF {
		t.Fatalf("Relay: %v", err)
	}
	if !bytes.Equal(out.Bytes(), wire) {
		t.Error("frames were not relayed byte for byte")
	}
	if len(got) != 3 || got[0] != "hello" || got[1] != "frag-mented" || got[2] != big {
		t.Errorf("messages = %q", got)
	}
}
