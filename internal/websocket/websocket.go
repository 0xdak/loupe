// Package websocket relays WebSocket frames unchanged while recording the
// messages they carry.
package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// Opcodes of data frames (RFC 6455 5.2).
const (
	OpText   = 1
	OpBinary = 2
)

// MaxMessage is how many bytes of a message are recorded.
const MaxMessage = 1 << 20

// Message is one recorded WebSocket message.
type Message struct {
	ID        int64     `json:"id"`
	FlowID    int64     `json:"flowId"` // the handshake
	Time      time.Time `json:"time"`
	URL       string    `json:"url"`
	ToServer  bool      `json:"toServer"`
	Opcode    int       `json:"opcode"`
	Length    int       `json:"length"` // full length, also when Data is truncated
	Data      []byte    `json:"data,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
}

// Store keeps the most recent messages in memory.
type Store struct {
	mu     sync.Mutex
	keep   int
	nextID int64
	msgs   []*Message
	subs   []func(*Message)
}

// NewStore returns a store that keeps the last keep messages.
func NewStore(keep int) *Store { return &Store{keep: keep} }

// Subscribe calls fn for every new message.
func (s *Store) Subscribe(fn func(*Message)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs = append(s.subs, fn)
}

// Add assigns m an ID and stores it.
func (s *Store) Add(m *Message) {
	s.mu.Lock()
	s.nextID++
	m.ID = s.nextID
	s.msgs = append(s.msgs, m)
	if len(s.msgs) > s.keep {
		s.msgs = s.msgs[len(s.msgs)-s.keep:]
	}
	subs := s.subs
	s.mu.Unlock()
	for _, fn := range subs {
		fn(m)
	}
}

// Recent returns up to n of the newest messages, oldest first.
func (s *Store) Recent(n int) []*Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.msgs) {
		n = len(s.msgs)
	}
	return append([]*Message(nil), s.msgs[len(s.msgs)-n:]...)
}

// Get returns the message with id, if it is still kept.
func (s *Store) Get(id int64) (*Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.msgs {
		if m.ID == id {
			return m, true
		}
	}
	return nil, false
}

// Relay copies frames from src to dst byte for byte and calls emit with each
// complete data message, unmasked and capped at MaxMessage. Control frames
// are relayed but not reported. It returns when either side fails or closes.
func Relay(dst io.Writer, src *bufio.Reader, emit func(opcode int, data []byte, length int, truncated bool)) error {
	var (
		hdr    [14]byte
		msgOp  int
		msg    []byte
		msgLen int
		chunk  = make([]byte, 32<<10)
	)
	for {
		if _, err := io.ReadFull(src, hdr[:2]); err != nil {
			return err
		}
		fin, op := hdr[0]&0x80 != 0, int(hdr[0]&0x0f)
		masked := hdr[1]&0x80 != 0
		n, hl := uint64(hdr[1]&0x7f), 2
		switch n {
		case 126:
			if _, err := io.ReadFull(src, hdr[2:4]); err != nil {
				return err
			}
			n, hl = uint64(binary.BigEndian.Uint16(hdr[2:4])), 4
		case 127:
			if _, err := io.ReadFull(src, hdr[2:10]); err != nil {
				return err
			}
			n, hl = binary.BigEndian.Uint64(hdr[2:10]), 10
		}
		var key []byte
		if masked {
			if _, err := io.ReadFull(src, hdr[hl:hl+4]); err != nil {
				return err
			}
			key = hdr[hl : hl+4]
			hl += 4
		}
		if _, err := dst.Write(hdr[:hl]); err != nil {
			return err
		}

		data := op < 8 // control frames have opcodes 8 and up
		if data && op != 0 {
			msgOp, msg, msgLen = op, msg[:0], 0
		}
		for pos := uint64(0); pos < n; {
			want := min(uint64(len(chunk)), n-pos)
			got, err := io.ReadFull(src, chunk[:want])
			if got > 0 {
				if _, werr := dst.Write(chunk[:got]); werr != nil {
					return werr
				}
				if data {
					room := MaxMessage - len(msg)
					take := min(got, max(room, 0))
					start := len(msg)
					msg = append(msg, chunk[:take]...)
					if masked {
						for i := range take {
							msg[start+i] ^= key[(pos+uint64(i))%4]
						}
					}
					msgLen += got
				}
				pos += uint64(got)
			}
			if err != nil {
				return err
			}
		}
		if data && fin && msgOp != 0 {
			emit(msgOp, bytes.Clone(msg), msgLen, msgLen > len(msg))
			msgOp = 0
		}
	}
}
