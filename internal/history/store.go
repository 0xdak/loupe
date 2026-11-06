// Package history persists flows as JSON lines and keeps the most recent
// ones in memory.
package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"

	"loupe/internal/flow"
)

// Store appends flows to a JSON-lines file. It is safe for concurrent use.
type Store struct {
	lastID atomic.Int64

	mu     sync.Mutex
	file   *os.File
	w      *bufio.Writer
	enc    *json.Encoder
	keep   int
	recent []*flow.Flow
	subs   []func(*flow.Flow)
}

// Open opens or creates the history file at path. IDs continue after the
// highest ID already in the file, and up to keep flows are held in memory.
func Open(path string, keep int) (*Store, error) {
	if keep <= 0 {
		keep = 1000
	}
	s := &Store{keep: keep}
	_, err := Each(path, func(f *flow.Flow) error {
		if f.ID > s.lastID.Load() {
			s.lastID.Store(f.ID)
		}
		s.pushRecent(f)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	// An interrupted write can leave a partial last line; start on a fresh one.
	ok, err := endsWithNewline(file)
	if err == nil && !ok {
		_, err = file.Write([]byte("\n"))
	}
	if err != nil {
		file.Close()
		return nil, err
	}

	s.file = file
	s.w = bufio.NewWriter(file)
	s.enc = json.NewEncoder(s.w)
	return s, nil
}

// NextID reserves the ID for a new flow.
func (s *Store) NextID() int64 { return s.lastID.Add(1) }

// Subscribe registers fn to be called after each flow is stored. Callbacks
// may run concurrently.
func (s *Store) Subscribe(fn func(*flow.Flow)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs = append(s.subs, fn)
}

// Add writes f to the history file and notifies subscribers.
func (s *Store) Add(f *flow.Flow) error {
	s.mu.Lock()
	err := s.enc.Encode(f)
	if err == nil {
		err = s.w.Flush()
	}
	s.pushRecent(f)
	subs := s.subs
	s.mu.Unlock()

	for _, fn := range subs {
		fn(f)
	}
	return err
}

// Recent returns up to n of the most recently stored flows, oldest first.
func (s *Store) Recent(n int) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	n = min(n, len(s.recent))
	return append([]*flow.Flow(nil), s.recent[len(s.recent)-n:]...)
}

// Get returns the flow with the given ID if it is still held in memory.
func (s *Store) Get(id int64) (*flow.Flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.recent) - 1; i >= 0; i-- {
		if s.recent[i].ID == id {
			return s.recent[i], true
		}
	}
	return nil, false
}

// Close flushes and closes the history file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.w.Flush()
	if cerr := s.file.Close(); err == nil {
		err = cerr
	}
	return err
}

func (s *Store) pushRecent(f *flow.Flow) {
	if len(s.recent) < s.keep {
		s.recent = append(s.recent, f)
		return
	}
	copy(s.recent, s.recent[1:])
	s.recent[len(s.recent)-1] = f
}

// Each calls fn for every flow in the history file at path, in file order.
// Lines that cannot be parsed, such as a write cut short by a crash, are
// skipped and counted in skipped.
func Each(path string, fn func(*flow.Flow) error) (skipped int, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	r := bufio.NewReader(file)
	for {
		line, rerr := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var f flow.Flow
			if json.Unmarshal(line, &f) != nil {
				skipped++
			} else if err := fn(&f); err != nil {
				return skipped, err
			}
		}
		if rerr == io.EOF {
			return skipped, nil
		}
		if rerr != nil {
			return skipped, rerr
		}
	}
}

func endsWithNewline(f *os.File) (bool, error) {
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if st.Size() == 0 {
		return true, nil
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, st.Size()-1); err != nil {
		return false, err
	}
	return b[0] == '\n', nil
}
