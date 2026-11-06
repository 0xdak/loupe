package intruder

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"loupe/internal/flow"
)

func TestCombine(t *testing.T) {
	defaults := []string{"a", "b"}
	cases := []struct {
		attack string
		sets   [][]string
		want   [][]string
	}{
		{Sniper, [][]string{{"1", "2"}}, [][]string{{"1", "b"}, {"2", "b"}, {"a", "1"}, {"a", "2"}}},
		{BatteringRam, [][]string{{"1", "2"}}, [][]string{{"1", "1"}, {"2", "2"}}},
		{Pitchfork, [][]string{{"1", "2", "3"}, {"x", "y"}}, [][]string{{"1", "x"}, {"2", "y"}}},
		{ClusterBomb, [][]string{{"1", "2"}, {"x", "y"}}, [][]string{{"1", "x"}, {"2", "x"}, {"1", "y"}, {"2", "y"}}},
	}
	for _, c := range cases {
		got, err := Combine(c.attack, defaults, c.sets)
		if err != nil {
			t.Fatalf("%s: %v", c.attack, err)
		}
		if !slices.EqualFunc(got, c.want, slices.Equal) {
			t.Errorf("%s: got %v, want %v", c.attack, got, c.want)
		}
	}
	if _, err := Combine(Pitchfork, defaults, [][]string{{"1"}}); err == nil {
		t.Error("pitchfork with too few sets must fail")
	}
	big := make([]string, 1000)
	if _, err := Combine(ClusterBomb, []string{"", ""}, [][]string{big, big}); err == nil {
		t.Error("an attack over the cap must be refused")
	}
}

func TestPositions(t *testing.T) {
	lit, def, err := Positions("GET /?id=§1§&x=§§ HTTP/1.1")
	if err != nil || !slices.Equal(def, []string{"1", ""}) || len(lit) != 3 {
		t.Errorf("lit %q def %q err %v", lit, def, err)
	}
	for _, bad := range []string{"no markers", "one § only"} {
		if _, _, err := Positions(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

type recorder struct {
	mu   sync.Mutex
	sent []string
}

func (r *recorder) Exchange(_ context.Context, _ flow.Target, raw []byte) (*flow.Flow, error) {
	r.mu.Lock()
	r.sent = append(r.sent, string(raw))
	r.mu.Unlock()
	return &flow.Flow{Status: 200, Request: raw, Response: []byte("HTTP/1.1 200 OK\r\n\r\n" + string(raw))}, nil
}

func TestAttackRunsAndEncodes(t *testing.T) {
	rec := &recorder{}
	m := NewManager(rec)
	ended := make(chan struct{})
	m.Subscribe(func(a *Attack, r *Result) {
		if r == nil {
			close(ended)
		}
	})
	a, err := m.Start(Config{
		Template: "GET /?q=§x§ HTTP/1.1\nHost: t\n\n", Type: Sniper, URLEncode: true,
		Sets: []PayloadSet{{Type: "numbers", From: 1, To: 3}, {}}, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("attack did not finish")
	}
	st := a.Status(true)
	if !st.Done || st.Sent != 3 || len(st.Results) != 3 {
		t.Fatalf("status %+v", st)
	}
	slices.Sort(rec.sent)
	for i, s := range rec.sent {
		if !strings.HasPrefix(s, fmt.Sprintf("GET /?q=%d HTTP", i+1)) {
			t.Errorf("request %d = %q", i, s)
		}
	}
	if got := urlEncode("a b&c=d/é"); got != "a%20b%26c%3Dd%2F%C3%A9" {
		t.Errorf("urlEncode = %q", got)
	}
}
