package ext

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"loupe/internal/flow"
)

func TestExtractAndDiscoverExample(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	defer m.Close()
	if _, err := os.Stat(filepath.Join(dir, "passive-scan", "manifest.json")); err != nil {
		t.Fatalf("example extension was not extracted: %v", err)
	}
	var found *Status
	for _, s := range m.List() {
		if s.Name == "passive-scan" {
			s := s
			found = &s
		}
	}
	if found == nil {
		t.Fatal("passive-scan not discovered")
	}
	if found.Enabled {
		t.Error("example should start disabled so nothing runs unasked")
	}
	if len(found.Events) == 0 || found.Events[0] != "http.response" {
		t.Errorf("manifest events not loaded: %v", found.Events)
	}
}

func TestExtractDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	NewManager(dir).Close()
	edited := filepath.Join(dir, "passive-scan", "manifest.json")
	if err := os.WriteFile(edited, []byte(`{"name":"passive-scan","events":["http.response"],"command":"mine"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	NewManager(dir).Close() // second run must not overwrite the edited copy
	data, _ := os.ReadFile(edited)
	var man Manifest
	json.Unmarshal(data, &man)
	if man.Command != "mine" {
		t.Errorf("extraction clobbered an existing extension: command=%q", man.Command)
	}
}

func TestStatePersistsEnabled(t *testing.T) {
	dir := t.TempDir()
	saveState(dir, map[string]bool{"x": true, "y": false})
	got := loadState(dir)
	if !got["x"] || got["y"] {
		t.Errorf("state round-trip wrong: %v", got)
	}
}

func TestSetEnabledUnknown(t *testing.T) {
	m := NewManager(t.TempDir())
	defer m.Close()
	if err := m.SetEnabled("nope", true); err == nil {
		t.Error("enabling an unknown extension should error")
	}
}

func TestHandleIssueLine(t *testing.T) {
	m := &Manager{urls: map[int64]string{7: "http://t/path"}}
	e := &extension{man: Manifest{Name: "scan"}}
	m.handleLine(e, []byte(`{"type":"issue","flow":7,"name":"Reflected","severity":"medium","detail":"d","evidence":"ev"}`))
	m.handleLine(e, []byte(`{"type":"log","message":"hello"}`))
	m.handleLine(e, []byte(`not json`))
	iss := m.Issues()
	if len(iss) != 1 {
		t.Fatalf("want 1 issue, got %d", len(iss))
	}
	if iss[0].Severity != "Medium" {
		t.Errorf("severity not normalised: %q", iss[0].Severity)
	}
	if iss[0].URL != "http://t/path" {
		t.Errorf("issue URL not enriched from flow: %q", iss[0].URL)
	}
	if iss[0].FlowID != 7 || iss[0].Name != "Reflected" {
		t.Errorf("issue fields wrong: %+v", iss[0])
	}
	if logs := m.Logs("scan"); len(logs) == 0 {
		// scan has no registered extension in m.exts, so Logs("scan") is nil here;
		// the log line went to e directly.
	}
	if len(e.logs) == 0 {
		t.Error("log and bad-json lines should be recorded")
	}
}

func TestFeedBuildsEvent(t *testing.T) {
	e := &extension{man: Manifest{Name: "t", Events: []string{"http.response"}}, enabled: true}
	e.running = true
	e.in = make(chan []byte, 4)
	m := &Manager{exts: []*extension{e}}
	m.Feed(&flow.Flow{ID: 9, Method: "GET", URL: "http://x/y", Target: flow.Target{Host: "x"},
		Status: 200, Request: []byte("GET /y HTTP/1.1\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nhi")})
	select {
	case line := <-e.in:
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("event not JSON: %v", err)
		}
		if ev["type"] != "http.response" || ev["flow"].(float64) != 9 {
			t.Errorf("event fields wrong: %v", ev)
		}
		if ev["request"] == "" || ev["response"] == "" {
			t.Error("event missing base64 bodies")
		}
	default:
		t.Fatal("Feed did not deliver an event to the extension")
	}
}

func TestFeedSkipsDisabled(t *testing.T) {
	e := &extension{man: Manifest{Name: "t", Events: []string{"http.response"}}, enabled: false}
	e.running = true
	e.in = make(chan []byte, 4)
	m := &Manager{exts: []*extension{e}}
	m.Feed(&flow.Flow{ID: 1, Response: []byte("HTTP/1.1 200 OK\r\n\r\nx")})
	if len(e.in) != 0 {
		t.Error("a disabled extension should not receive events")
	}
}
