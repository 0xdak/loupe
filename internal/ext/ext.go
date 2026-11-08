// Package ext runs third-party extensions as separate programs and collects
// the issues they report.
//
// An extension is a directory holding a manifest.json and a program written in
// any language. Loupe launches the program and exchanges line-delimited JSON
// with it over stdio, so extensions need no shared runtime and Loupe never has
// to be recompiled to add one. The protocol is deliberately tiny:
//
//	Loupe -> extension (stdin), one compact JSON object per line:
//	  {"type":"http.response","flow":12,"method":"GET","url":"...","host":"...",
//	   "status":200,"request":"<base64>","response":"<base64>"}
//
//	extension -> Loupe (stdout), one JSON object per line, any of:
//	  {"type":"hello","name":"...","version":"...","events":["http.response"]}
//	  {"type":"issue","flow":12,"name":"...","severity":"High","detail":"...","evidence":"..."}
//	  {"type":"log","message":"..."}
//	anything on stderr is captured as the extension's error log.
//
// Extensions are local programs the tester installs and enables deliberately,
// exactly like Burp's Java extensions; Loupe never downloads or auto-runs one.
package ext

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"loupe/internal/flow"
	"loupe/internal/rawhttp"
)

const (
	maxIssues = 2000
	maxLogs   = 500
	feedQueue = 256
)

// Severity values, normalised from whatever an extension reports.
var severities = map[string]string{
	"info": "Info", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical",
}

// Issue is one finding reported by an extension.
type Issue struct {
	ID       int64     `json:"id"`
	Ext      string    `json:"ext"`
	FlowID   int64     `json:"flow,omitempty"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail,omitempty"`
	Evidence string    `json:"evidence,omitempty"`
	URL      string    `json:"url,omitempty"`
	Time     time.Time `json:"time"`
}

// Manifest is an extension's manifest.json.
type Manifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Events      []string `json:"events"`
	Command     string   `json:"command"`
	Args        []string `json:"args"`
}

// Status is the UI-facing view of one extension.
type Status struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Events      []string `json:"events"`
	Command     string   `json:"command"`
	Enabled     bool     `json:"enabled"`
	Running     bool     `json:"running"`
	Error       string   `json:"error,omitempty"`
	Issues      int      `json:"issues"`
	Logs        int      `json:"logs"`
}

type extension struct {
	man     Manifest
	dir     string
	enabled bool

	mu      sync.Mutex
	running bool
	errMsg  string
	logs    []string
	issues  int
	in      chan []byte
	stop    func()
}

func (e *extension) wants(event string) bool {
	for _, ev := range e.man.Events {
		if ev == event {
			return true
		}
	}
	return false
}

// Manager discovers, runs and supervises extensions, and keeps the issues they
// report.
type Manager struct {
	dir string

	mu       sync.Mutex
	exts     []*extension
	issues   []*Issue
	issueSeq int64
	urls     map[int64]string // recent flow id -> URL, to label issues
	urlOrder []int64

	onIssue  func(*Issue)
	onChange func()
}

// NewManager extracts the bundled example extensions into dir (without ever
// overwriting one already there), discovers every extension in dir and loads
// which were previously enabled. Nothing is started until SetEnabled is called,
// so no third-party code runs unless the tester turns it on.
func NewManager(dir string) *Manager {
	m := &Manager{dir: dir}
	if err := os.MkdirAll(dir, 0o755); err == nil {
		m.extractExamples()
	}
	m.discover(loadState(dir))
	// Resume extensions the tester had enabled before, as Burp reloads its
	// extensions on startup.
	m.mu.Lock()
	resume := []*extension{}
	for _, e := range m.exts {
		if e.enabled {
			resume = append(resume, e)
		}
	}
	m.mu.Unlock()
	for _, e := range resume {
		m.launch(e)
	}
	return m
}

// SetHooks registers callbacks fired when an issue arrives or an extension's
// state changes, so the UI can stream updates. Safe to call once at start-up.
func (m *Manager) SetHooks(onIssue func(*Issue), onChange func()) {
	m.mu.Lock()
	m.onIssue, m.onChange = onIssue, onChange
	m.mu.Unlock()
}

func (m *Manager) find(name string) *extension {
	for _, e := range m.exts {
		if e.man.Name == name {
			return e
		}
	}
	return nil
}

// discover scans the extensions directory for subdirectories with a
// manifest.json, preserving the running state of extensions already loaded.
func (m *Manager) discover(enabled map[string]bool) {
	entries, _ := os.ReadDir(m.dir)
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		dir := filepath.Join(m.dir, de.Name())
		man, err := readManifest(dir)
		if err != nil {
			continue
		}
		seen[man.Name] = true
		if e := m.find(man.Name); e != nil {
			e.man = man // refresh metadata; leave a running process alone
			continue
		}
		m.exts = append(m.exts, &extension{man: man, dir: dir, enabled: enabled[man.Name]})
	}
	// Drop extensions whose directory disappeared (stopping them if running).
	kept := m.exts[:0]
	for _, e := range m.exts {
		if seen[e.man.Name] {
			kept = append(kept, e)
		} else {
			e.halt()
		}
	}
	m.exts = kept
	sort.Slice(m.exts, func(i, j int) bool { return m.exts[i].man.Name < m.exts[j].man.Name })
}

// Reload re-scans the directory, picking up newly added extensions, and starts
// any that are marked enabled but not yet running.
func (m *Manager) Reload() {
	m.discover(m.enabledMap())
	m.mu.Lock()
	start := []*extension{}
	for _, e := range m.exts {
		if e.enabled && !e.isRunning() {
			start = append(start, e)
		}
	}
	m.mu.Unlock()
	for _, e := range start {
		m.launch(e)
	}
	m.changed()
}

func (m *Manager) enabledMap() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, e := range m.exts {
		out[e.man.Name] = e.enabled
	}
	return out
}

// List returns a snapshot of every known extension for the UI.
func (m *Manager) List() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.exts))
	for _, e := range m.exts {
		e.mu.Lock()
		out = append(out, Status{
			Name: e.man.Name, Version: e.man.Version, Author: e.man.Author,
			Description: e.man.Description, Events: e.man.Events, Command: e.commandLine(),
			Enabled: e.enabled, Running: e.running, Error: e.errMsg, Issues: e.issues, Logs: len(e.logs),
		})
		e.mu.Unlock()
	}
	return out
}

// SetEnabled turns an extension on (starting its process) or off (stopping it),
// and remembers the choice.
func (m *Manager) SetEnabled(name string, on bool) error {
	m.mu.Lock()
	e := m.find(name)
	m.mu.Unlock()
	if e == nil {
		return fmt.Errorf("no extension named %q", name)
	}
	e.enabled = on
	if on {
		m.launch(e)
	} else {
		e.halt()
	}
	saveState(m.dir, m.enabledMap())
	m.changed()
	return nil
}

// Logs returns the recent stdout "log" lines and stderr output of an extension.
func (m *Manager) Logs(name string) []string {
	m.mu.Lock()
	e := m.find(name)
	m.mu.Unlock()
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.logs...)
}

// Issues returns the collected issues, newest first.
func (m *Manager) Issues() []*Issue {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Issue, len(m.issues))
	for i, is := range m.issues {
		out[len(m.issues)-1-i] = is
	}
	return out
}

// ClearIssues drops every collected issue.
func (m *Manager) ClearIssues() {
	m.mu.Lock()
	m.issues = nil
	m.mu.Unlock()
	m.changed()
}

// Feed offers a completed flow to every enabled extension that subscribed to
// http.response. It never blocks the proxy: an extension that cannot keep up
// misses events.
func (m *Manager) Feed(f *flow.Flow) {
	if f == nil || len(f.Response) == 0 {
		return
	}
	m.mu.Lock()
	var targets []*extension
	for _, e := range m.exts {
		if e.enabled && e.wants("http.response") && e.isRunning() {
			targets = append(targets, e)
		}
	}
	if len(targets) > 0 {
		if m.urls == nil {
			m.urls = map[int64]string{}
		}
		if _, ok := m.urls[f.ID]; !ok {
			m.urls[f.ID] = f.URL
			m.urlOrder = append(m.urlOrder, f.ID)
			if len(m.urlOrder) > 4096 {
				delete(m.urls, m.urlOrder[0])
				m.urlOrder = m.urlOrder[1:]
			}
		}
	}
	m.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	resp := f.Response
	if dec := rawhttp.Decode(resp); dec != nil {
		resp = dec
	}
	ev := map[string]any{
		"type": "http.response", "flow": f.ID, "method": f.Method, "url": f.URL,
		"host": f.Target.Host, "status": f.Status,
		"request":  base64.StdEncoding.EncodeToString(f.Request),
		"response": base64.StdEncoding.EncodeToString(resp),
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	for _, e := range targets {
		e.send(line)
	}
}

// Close stops every running extension.
func (m *Manager) Close() {
	m.mu.Lock()
	exts := append([]*extension(nil), m.exts...)
	m.mu.Unlock()
	for _, e := range exts {
		e.halt()
	}
}

func (m *Manager) changed() {
	m.mu.Lock()
	fn := m.onChange
	m.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (m *Manager) addIssue(e *extension, raw map[string]any) {
	is := &Issue{
		Ext:      e.man.Name,
		FlowID:   asInt64(raw["flow"]),
		Name:     strings.TrimSpace(asString(raw["name"])),
		Severity: normSeverity(asString(raw["severity"])),
		Detail:   asString(raw["detail"]),
		Evidence: asString(raw["evidence"]),
		URL:      asString(raw["url"]),
		Time:     time.Now(),
	}
	if is.Name == "" {
		is.Name = "(unnamed issue)"
	}
	m.mu.Lock()
	if is.URL == "" && is.FlowID != 0 {
		is.URL = m.urls[is.FlowID]
	}
	m.issueSeq++
	is.ID = m.issueSeq
	m.issues = append(m.issues, is)
	if len(m.issues) > maxIssues {
		m.issues = m.issues[len(m.issues)-maxIssues:]
	}
	fn := m.onIssue
	m.mu.Unlock()
	e.mu.Lock()
	e.issues++
	e.mu.Unlock()
	if fn != nil {
		fn(is)
	}
}
