package ext

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

func (e *extension) isRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *extension) commandLine() string {
	parts := append([]string{e.man.Command}, e.man.Args...)
	return strings.TrimSpace(strings.Join(parts, " "))
}

func (e *extension) appendLog(line string) {
	e.mu.Lock()
	e.logs = append(e.logs, line)
	if len(e.logs) > maxLogs {
		e.logs = e.logs[len(e.logs)-maxLogs:]
	}
	e.mu.Unlock()
}

// send queues a line for the extension's stdin without blocking the caller; if
// the extension is backed up, the event is dropped.
func (e *extension) send(line []byte) {
	e.mu.Lock()
	in := e.in
	e.mu.Unlock()
	if in == nil {
		return
	}
	select {
	case in <- line:
	default: // extension is too slow; drop rather than stall the proxy
	}
}

// launch starts the extension process (if not already running) and the
// goroutines that feed it and read its output.
func (m *Manager) launch(e *extension) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	if strings.TrimSpace(e.man.Command) == "" {
		e.errMsg = "manifest has no command to run"
		e.mu.Unlock()
		return
	}
	cmd := exec.Command(e.man.Command, e.man.Args...)
	cmd.Dir = e.dir
	cmd.Env = cleanEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		e.errMsg = err.Error()
		e.mu.Unlock()
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.errMsg = err.Error()
		e.mu.Unlock()
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		e.errMsg = err.Error()
		e.mu.Unlock()
		return
	}
	if err := cmd.Start(); err != nil {
		e.errMsg = "could not start: " + err.Error()
		e.mu.Unlock()
		return
	}
	in := make(chan []byte, feedQueue)
	var once sync.Once
	e.in = in
	e.running = true
	e.errMsg = ""
	e.stop = func() {
		once.Do(func() {
			close(in)
			_ = cmd.Process.Kill()
		})
	}
	e.mu.Unlock()

	// Writer: drain the queue to stdin until the queue is closed.
	go func() {
		defer stdin.Close()
		for line := range in {
			if _, err := stdin.Write(append(line, '\n')); err != nil {
				return
			}
		}
	}()

	// stderr: capture as log lines.
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			e.appendLog("stderr: " + sc.Text())
		}
	}()

	// stdout: parse one JSON message per line.
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			m.handleLine(e, sc.Bytes())
		}
	}()

	// Reap the process and mark it stopped when it exits.
	go func() {
		err := cmd.Wait()
		e.mu.Lock()
		e.running = false
		if e.in == in {
			e.in = nil
		}
		if err != nil && e.enabled {
			e.errMsg = "exited: " + err.Error()
		}
		e.mu.Unlock()
		m.changed()
	}()
}

func (m *Manager) handleLine(e *extension, raw []byte) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || raw[0] != '{' {
		if len(raw) > 0 {
			e.appendLog("out: " + string(raw))
		}
		return
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		e.appendLog("bad JSON: " + string(raw))
		return
	}
	switch asString(msg["type"]) {
	case "issue":
		m.addIssue(e, msg)
	case "log":
		e.appendLog(asString(msg["message"]))
	case "hello":
		e.appendLog("hello: " + asString(msg["name"]) + " " + asString(msg["version"]))
	default:
		e.appendLog("out: " + string(raw))
	}
}

// halt stops the extension's process if it is running.
func (e *extension) halt() {
	e.mu.Lock()
	stop := e.stop
	e.stop = nil
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// cleanEnv is a minimal environment for extension processes: enough to find an
// interpreter, but without passing Loupe's whole environment (and any secrets
// in it) down to third-party code.
func cleanEnv() []string {
	keep := []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
	if runtime.GOOS == "windows" {
		keep = append(keep, "SystemRoot", "SYSTEMROOT", "windir", "USERPROFILE", "TEMP", "TMP",
			"PATHEXT", "ComSpec", "APPDATA", "LOCALAPPDATA")
	}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func readManifest(dir string) (Manifest, error) {
	var man Manifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return man, err
	}
	if err := json.Unmarshal(data, &man); err != nil {
		return man, fmt.Errorf("manifest.json: %w", err)
	}
	if strings.TrimSpace(man.Name) == "" {
		man.Name = filepath.Base(dir)
	}
	return man, nil
}

// ── enabled-state persistence ──

func stateFile(dir string) string { return filepath.Join(dir, "state.json") }

func loadState(dir string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(stateFile(dir))
	if err != nil {
		return out
	}
	var st struct {
		Enabled map[string]bool `json:"enabled"`
	}
	if json.Unmarshal(data, &st) == nil {
		for k, v := range st.Enabled {
			out[k] = v
		}
	}
	return out
}

func saveState(dir string, enabled map[string]bool) {
	data, err := json.MarshalIndent(struct {
		Enabled map[string]bool `json:"enabled"`
	}{enabled}, "", "  ")
	if err != nil {
		return
	}
	tmp := stateFile(dir) + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, stateFile(dir))
	}
}

// ── small JSON coercions ──

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64:
		return strings.TrimSuffix(fmt.Sprintf("%v", t), ".0")
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}

func normSeverity(s string) string {
	if v, ok := severities[strings.ToLower(strings.TrimSpace(s))]; ok {
		return v
	}
	return "Info"
}
