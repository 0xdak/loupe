// Package scope decides which hosts are being tested, and which are the
// browser's own background traffic.
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Scope is a list of host patterns. An empty scope includes every host.
//
// A pattern is a host name ("example.com", which matches only that host) or a
// wildcard ("*.example.com", which matches example.com and every subdomain).
type Scope struct {
	mu       sync.RWMutex
	patterns []string
	path     string
}

// Load reads patterns from path, one per line. A missing file is an empty
// scope. An empty path keeps the scope in memory only.
func Load(path string) (*Scope, error) {
	s := &Scope{path: path}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	patterns, err := Normalize(strings.Split(string(data), "\n"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.patterns = patterns
	return s, nil
}

// Normalize validates patterns and returns them lowercased, without blanks
// or duplicates. A pasted URL is reduced to its host.
func Normalize(in []string) ([]string, error) {
	var out []string
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if strings.Contains(p, "://") {
			u, err := url.Parse(p)
			if err != nil || u.Hostname() == "" {
				return nil, fmt.Errorf("%q is not a host or URL", p)
			}
			p = u.Hostname()
		}
		p = strings.TrimSuffix(p, ".")
		name := strings.TrimPrefix(p, "*.")
		if name == "" || strings.ContainsAny(name, "*/:@ \t?#") {
			return nil, fmt.Errorf("%q is not a host pattern; use example.com or *.example.com", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Patterns returns a copy of the current patterns.
func (s *Scope) Patterns() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.patterns...) // never nil, so JSON shows []
}

// Set replaces the patterns and saves them if the scope has a file.
func (s *Scope) Set(patterns []string) error {
	patterns, err := Normalize(patterns)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" {
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			return err
		}
		data := strings.Join(patterns, "\n")
		if data != "" {
			data += "\n"
		}
		if err := os.WriteFile(s.path, []byte(data), 0o600); err != nil {
			return err
		}
	}
	s.patterns = patterns
	return nil
}

// Includes reports whether host, which may carry a port, is in scope.
func (s *Scope) Includes(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.patterns) == 0 {
		return true
	}
	host = hostname(host)
	for _, p := range s.patterns {
		if match(p, host) {
			return true
		}
	}
	return false
}

func match(pattern, host string) bool {
	if name, ok := strings.CutPrefix(pattern, "*."); ok {
		return host == name || strings.HasSuffix(host, "."+name)
	}
	return host == pattern
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// noise lists services that Chromium-based browsers contact on their own:
// safe browsing, updates, telemetry and the new tab page.
var noise = []string{
	"*.smartscreen.microsoft.com", "smartscreen.microsoft.com", "*.smartscreen-prod.microsoft.com",
	"edge.microsoft.com", "*.edge.microsoft.com", "config.edge.skype.com", "*.events.data.microsoft.com",
	"*.msn.com", "edge.activity.windows.com", "browser.events.data.msn.com", "go.microsoft.com",
	"update.googleapis.com", "safebrowsing.googleapis.com", "clientservices.googleapis.com",
	"optimizationguide-pa.googleapis.com", "content-autofill.googleapis.com",
	"android.clients.google.com", "clients2.google.com",
	"clients1.google.com", "redirector.gvt1.com", "*.gvt1.com", "edgedl.me.gvt1.com",
	"*.brave.com", "*.bravesoftware.com",
}

// Noise reports whether host, which may carry a port, is a known browser
// background service.
func Noise(host string) bool {
	host = hostname(host)
	for _, p := range noise {
		if match(p, host) {
			return true
		}
	}
	return false
}
