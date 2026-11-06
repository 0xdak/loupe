// Package rules applies match-and-replace rules to traffic passing the proxy.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"loupe/internal/flow"
	"loupe/internal/pipeline"
	"loupe/internal/rawhttp"
)

// Rule types.
const (
	RequestHeader     = "request_header"
	RequestBody       = "request_body"
	RequestFirstLine  = "request_first_line"
	ResponseHeader    = "response_header"
	ResponseBody      = "response_body"
	ResponseFirstLine = "response_first_line"
)

// Rule replaces Match with Replace in one part of a message.
//
// For header rules each header line ("Name: value") is matched separately; a
// line that becomes empty is removed, and a rule with an empty Match adds
// Replace as a new header line.
type Rule struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
	Match   string `json:"match"`
	Replace string `json:"replace"`
	Regex   bool   `json:"regex"`
	Comment string `json:"comment,omitempty"`
}

type compiled struct {
	Rule
	re *regexp.Regexp // nil for a header rule that adds a line
}

func (c compiled) apply(s string) string {
	if c.Regex {
		return c.re.ReplaceAllString(s, c.Replace)
	}
	return c.re.ReplaceAllLiteralString(s, c.Replace)
}

func compile(r Rule) (compiled, error) {
	switch r.Type {
	case RequestHeader, RequestBody, RequestFirstLine, ResponseHeader, ResponseBody, ResponseFirstLine:
	default:
		return compiled{}, fmt.Errorf("unknown rule type %q", r.Type)
	}
	c := compiled{Rule: r}
	if r.Match == "" {
		if r.Type != RequestHeader && r.Type != ResponseHeader {
			return compiled{}, errors.New("only header rules may have an empty match (to add a header)")
		}
		return c, nil
	}
	expr := r.Match
	if !r.Regex {
		expr = regexp.QuoteMeta(expr)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return compiled{}, fmt.Errorf("rule %q: %w", r.Match, err)
	}
	c.re = re
	return c, nil
}

// Engine is a request and response hook that applies the enabled rules.
type Engine struct {
	maxBody int64
	path    string

	mu    sync.RWMutex
	rules []Rule
	comp  []compiled
}

// Load reads rules from path (JSON). A missing file gives the default rules;
// an empty path keeps the rules in memory only.
func Load(path string, maxBody int64) (*Engine, error) {
	e := &Engine{maxBody: maxBody, path: path}
	rules := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &rules); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	comp, err := compileAll(rules)
	if err != nil {
		return nil, err
	}
	e.rules, e.comp = rules, comp
	return e, nil
}

// Defaults are disabled examples, like the ones Burp ships.
func Defaults() []Rule {
	return []Rule{
		{Type: RequestHeader, Match: `^User-Agent:.*$`, Replace: "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", Regex: true, Comment: "Emulate iPhone"},
		{Type: RequestHeader, Match: `^If-Modified-Since:.*$`, Regex: true, Comment: "Require non-cached response"},
		{Type: RequestHeader, Match: `^If-None-Match:.*$`, Regex: true, Comment: "Require non-cached response"},
		{Type: ResponseHeader, Match: `^Strict-Transport-Security:.*$`, Regex: true, Comment: "Remove HSTS headers"},
		{Type: ResponseHeader, Match: `^Content-Security-Policy:.*$`, Regex: true, Comment: "Remove CSP headers"},
	}
}

func compileAll(rules []Rule) ([]compiled, error) {
	var out []compiled
	for _, r := range rules {
		c, err := compile(r)
		if err != nil {
			return nil, err
		}
		if r.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

// Rules returns a copy of all rules.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}

// Set validates and replaces the rules, saving them if the engine has a file.
func (e *Engine) Set(rules []Rule) error {
	if rules == nil {
		rules = []Rule{}
	}
	comp, err := compileAll(rules)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.path != "" {
		data, _ := json.MarshalIndent(rules, "", "  ")
		if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(e.path, data, 0o600); err != nil {
			return err
		}
	}
	e.rules, e.comp = rules, comp
	return nil
}

func (e *Engine) active(first, header, body string) (lines, bodies []compiled) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, c := range e.comp {
		switch c.Type {
		case first, header:
			lines = append(lines, c)
		case body:
			bodies = append(bodies, c)
		}
	}
	return lines, bodies
}

// OnRequest applies the request rules.
func (e *Engine) OnRequest(f *flow.Flow, req *http.Request) pipeline.Action {
	lines, bodies := e.active(RequestFirstLine, RequestHeader, RequestBody)
	if len(lines)+len(bodies) == 0 {
		return pipeline.Continue
	}
	head := rawhttp.RequestHead(req)
	var body []byte
	readBody := false
	if len(bodies) > 0 {
		b, whole, err := rawhttp.ReadBody(req, e.maxBody)
		if err == nil && whole {
			body, readBody = b, true
		}
	}
	newHead := applyHead(head, lines)
	newBody := body
	if readBody {
		newBody = applyBody(body, bodies)
	}
	if bytes.Equal(newHead, head) && bytes.Equal(newBody, body) {
		return pipeline.Continue
	}
	parsed, err := rawhttp.ParseRequest(append(bytes.Clone(newHead), newBody...))
	if err != nil {
		f.Note = "match and replace produced an invalid request; sent unchanged: " + err.Error()
		return pipeline.Continue
	}
	if !readBody { // only the head changed: keep streaming the original body
		parsed.Body, parsed.GetBody, parsed.ContentLength = req.Body, req.GetBody, req.ContentLength
		if v := req.Header.Get("Content-Length"); v != "" {
			parsed.Header.Set("Content-Length", v)
		}
	}
	f.KeepOriginalRequest(append(bytes.Clone(head), body...))
	rawhttp.ReplaceRequest(req, parsed)
	return pipeline.Continue
}

// OnResponse applies the response rules.
func (e *Engine) OnResponse(f *flow.Flow, resp *http.Response) pipeline.Action {
	lines, bodies := e.active(ResponseFirstLine, ResponseHeader, ResponseBody)
	if len(lines)+len(bodies) == 0 {
		return pipeline.Continue
	}
	head := rawhttp.ResponseHead(resp)
	var body []byte
	readBody := false
	if len(bodies) > 0 {
		b, whole, err := rawhttp.ReadResponseBody(resp, e.maxBody)
		if err == nil && whole {
			body, readBody = b, true
		}
	}
	newHead := applyHead(head, lines)
	newBody := body
	if readBody {
		newBody = applyBody(body, bodies)
	}
	if bytes.Equal(newHead, head) && bytes.Equal(newBody, body) {
		return pipeline.Continue
	}
	parsed, err := rawhttp.ParseResponse(append(bytes.Clone(newHead), newBody...))
	if err != nil {
		f.Note = "match and replace produced an invalid response; sent unchanged: " + err.Error()
		return pipeline.Continue
	}
	if !readBody {
		parsed.Body, parsed.ContentLength = resp.Body, resp.ContentLength
		parsed.Header.Del("Content-Length")
		if v := resp.Header.Get("Content-Length"); v != "" {
			parsed.Header.Set("Content-Length", v)
		}
	}
	f.KeepOriginalResponse(append(bytes.Clone(head), body...))
	rawhttp.ReplaceResponse(resp, parsed)
	return pipeline.Continue
}

// applyHead applies first-line and header rules to a rendered message head.
func applyHead(head []byte, rules []compiled) []byte {
	if len(rules) == 0 {
		return head
	}
	text := strings.TrimSuffix(string(head), "\r\n\r\n")
	lines := strings.Split(text, "\r\n")
	for _, r := range rules {
		if strings.HasSuffix(r.Type, "_first_line") {
			lines[0] = r.apply(lines[0])
			continue
		}
		if r.re == nil {
			lines = append(lines, r.Replace)
			continue
		}
		kept := lines[:1]
		for _, l := range lines[1:] {
			if r.re.MatchString(l) {
				l = r.apply(l)
			}
			if l != "" {
				kept = append(kept, l)
			}
		}
		lines = kept
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

func applyBody(body []byte, rules []compiled) []byte {
	s := string(body)
	for _, r := range rules {
		s = r.apply(s)
	}
	return []byte(s)
}
