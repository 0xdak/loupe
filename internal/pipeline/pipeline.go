// Package pipeline runs ordered, removable hooks over proxied traffic.
package pipeline

import (
	"fmt"
	"net/http"
	"sync"

	"lightproxy/internal/flow"
)

// Action tells the proxy what to do with a message after a hook has seen it.
type Action int

const (
	// Continue passes the message on to the next hook and then onwards.
	Continue Action = iota
	// Drop stops the message; the client receives an error response.
	Drop
)

// RequestHook may inspect or modify a request before it is sent upstream.
// A hook that replaces the body must also set req.ContentLength.
type RequestHook interface {
	OnRequest(f *flow.Flow, req *http.Request) Action
}

// ResponseHook may inspect or modify a response before it reaches the client.
// A hook that replaces the body must keep the Content-Length header consistent.
type ResponseHook interface {
	OnResponse(f *flow.Flow, resp *http.Response) Action
}

// Chain holds hooks in registration order. The zero value is ready to use
// and it is safe for concurrent use.
type Chain struct {
	mu     sync.RWMutex
	lastID int
	hooks  []entry
}

type entry struct {
	id   int
	name string
	hook any
}

// Register appends a hook that implements RequestHook, ResponseHook or both.
// It returns a function that removes the hook again.
func (c *Chain) Register(name string, hook any) (unregister func()) {
	_, isReq := hook.(RequestHook)
	_, isResp := hook.(ResponseHook)
	if !isReq && !isResp {
		panic(fmt.Sprintf("pipeline: hook %q implements neither RequestHook nor ResponseHook", name))
	}
	c.mu.Lock()
	c.lastID++
	id := c.lastID
	c.hooks = append(c.hooks, entry{id: id, name: name, hook: hook})
	c.mu.Unlock()

	var once sync.Once
	return func() { once.Do(func() { c.remove(id) }) }
}

func (c *Chain) remove(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.hooks {
		if e.id == id {
			// Build a new slice so snapshots held by running chains stay intact.
			c.hooks = append(c.hooks[:i:i], c.hooks[i+1:]...)
			return
		}
	}
}

func (c *Chain) snapshot() []entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hooks
}

// RunRequest passes req through every request hook in order. A hook that
// panics is skipped and reported in errs; the remaining hooks still run.
func (c *Chain) RunRequest(f *flow.Flow, req *http.Request) (a Action, errs []error) {
	for _, e := range c.snapshot() {
		h, ok := e.hook.(RequestHook)
		if !ok {
			continue
		}
		act, err := callSafely(e.name, func() Action { return h.OnRequest(f, req) })
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if act == Drop {
			return Drop, errs
		}
	}
	return Continue, errs
}

// RunResponse passes resp through every response hook in order, with the
// same panic isolation as RunRequest.
func (c *Chain) RunResponse(f *flow.Flow, resp *http.Response) (a Action, errs []error) {
	for _, e := range c.snapshot() {
		h, ok := e.hook.(ResponseHook)
		if !ok {
			continue
		}
		act, err := callSafely(e.name, func() Action { return h.OnResponse(f, resp) })
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if act == Drop {
			return Drop, errs
		}
	}
	return Continue, errs
}

func callSafely(name string, fn func() Action) (a Action, err error) {
	defer func() {
		if r := recover(); r != nil {
			a, err = Continue, fmt.Errorf("hook %q panicked: %v", name, r)
		}
	}()
	return fn(), nil
}
