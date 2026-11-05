// Package flow defines the record of one exchange that passed through the proxy.
package flow

import "time"

// Target identifies the upstream endpoint of a flow.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
}

// Flow is one request/response exchange that passed through the proxy.
//
// Request and Response hold a reconstructed message head followed by the
// captured body. Bodies are captured up to the proxy's limit; traffic itself
// is always forwarded in full.
type Flow struct {
	ID       int64         `json:"id"`
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration"`
	Source   string        `json:"source"`
	Target   Target        `json:"target"`
	Method   string        `json:"method"`
	URL      string        `json:"url"`
	Status   int           `json:"status,omitempty"`
	Request  []byte        `json:"request,omitempty"`
	Response []byte        `json:"response,omitempty"`
	// Truncated reports that a body was larger than the capture limit.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
	Note      string `json:"note,omitempty"`
	// Edited reports that a person or a match-and-replace rule changed the
	// message. OriginalRequest and OriginalResponse then hold the message as
	// it arrived, when it was changed.
	Edited           bool   `json:"edited,omitempty"`
	OriginalRequest  []byte `json:"originalRequest,omitempty"`
	OriginalResponse []byte `json:"originalResponse,omitempty"`
}

// KeepOriginalRequest stores msg as the original request unless an earlier
// change already did, and marks the flow edited.
func (f *Flow) KeepOriginalRequest(msg []byte) {
	if f.OriginalRequest == nil {
		f.OriginalRequest = msg
	}
	f.Edited = true
}

// KeepOriginalResponse is KeepOriginalRequest for the response.
func (f *Flow) KeepOriginalResponse(msg []byte) {
	if f.OriginalResponse == nil {
		f.OriginalResponse = msg
	}
	f.Edited = true
}
