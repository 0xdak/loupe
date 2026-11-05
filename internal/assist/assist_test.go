package assist

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestPrompt(t *testing.T) {
	p := prompt(Exchange{Target: "https://x.test", Request: "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n", Note: "history #3"},
		[]Message{{"user", "first?"}, {"assistant", "answer"}, {"user", "and now?"}})
	for _, want := range []string{"<target>https://x.test</target>", "GET / HTTP/1.1", "(none yet)", "<user>\nfirst?\n</user>", "<assistant>\nanswer\n</assistant>"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
	if !strings.HasSuffix(p, "and now?") {
		t.Error("the new question must come last")
	}
	if c := clip(strings.Repeat("a", MaxMessage+10)); !strings.HasSuffix(c, "[… 10 more bytes not included]") {
		t.Errorf("clip = …%q", c[len(c)-40:])
	}
}

// TestRealClaude talks to the installed CLI; it costs a request, so it only
// runs when LIGHTPROXY_TEST_CLAUDE is set.
func TestRealClaude(t *testing.T) {
	if os.Getenv("LIGHTPROXY_TEST_CLAUDE") == "" {
		t.Skip("set LIGHTPROXY_TEST_CLAUDE=1 to run")
	}
	a, err := Find()
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	err = a.Chat(context.Background(), Exchange{Request: "GET /admin?debug=true HTTP/1.1\r\nHost: shop.test\r\n\r\n"},
		[]Message{{"user", "Which query parameter does this request send? Answer with the parameter name only."}},
		func(s string) { got.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(got.String()), "debug") {
		t.Errorf("answer = %q", got.String())
	}
}
