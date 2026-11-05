package scope

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestIncludes(t *testing.T) {
	s, _ := Load("")
	if !s.Includes("anything.test") {
		t.Error("an empty scope must include every host")
	}
	if err := s.Set([]string{"Example.COM", "*.api.test", "https://shop.test:8443/cart", ""}); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"example.com": true, "example.com:443": true, "www.example.com": false,
		"api.test": true, "v1.api.test": true, "evilapi.test": false,
		"shop.test:8443": true, "other.test": false,
	} {
		if got := s.Includes(host); got != want {
			t.Errorf("Includes(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestSetRejectsBadPatternsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"a/b", "*", "exa mple.com", "*.*.x"} {
		if err := s.Set([]string{bad}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if err := s.Set([]string{"a.test", "*.b.test", "a.test"}); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Patterns(); !slices.Equal(got, []string{"a.test", "*.b.test"}) {
		t.Errorf("reloaded patterns = %v", got)
	}
}

func TestNoise(t *testing.T) {
	if !Noise("nav.smartscreen.microsoft.com:443") || !Noise("assets.msn.com") {
		t.Error("browser services should be noise")
	}
	if Noise("example.com") || Noise("microsoft.com") {
		t.Error("ordinary sites must not be noise")
	}
}
