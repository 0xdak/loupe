// Package launch opens URLs and starts a Chromium-based browser that sends
// its traffic through the proxy, on Windows, macOS and Linux.
package launch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// OpenURL opens u in the user's default browser.
func OpenURL(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

// Browser starts Edge, Chrome, Chromium or Brave with its own profile and all
// traffic, including localhost, routed through proxyAddr. Using a separate
// profile keeps the user's normal browser and its settings untouched.
//
// When trustSPKI is set (a base64 SHA-256 public key hash), the browser accepts
// certificates with that key, so intercepted HTTPS works without installing
// the CA anywhere. Chromium only honours this together with --user-data-dir.
func Browser(proxyAddr, startURL, trustSPKI string) (*exec.Cmd, error) {
	bin := findBrowser()
	if bin == "" {
		return nil, errors.New("no Edge, Chrome, Chromium or Brave installation found")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	profile := filepath.Join(cache, "lightproxy", "browser-profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return nil, err
	}
	args := []string{
		"--proxy-server=http://" + proxyAddr,
		"--proxy-bypass-list=<-loopback>", // Chromium skips the proxy for localhost unless told otherwise
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		// Keep the browser's own background requests out of the history.
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--disable-sync",
		"--no-pings",
	}
	if trustSPKI != "" {
		args = append(args, "--ignore-certificate-errors-spki-list="+trustSPKI)
	}
	cmd := exec.Command(bin, append(args, startURL)...)
	return cmd, cmd.Start()
}

func findBrowser() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
			if root == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(root, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			)
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		}
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
			if p, err := exec.LookPath(name); err == nil {
				return p
			}
		}
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
