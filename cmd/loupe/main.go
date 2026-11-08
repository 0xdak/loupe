// Command loupe is a lightweight intercepting HTTP proxy.
//
// Run without arguments it starts the proxy and the web interface together
// and opens the interface in the default browser.
//
//	loupe [run] [-listen addr] [-ui addr] [-open] [-browser] [-history file] [-max-body n] [-quiet]
//	loupe history [-history file] [-n count] [-id flowID]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"loupe/internal/assist"
	"loupe/internal/ca"
	"loupe/internal/ext"
	"loupe/internal/flow"
	"loupe/internal/history"
	"loupe/internal/intercept"
	"loupe/internal/intruder"
	"loupe/internal/launch"
	"loupe/internal/pipeline"
	"loupe/internal/proxy"
	"loupe/internal/rules"
	"loupe/internal/scope"
	"loupe/internal/ui"
	"loupe/internal/websocket"
)

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && (args[0] == "run" || args[0] == "history") {
		cmd, args = args[0], args[1:]
	}
	if cmd == "history" {
		os.Exit(runHistory(args))
	}
	os.Exit(runProxy(args))
}

func runProxy(args []string) int {
	fs := flag.NewFlagSet("loupe", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to accept proxy connections on")
	histPath := fs.String("history", "history.jsonl", "file that captured traffic is appended to")
	maxBody := fs.Int64("max-body", proxy.DefaultMaxBody, "bytes of each body to record (traffic is always forwarded in full)")
	quiet := fs.Bool("quiet", false, "do not print each flow")
	uiAddr := fs.String("ui", "127.0.0.1:8081", "address of the web interface (empty disables it)")
	openUI := fs.Bool("open", true, "open the web interface in the default browser on start")
	browser := fs.Bool("browser", false, "also start a separate browser that is routed through the proxy")
	noMITM := fs.Bool("no-mitm", false, "tunnel HTTPS without decrypting it")
	caDir := fs.String("ca-dir", defaultCADir(), "directory holding the CA certificate and keys")
	insecure := fs.Bool("insecure-upstream", false, "do not verify upstream server certificates (for self-signed test servers)")
	aiProvider := fs.String("ai", "auto", "AI backend for the assistant: auto, claude, ollama or openai")
	aiModel := fs.String("ai-model", "", "AI model name for ollama/openai, e.g. qwen2.5 or qwen-plus")
	aiURL := fs.String("ai-url", "", "AI base URL (ollama: http://localhost:11434; openai-compatible: a .../v1 base)")
	aiKey := fs.String("ai-key", "", "API key for an openai-compatible endpoint (or set OPENAI_API_KEY / DASHSCOPE_API_KEY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	store, err := history.Open(*histPath, 1000)
	if err != nil {
		logger.Error("opening history", "path", *histPath, "err", err)
		return 1
	}
	defer store.Close()
	if !*quiet {
		store.Subscribe(flowPrinter(os.Stdout))
	}

	var authority *ca.Authority
	if !*noMITM {
		if authority, err = ca.LoadOrCreate(*caDir); err != nil {
			logger.Error("loading the CA", "dir", *caDir, "err", err)
			return 1
		}
	}

	sc, err := scope.Load(filepath.Join(*caDir, "scope.txt"))
	if err != nil {
		logger.Error("loading the scope", "err", err)
		return 1
	}
	// Only hold in-scope pages, never browser background services or
	// requests to the UI itself, which would then wait for its own answer.
	var uiHostPort string
	queue := intercept.New(func(r *http.Request) bool {
		return r.URL.Host != uiHostPort && !scope.Noise(r.URL.Host) && sc.Includes(r.URL.Host)
	}, *maxBody)

	engine, err := rules.Load(filepath.Join(*caDir, "rules.json"), *maxBody)
	if err != nil {
		logger.Error("loading match and replace rules", "err", err)
		return 1
	}

	hooks := &pipeline.Chain{}
	hooks.Register("match and replace", engine)
	hooks.Register("intercept", queue) // last, so it shows messages as they will be sent
	wsStore := websocket.NewStore(5000)
	p := proxy.New(hooks, store, proxy.Config{
		MaxBody: *maxBody, Logger: logger, CA: authority, InsecureUpstream: *insecure, WebSockets: wsStore,
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listening", "addr", *listen, "err", err)
		return 1
	}
	if host, _, _ := net.SplitHostPort(*listen); !isLoopback(host) {
		logger.Warn("listening on a non-loopback address: anyone who can reach it can use this proxy", "addr", ln.Addr())
	}

	proxyAddr := clientAddr(ln.Addr().(*net.TCPAddr))
	var spki string
	var caPEM []byte
	if authority != nil {
		spki, caPEM = authority.LeafSPKIHash(), authority.CertPEM()
	}
	startBrowser := func() error {
		_, err := launch.Browser(proxyAddr, "https://example.com/", spki)
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	servers := []*http.Server{{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: errLog}}
	listeners := []net.Listener{ln}

	// The assistant uses Claude Code, Ollama or an OpenAI-compatible endpoint.
	// The flags seed the first run; after that the provider and model can be
	// changed in the interface, and the choice is remembered in the config dir.
	aiMgr := assist.NewManager(
		assist.Config{Provider: *aiProvider, Model: *aiModel, URL: *aiURL, APIKey: *aiKey},
		filepath.Join(*caDir, "ai.json"),
	)

	// Extensions are third-party programs the tester installs under the config
	// directory and enables deliberately; none run until turned on in the UI.
	extMgr := ext.NewManager(filepath.Join(*caDir, "extensions"))
	defer extMgr.Close()

	var uiURL string
	if *uiAddr != "" {
		uiLn, err := net.Listen("tcp", *uiAddr)
		if err != nil {
			logger.Error("listening for the UI", "addr", *uiAddr, "err", err)
			ln.Close()
			return 1
		}
		uiHostPort = clientAddr(uiLn.Addr().(*net.TCPAddr))
		uiURL = "http://" + uiHostPort + "/"
		servers = append(servers, &http.Server{
			Handler: ui.New(store, ui.Options{
				ProxyAddr: proxyAddr, OpenBrowser: startBrowser, CACert: caPEM,
				Intercept: queue, Scope: sc, Sender: p, Rules: engine,
				Intruder: intruder.NewManager(p), WebSockets: wsStore,
				Assistant: aiMgr, AI: aiMgr, Extensions: extMgr,
			}),
			ReadHeaderTimeout: 30 * time.Second,
			ErrorLog:          errLog,
			// Live event streams end when the program is asked to stop.
			BaseContext: func(net.Listener) context.Context { return ctx },
		})
		listeners = append(listeners, uiLn)
	}

	fmt.Fprintf(os.Stderr, "loupe proxy:  %s\n", proxyAddr)
	if uiURL != "" {
		fmt.Fprintf(os.Stderr, "loupe UI:     %s\n", uiURL)
	}
	if authority != nil {
		fmt.Fprintf(os.Stderr, "HTTPS decryption:  on (CA in %s)\n", authority.Dir())
	} else {
		fmt.Fprintf(os.Stderr, "HTTPS decryption:  off\n")
	}
	fmt.Fprintf(os.Stderr, "history file:      %s\npress Ctrl+C to stop\n\n", *histPath)

	var wg sync.WaitGroup
	serveErr := make(chan error, len(servers))
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(listeners[i]); !errors.Is(err, http.ErrServerClosed) {
				serveErr <- err
			}
		}()
	}

	if uiURL != "" && *openUI {
		if err := launch.OpenURL(uiURL); err != nil {
			logger.Warn("could not open the UI; open it manually", "url", uiURL, "err", err)
		}
	}
	if *browser {
		if err := startBrowser(); err != nil {
			logger.Warn("could not start a browser", "err", err)
		}
	}

	code := 0
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		logger.Error("serving", "err", err)
		code = 1
	}
	queue.Configure(intercept.Settings{}) // release held messages so their handlers finish
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(sctx)
	}
	wg.Wait() // let in-flight handlers record their flows before the store closes
	return code
}

func defaultCADir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "loupe")
	}
	return "loupe-ca"
}

// clientAddr turns a listening address into one a local client can dial:
// a wildcard listener (0.0.0.0 or ::) is reached through loopback.
func clientAddr(a *net.TCPAddr) string {
	host := a.IP.String()
	if a.IP.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(a.Port))
}

func runHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	histPath := fs.String("history", "history.jsonl", "history file to read")
	n := fs.Int("n", 20, "number of most recent flows to list")
	id := fs.Int64("id", 0, "print the full request and response of this flow")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var found *flow.Flow
	var last []*flow.Flow
	skipped, err := history.Each(*histPath, func(f *flow.Flow) error {
		if *id != 0 {
			if f.ID == *id {
				found = f
			}
			return nil
		}
		last = append(last, f)
		if len(last) > *n {
			last = last[1:]
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading history:", err)
		return 1
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "warning: skipped %d unreadable line(s)\n", skipped)
	}

	if *id == 0 {
		print := flowPrinter(os.Stdout)
		for _, f := range last {
			print(f)
		}
		return 0
	}
	if found == nil {
		fmt.Fprintf(os.Stderr, "flow %d not found\n", *id)
		return 1
	}
	printFlowDetail(os.Stdout, found)
	return 0
}

func flowPrinter(w io.Writer) func(*flow.Flow) {
	var mu sync.Mutex
	return func(f *flow.Flow) {
		status := strconv.Itoa(f.Status)
		if f.Error != "" {
			status = "ERR"
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "#%-5d %-7s %-4s %8s  %s\n", f.ID, f.Method, status, f.Duration.Round(time.Millisecond), f.URL)
	}
}

func printFlowDetail(w io.Writer, f *flow.Flow) {
	fmt.Fprintf(w, "flow #%d  %s  %s  (%s)\n", f.ID, f.Start.Format(time.RFC3339), f.URL, f.Duration.Round(time.Millisecond))
	if f.Error != "" {
		fmt.Fprintf(w, "error: %s\n", f.Error)
	}
	if f.Note != "" {
		fmt.Fprintf(w, "note: %s\n", f.Note)
	}
	if f.Truncated {
		fmt.Fprintln(w, "note: body truncated to the capture limit")
	}
	fmt.Fprintf(w, "\n----- request -----\n%s\n----- response -----\n%s\n", f.Request, f.Response)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
