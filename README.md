<img src="internal/ui/static/logo.svg" width="72" align="right" alt="">

# Loupe

Loupe is a lightweight, single-binary, cross-platform intercepting HTTP(S) proxy with a Burp-style web interface. It is written in Go with the standard library only and has no external dependencies.

## Usage

Double-click the binary or run it without arguments. The proxy (`127.0.0.1:8080`) and the web interface (`http://127.0.0.1:8081`) start together, and the interface opens in your default browser.

There are two ways to route traffic through it:

- **Open browser** starts Edge, Chrome or Brave with its own profile. All of that browser's traffic, including localhost, goes through the proxy. It also trusts Loupe's certificates, so HTTPS is decrypted without installing anything. Your normal browser is not touched.
- For any other application, set its HTTP proxy to `127.0.0.1:8080`. For example: `curl -x http://127.0.0.1:8080 http://example.com`.

```bash
loupe history -n 20         # list the last 20 flows
loupe history -id 12        # print the full request and response of flow 12
```

| Flag | Default | Description |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | Proxy listener address |
| `-ui` | `127.0.0.1:8081` | Web interface address. Leave it empty to disable the interface. |
| `-open` | on | Open the interface in the default browser on start |
| `-browser` | off | Also start the separate proxied browser on start |
| `-no-mitm` | off | Do not decrypt HTTPS; tunnel it instead |
| `-ca-dir` | user config dir/`loupe` | Directory holding the CA, keys, scope and match-and-replace rules |
| `-insecure-upstream` | off | Do not verify upstream certificates, for self-signed test servers |
| `-history` | `history.jsonl` | History file (one JSON flow per line) |
| `-max-body` | 10 MiB | Bytes of each body to record. Traffic is always forwarded in full. |
| `-quiet` | off | Do not print each flow |
| `-ai` | `auto` | AI backend for the assistant: `auto`, `claude`, `ollama` or `openai` |
| `-ai-model` | — | Model name for `ollama`/`openai`, e.g. `qwen2.5` or `qwen-plus` |
| `-ai-url` | — | Base URL (`ollama`: `http://localhost:11434`; `openai`: a `.../v1` base) |
| `-ai-key` | — | API key for an `openai`-compatible endpoint (or set `OPENAI_API_KEY` / `DASHSCOPE_API_KEY`) |

## Interface

The tabs follow Burp Suite's layout and names.

- **Target**
  - **Site map**: hosts and paths seen so far.
  - **Scope**: the hosts under test. `example.com` matches that host only; `*.example.com` matches it and all of its subdomains.
- **Proxy**
  - **Intercept**: hold requests and, optionally, responses. Edit them, then **Forward** (Ctrl+F) or **Drop** (Ctrl+D).
    - Only in-scope hosts are held; with an empty scope, everything is.
    - Static files and browser background services are not held.
  - **HTTP history**: sortable columns, a filter, the Pretty/Raw/Hex message editor and original/edited versions. Right-click an item to send it to Repeater (Ctrl+R), Intruder (Ctrl+I) or Decoder, change the scope, or copy it as a URL or curl command.
  - **WebSockets history**: messages of WebSocket connections that go through the proxy.
  - **Match and replace**: rules for request and response headers, bodies and first lines, as literal text or regex. They apply to proxy traffic, before Intercept.
  - **Proxy settings**: interception options and CA certificate export with installation instructions.
- **Intruder**
  - Attack types: Sniper, Battering ram, Pitchfork and Cluster bomb.
  - Positions are marked with `§…§`, using Add §, Clear § and Auto §.
  - Payload types: simple lists and number ranges, with optional URL-encoding.
  - Settings for concurrency and delay.
  - A results window with a sortable, filterable table.
- **Repeater**: numbered tabs. Edit a request, send it (Ctrl+Space) and step back and forth through what each tab has sent.
- **Decoder**: chained panels that decode, encode or hash.
  - Decode and encode: URL, HTML, Base64, hex and gzip, plus JWT decoding.
  - Hashes: MD5 and the SHA family.
  - **Smart decode** picks the decoding automatically.

- **AI assistant**: talk to an AI model about any request. It opens from the **Ask …** button in HTTP history, Repeater and Intercept, or from the right-click menu (Ctrl+J). The buttons and the top-bar **✦** tab show the active model's name.
  - The model sees the request and the decoded response. Quick prompts cover explaining the request, finding security issues, suggesting test requests and explaining the response.
  - Requests the model proposes come with **Send & show response** (sends the request through the proxy and feeds the real response back into the conversation, so you can iterate test-by-test with one click per request), **Repeater**, **Intruder** and **Copy** buttons. In Intercept, a proposed request also gets **Forward this instead**, which forwards the held message with the model's edit.
  - Each request has its own conversation. **☰ Chats** in the panel, or the **✦** tab in the top bar, lists them all, and they keep answering in the background while you open others.
  - The 60 most recent conversations are kept in this browser across reloads.
  - Messages are capped at 100 KB each before being sent; the cut is marked.

  The provider and model can be changed from the interface at any time: open the
  assistant and click **⚙ Model**. It lists the models on a running Ollama server
  and whether Claude Code is installed, and remembers the choice (in `ai.json` in
  the config directory). Any API key is stored on this machine only and is never
  sent back to the browser. The `-ai*` flags below just seed the first run.

  Pick the backend with `-ai`:
  - **`auto`** (default): uses the Claude Code CLI if it is installed, otherwise a running Ollama server.
  - **`claude`**: your installed Claude Code CLI (`claude`), run with every tool disabled, so no API key is needed and it cannot run anything on your machine.
  - **`ollama`**: a local [Ollama](https://ollama.com) server — open models such as Qwen or Llama, all on your machine. Pull one first (`ollama pull qwen2.5`), then run `loupe -ai ollama -ai-model qwen2.5`. With no `-ai-model`, auto mode prefers an installed Qwen model.
  - **`openai`**: any OpenAI-compatible chat endpoint — Qwen's cloud API (DashScope), LM Studio, vLLM, llama.cpp's server. For example, Qwen cloud: `loupe -ai openai -ai-url https://dashscope-intl.aliyuncs.com/compatible-mode/v1 -ai-model qwen-plus -ai-key $DASHSCOPE_API_KEY`.

The theme follows the system setting. The **Theme** button switches between light and dark.

## macOS

The macOS binaries are not signed by Apple, so Gatekeeper says it "could not verify" the file when it was downloaded. Allow it once, from Terminal in the folder that holds it:

```bash
xattr -d com.apple.quarantine loupe-darwin-arm64   # Apple Silicon; use loupe-darwin-amd64 on Intel
chmod +x loupe-darwin-arm64
./loupe-darwin-arm64
```

Alternatively, try to open it once, then use System Settings → Privacy & Security → **Open Anyway**.

## HTTPS

On first start a CA is created in the CA directory (`%APPDATA%\loupe` on Windows, `~/Library/Application Support/loupe` on macOS). A certificate for each site is signed on the fly.

- The browser started with **Open browser** needs no setup. All site certificates share one key, which that browser is told to trust with `--ignore-certificate-errors-spki-list`.
- For other applications, export the CA in **Proxy settings** and install it. Through the proxy it is also served at `http://loupe/cert`.
- On Windows, `curl` (Schannel) cannot check revocation for a local CA. Add `--ssl-no-revoke`.
- Clients that pin certificates refuse interception. They appear as "TLS rejected".
- Never share `ca-key.pem`.

Accept-Encoding is limited to gzip and deflate so responses can be shown decoded. The WebSocket compression extension is removed so messages can be read.

## Building

```bash
go test ./...
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/loupe-darwin-arm64 ./cmd/loupe
```

`GOOS`/`GOARCH` may be `windows/amd64`, `darwin/arm64`, `darwin/amd64` or `linux/amd64`.

## Layout

```
cmd/loupe           command line: run and history
internal/flow       one recorded exchange
internal/pipeline   ordered, removable hooks; a panicking hook is skipped
internal/history    JSONL history file and recent flows in memory
internal/proxy      listener, forwarding, CONNECT, TLS interception, WebSocket relay, Repeater sending
internal/rawhttp    HTTP message text <-> net/http, parsing of edited messages, gzip decoding
internal/intercept  queue that holds requests and responses for a decision
internal/rules      match and replace
internal/intruder   payload positions, attack types and attack runs
internal/websocket  frame relay and message store
internal/scope      scope patterns and the browser noise list
internal/ca         local CA and per-site certificates
internal/ui         embedded web interface, JSON API and live event stream
internal/launch     opening URLs and starting the proxied browser
internal/assist     AI assistant: Claude Code CLI, Ollama or an OpenAI-compatible endpoint
```

## Known limitations

- Clients are served HTTP/1.1 only; browsers fall back to it without problems.
- Recorded message heads are rebuilt by net/http, so header order and case may differ from the wire.
- An edited body is sent with LF line endings. Do not edit binary bodies as text.
- WebSocket messages can be viewed but not intercepted or edited.
- Intruder results and WebSocket messages are kept in memory only.
