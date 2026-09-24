# proxyscope

A local intercepting HTTP proxy with a web UI, in the spirit of Burp Suite, for **personal use in authorized web pentesting and network traffic reverse engineering**.

> **Use only against your own traffic or systems you have explicit authorization to test.**

You point your browser (or any HTTP client) at proxyscope as a manual HTTP proxy. It forwards every request to the real server, stores each request/response pair in a local SQLite database, and shows the history in a web UI at `http://127.0.0.1:8081`.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Plain HTTP proxy, SQLite history, web UI | **Implemented (this version)** |
| 2 | HTTPS via TLS MITM with a custom CA | Not started |
| 3 | Live intercept (pause/edit/forward) + Repeater | Not started |
| 4 | Match & replace rules | Not started |
| 5 | Generic TCP/UDP relay (separate module) | Not started |

### What works now (Phase 1)

- HTTP/1.1 forward proxy: keep-alive, `Content-Length` and chunked bodies (both directions), streaming responses are flushed as they arrive.
- Every exchange is stored in SQLite: method, full URL, request/response headers, request/response bodies, timestamp, status code, duration, and an error message when no response could be obtained.
- Web UI: history table (method, host, path, status, size, time), click a row for full request/response detail, near-real-time updates by polling every second, client-side filter, pause, clear history.
- The UI decodes `gzip`/`deflate` response bodies for display, and shows binary bodies as a hex dump. The stored body is always the raw bytes from the wire.
- Network errors never crash the proxy. Unreachable host, DNS failure, refused connection and timeouts are logged, stored, and returned to the client as a readable plain-text `502`/`504`.

### Known limitations (by design in Phase 1)

- **HTTPS is not supported.** A `CONNECT` request (what the browser sends for `https://` sites) gets a readable `501` and is recorded in the history as a `CONNECT` row so you can see what was attempted. Phase 2 adds MITM.
- **WebSocket / `Upgrade` requests** are answered with `501`.
- Exchanges are saved when the response has been fully relayed, so a long-running or streaming response only appears in the history once it finishes.
- Bodies larger than `-max-body` (default 10 MiB) are forwarded in full but only the first `-max-body` bytes are stored (the UI shows "TRUNCATED" and the real size).
- Header order and exact casing are not preserved (Go normalizes them); values are.
- No proxy authentication, no upstream proxy chaining, no HTTP/2.

## Requirements

- Go **1.25 or newer** (`go version`).
- Nothing else. SQLite is provided by [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite), a pure-Go driver, so **no CGO / C compiler is needed** on either OS.

## Install and run

Same on Windows and Linux; only the shell syntax differs.

**Linux (Arch)**

```bash
sudo pacman -S go          # if Go is not installed
go build -o proxyscope ./cmd/proxyscope
./proxyscope
```

**Windows (PowerShell)**

```powershell
go build -o proxyscope.exe ./cmd/proxyscope
.\proxyscope.exe
```

Or without building: `go run ./cmd/proxyscope`.

Stop it with `Ctrl+C` (graceful shutdown on both OSes).

### Configuration

Command-line flags (run `proxyscope -h` for the list):

| Flag | Default | Meaning |
|------|---------|---------|
| `-proxy-addr` | `127.0.0.1:8080` | Proxy listen address |
| `-ui-addr` | `127.0.0.1:8081` | Web UI listen address |
| `-db` | `proxyscope.db` | SQLite file (created if missing; relative to the working directory) |
| `-max-body` | `10485760` | Max bytes stored per request/response body |
| `-dial-timeout` | `10s` | Timeout connecting to the target server |
| `-header-timeout` | `60s` | Timeout waiting for the target's response headers |

Both listeners bind to **loopback only** by default, because captured traffic contains credentials and cookies. Binding to `0.0.0.0` (e.g. to proxy a phone on your LAN) is possible via the flags but exposes an unauthenticated proxy and UI to your network. Do that only on networks you trust.

## Using it

1. Start proxyscope.
2. Configure the client to use an **HTTP proxy** at `127.0.0.1:8080`:
   - **Firefox**: Settings → Network Settings → Manual proxy configuration → HTTP Proxy `127.0.0.1`, Port `8080`. Leave "Also use this proxy for HTTPS" **unchecked** (HTTPS is Phase 2). Firefox may skip the proxy for `localhost`/`127.0.0.1` by default ("No proxy for"); test with another host or a hostname that is not localhost.
   - **Chrome/Edge**: they use the OS proxy settings (Windows: Settings → Network → Proxy; Linux: system proxy settings or `--proxy-server="http=127.0.0.1:8080"`). They bypass the proxy for localhost by default.
   - **curl**: `curl -x http://127.0.0.1:8080 http://example.com/`
3. Open `http://127.0.0.1:8081` and browse `http://` sites (e.g. `http://example.com`).

Most of the web is HTTPS, so until Phase 2 you will mostly see plain-HTTP targets (lab apps, local dev servers, IoT devices, legacy sites) plus `CONNECT` rows for HTTPS attempts.

## Architecture

```
cmd/proxyscope/        main: parse flags, wire packages, run both servers, graceful shutdown
internal/
  model/               Exchange + Summary types shared by all packages (no internal deps)
  config/              Flag parsing into a Config struct
  proxy/               Proxy engine: forwarding, body capture, error mapping
    proxy.go             http.Handler, forward(), CONNECT rejection, error classification
    capture.go           size-capped io.Writer used to record bodies while streaming
    headers.go           hop-by-hop header handling, Upgrade detection
  store/               SQLite persistence (Save/List/Get/Clear), schema versioning
  ui/                  Web UI server + JSON API
    ui.go                routes, host/CSRF guard, detail view
    body.go              body rendering for the browser (gzip/deflate decode, hex dump)
    web/                 embedded static frontend (index.html, style.css, app.js)
```

Dependency direction: `cmd` → `proxy`, `store`, `ui`, `config`; `proxy` and `ui` depend only on `model` (and on small interfaces, `proxy.Sink` and `ui.Store`, that `store.Store` satisfies). `store` depends on `model`. Nothing depends on `cmd`.

### Request flow

1. The browser sends `GET http://host/path` (absolute-form) to the proxy.
2. `proxy.forward` builds an outbound request, strips hop-by-hop headers, and streams the body through a size-capped recorder.
3. It uses `http.Transport.RoundTrip` directly (no redirect following, no cookie jar, no compression handling, no env proxies), so redirects and encodings reach the client untouched.
4. The response is relayed to the client while being recorded; then one `model.Exchange` is handed to the `Sink` (`store.Save`).
5. The UI polls `GET /api/exchanges?after=<lastId>` and loads detail with `GET /api/exchanges/{id}`.

### UI API

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/exchanges?after=ID&limit=N` | Summaries in ascending id. `after=0` returns the latest `limit` (default 500, max 1000). |
| GET | `/api/exchanges/{id}` | Full detail: sorted headers and rendered bodies. |
| DELETE | `/api/exchanges` | Clears history. Requires header `X-Requested-With: proxyscope`. |

Security notes: when the UI is bound to loopback, requests whose `Host` is not a loopback name are rejected (DNS-rebinding defense), non-GET requests need the custom header above (CSRF defense), and the frontend renders all captured data with `textContent` only (no HTML injection from captured traffic).

### Database

SQLite file (`-db`), WAL mode, one table `exchanges`; headers are stored as JSON, bodies as BLOBs, timestamps/durations as integer nanoseconds. Schema version is kept in `PRAGMA user_version` (currently 1); add a migration step in `store.migrate` when changing it. Ids use `AUTOINCREMENT`, so they are never reused after "Clear history". You can inspect the file with any SQLite client (`sqlite3 proxyscope.db`).

## Windows vs Linux

There is currently **no OS-specific code**. Differences you may notice:

- Build output name (`proxyscope.exe` vs `proxyscope`) and shell syntax.
- Error text for network failures comes from the OS (e.g. Windows says "connectex: …refused", Linux says "connection refused", and it may be localized). The proxy therefore matches on Go error types, not on errno values.
- Windows Firewall may prompt the first time the listeners start; allow private-network access only if you need LAN access.

Any future OS-specific code must live in a clearly named file (`*_windows.go` / `*_linux.go`, build tags) and be listed here.

## Development

```bash
go vet ./...
go test ./...          # add -race where a C compiler is available
gofmt -l .             # must print nothing
```

Tests cover forwarding, chunked bodies in both directions, body truncation, connection-refused → 502, header timeout → 504, `CONNECT` rejection, the SQLite round trip, body rendering, and the UI guard. See `CLAUDE.md` for repo conventions (also intended for future Claude sessions).

## Roadmap (not implemented)

- **Phase 2**: TLS MITM with a locally generated custom CA (per-host leaf certs, `CONNECT` handling, CA export for browser import).
- **Phase 3**: live intercept queue (pause/edit/forward/drop) and a Repeater to resend edited requests.
- **Phase 4**: match & replace rules on requests/responses.
- **Phase 5**: generic TCP/UDP relay as a separate module in the same project.
