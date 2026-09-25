# proxyscope

A local intercepting HTTP/HTTPS proxy with a web UI, in the spirit of Burp Suite, for **personal use in authorized web pentesting and network traffic reverse engineering**.

> **Use only against your own traffic or systems you have explicit authorization to test.**

You point your browser (or any HTTP client) at proxyscope as a manual HTTP proxy. It forwards every request to the real server, stores each request/response pair in a local SQLite database, and shows the history in a web UI at `http://127.0.0.1:8081`. For HTTPS it terminates TLS with certificates signed by a local CA that you install in your trust store, so encrypted traffic is decrypted, logged and displayed exactly like plain HTTP.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Plain HTTP proxy, SQLite history, web UI | **Implemented** |
| 2 | HTTPS via TLS MITM with a custom local CA | **Implemented (this version)** |
| 3 | Live intercept (pause/edit/forward) + Repeater | Not started |
| 4 | Match & replace rules | Not started |
| 5 | Generic TCP/UDP relay (separate module) | Not started |

### What works now

- HTTP/1.1 forward proxy: keep-alive, `Content-Length` and chunked bodies (both directions), streaming responses are flushed as they arrive.
- **HTTPS interception**: `CONNECT` tunnels are terminated with an on-the-fly leaf certificate (correct SAN, signed by the local root CA, cached per host), a real TLS connection is opened to the upstream server, and the decrypted requests go through the same forwarding, storage and UI pipeline as plain HTTP. Stored URLs are `https://host[:port]/path`; the UI shows `https://` in the Host column of these rows.
- A root CA is generated on first run and can be exported (`-export-ca`) or downloaded from the UI (`/ca.crt`).
- Every exchange is stored in SQLite: method, full URL, request/response headers, request/response bodies, timestamp, status code, duration, and an error message when no response could be obtained.
- Web UI: history table, click a row for full request/response detail, near-real-time updates by polling every second, client-side filter, pause, clear history, CA download link.
- The UI decodes `gzip`/`deflate` response bodies for display and shows binary bodies as a hex dump. The stored body is always the raw bytes from the wire.
- Network and TLS errors never crash the proxy. Unreachable host, DNS failure, refused connection, timeouts and invalid upstream certificates are logged, stored, and returned to the client as a readable plain-text `502`/`504` (also inside TLS tunnels). A client that refuses the ProxyScope certificate produces a `CONNECT` row with an explanatory error and a log warning; nothing hangs.

### Known limitations

- **HTTP/1.1 only.** On intercepted TLS connections ProxyScope offers only `http/1.1` via ALPN, so browsers fall back from HTTP/2 automatically. A client that speaks *only* HTTP/2 (e.g. some gRPC clients) fails the handshake (recorded as a `CONNECT` error row).
- **WebSocket / `Upgrade`** (`ws://` and `wss://`) is answered with `501`.
- **Certificate pinning**: apps that pin their server certificate reject the ProxyScope certificate and cannot be intercepted. This is inherent to MITM and shows up as a failed-handshake `CONNECT` row.
- Exchanges are saved when the response has been fully relayed, so a long-running or streaming response only appears in the history once it finishes.
- Bodies larger than `-max-body` (default 10 MiB) are forwarded in full but only the first `-max-body` bytes are stored (the UI shows "TRUNCATED" and the real size).
- Header order and exact casing are not preserved (Go normalizes them); values are.
- Traffic that the browser never sends cannot be seen: built-in blockers such as Brave Shields can drop, upgrade or alter requests before they reach the proxy (see [Troubleshooting](#troubleshooting)).
- Successful `CONNECT` tunnels are not recorded as their own rows (only the decrypted requests inside them are). Failed tunnels are.
- No proxy authentication, no upstream proxy chaining, no client-certificate (mTLS) forwarding.

## Requirements

- Go **1.25 or newer** (`go version`).
- Nothing else. SQLite is provided by [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite), a pure-Go driver, so **no CGO / C compiler is needed** on either OS. TLS and certificates use Go's standard library.

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

Or without building: `go run ./cmd/proxyscope`. Stop it with `Ctrl+C` (graceful shutdown on both OSes).

On first run it generates the root CA (see below) and logs its path and SHA-256 fingerprint.

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
| `-ca-dir` | see [CA location](#where-the-ca-lives) | Directory of the root CA (`ca.crt`, `ca.key`); generated if missing |
| `-export-ca` | *(unset)* | Write the public CA certificate (PEM) to this path and exit |
| `-insecure-upstream` | `false` | **Do not validate upstream servers' TLS certificates** |

Both listeners bind to **loopback only** by default, because captured traffic contains credentials and cookies. Binding to `0.0.0.0` (e.g. to proxy a phone on your LAN) is possible via the flags but exposes an unauthenticated proxy and UI to your network. Do that only on networks you trust.

## HTTPS interception

### How it works

1. The client sends `CONNECT host:443` to the proxy. ProxyScope replies `200 Connection Established` and takes over the raw TCP connection.
2. It performs a TLS handshake **with the client**, choosing the certificate from the client's **SNI**: the leaf certificate is issued for the SNI name if the ClientHello has one, otherwise for the `CONNECT` host (this is also the case when connecting by IP address, which gets an IP SAN). If the SNI differs from the `CONNECT` host, a warning is logged and the certificate follows the SNI, because that is the name the client will validate.
3. The leaf certificate (ECDSA P-256, `subjectAltName` = DNS name or IP, `serverAuth`, valid one year, signed by the root CA) is generated on demand and **cached per name** (regenerated a day before expiry; the cache is bounded).
4. Decrypted HTTP/1.1 requests are handled by the same forwarding code as plain HTTP, sent over a **new TLS connection to the upstream** at the `CONNECT` host:port. The upstream is contacted with TLS server name = the leaf name (i.e. what the client asked for), so name mismatches between SNI and target are consistent on both legs.
5. Each request/response pair is stored like any other exchange, with the URL `https://host[:port]/path` (the `:443` default port is omitted).

Names that are not valid host names (empty, wildcards, whitespace/control characters, non-punycode IDNs, over-long labels) are refused: the handshake fails, the client gets a TLS alert, and a `CONNECT` row with the error is recorded.

### Upstream certificate validation

**On by default.** ProxyScope verifies the real server's certificate against the system trust store. If it is expired, self-signed, for the wrong host, or from an unknown CA, the client receives a readable `502` through the tunnel explaining why (and the exchange is recorded with that error). Rationale: for a pentesting tool, silently accepting bad upstream certificates would hide real problems and would make the proxy an easy way to attack your own connections.

Pass **`-insecure-upstream`** to accept any upstream certificate, which is the practical choice for lab targets with self-signed certificates. It logs a warning at startup. There is no per-host setting yet.

### Where the CA lives

The root CA is created on first run in:

| OS | Directory |
|----|-----------|
| Windows | `%AppData%\ekisde.dev\Proxy\ca\` = `C:\Users\<you>\AppData\Roaming\ekisde.dev\Proxy\ca\` |
| Linux (Arch) | `$XDG_CONFIG_HOME/ekisde.dev/Proxy/ca/`, normally `~/.config/ekisde.dev/Proxy/ca/` |

Both come from Go's `os.UserConfigDir()`, so the layout is `<user config dir>/ekisde.dev/Proxy/ca/`. Override with `-ca-dir`. Files:

- `ca.crt`: public root certificate (PEM). This is what you install in trust stores. Safe to share.
- `ca.key`: the CA **private key** (PKCS#8 PEM). Never logged, never shown in the UI, never served over HTTP; only `ca.crt` is exposed. Created with mode `0600` on Linux; on Windows it inherits the private ACL of your user profile. Note that `%AppData%\Roaming` can be synchronized in domain roaming-profile setups; use `-ca-dir` with a local path if that matters to you.

The CA is ECDSA P-256, valid 10 years, name `ProxyScope Local CA`, restricted to signing leaf certificates (`pathLen=0`). If only one of the two files exists, or they do not match, or the CA has expired, ProxyScope refuses to start with an explanatory error instead of overwriting anything. To rotate the CA, delete both files (and remove the old certificate from your trust stores) and restart.

> **Security:** anyone who has `ca.key` can impersonate *any* website to every machine/browser that trusts this CA. Keep the directory private, never commit it, and **remove the CA from your trust stores when you are done testing**.

### Getting `ca.crt`

- It already exists at the path above after the first run.
- Copy/export it: `proxyscope -export-ca ./proxyscope-ca.crt` (creates the CA first if needed; prints the SHA-256 fingerprint; never exports the key).
- Download it from the UI: `http://127.0.0.1:8081/ca.crt` (link "CA certificate" in the header).

Compare the fingerprint shown in the OS/browser dialog with the one printed by ProxyScope at startup or by `-export-ca`.

### Installing the CA

Until the CA is trusted, browsers refuse the ProxyScope certificates ("your connection is not private" / `SEC_ERROR_UNKNOWN_ISSUER`); this is expected. Restart the browser after installing.

Which trust store does each browser use?

| Browser | Windows | Arch Linux |
|---------|---------|------------|
| **Brave**, Chrome, Edge, Chromium | Windows certificate store (install once, see below) | **NSS database in your profile** (`~/.pki/nssdb`), *not* the `trust anchor` system store |
| Firefox | Its own store (separate import) | Its own store (separate import) |
| curl, wget, Python, Go programs | Windows store (curl's own build may differ) | System store (`trust anchor`) |

**Brave** is Chromium-based and behaves exactly like Chrome here: on **Windows** the OS-level install below is all it needs (no Firefox-style import, no Brave-specific step). On **Arch Linux** the system-level `trust anchor` install is *not* enough for Brave, because Chromium-based browsers read the NSS database: use the "Chrome / Chromium / Brave on Linux" steps below. Brave does **not** need the Firefox instructions.

**Windows** (Brave, Chrome, Edge and other apps that use the Windows store)

GUI: double-click `ca.crt` → *Install Certificate…* → *Current User* → *Place all certificates in the following store* → *Browse…* → **Trusted Root Certification Authorities** → *Finish* → confirm the security warning.

PowerShell (current user; Windows still shows a confirmation dialog):

```powershell
certutil -user -addstore Root "$env:APPDATA\ekisde.dev\Proxy\ca\ca.crt"
```

Machine-wide (elevated PowerShell): `certutil -addstore Root "<path>\ca.crt"`. Remove later with `certutil -user -delstore Root "ProxyScope Local CA"` (or `certmgr.msc` → Trusted Root Certification Authorities → Certificates).

**Arch Linux, system trust store** (curl, wget, Python `requests`, Go programs, and anything using the p11-kit/OpenSSL system bundle)

```bash
sudo trust anchor --store ~/.config/ekisde.dev/Proxy/ca/ca.crt
```

Remove later: `sudo trust anchor --remove ~/.config/ekisde.dev/Proxy/ca/ca.crt`. (Equivalent manual way: copy it to `/etc/ca-certificates/trust-source/anchors/proxyscope.crt` and run `sudo update-ca-trust`.)

**Chrome / Chromium / Brave on Linux** do *not* use the system store; they use the NSS database in your profile. Either use the browser UI (Brave: `brave://settings/certificates`; Chrome: *Settings → Privacy and security → Security → Manage certificates* → **Authorities** → **Import**, tick "Trust this certificate for identifying websites") or, with the `nss` package (`sudo pacman -S nss`):

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "ProxyScope Local CA" -i ~/.config/ekisde.dev/Proxy/ca/ca.crt
```

Remove: `certutil -d sql:$HOME/.pki/nssdb -D -n "ProxyScope Local CA"`.

Brave installed as a Flatpak/Snap keeps its profile elsewhere, so `~/.pki/nssdb` may not apply; use the browser's own certificate manager in that case.

**Firefox (Windows and Linux)** has its own certificate store and ignores the OS store by default, so it needs a separate import (kept here for when it's needed; **Brave does not need these steps**):

1. Open *Settings → Privacy & Security*, scroll to **Certificates**, click **View Certificates…**.
2. Tab **Authorities** → **Import…** → select `ca.crt`.
3. Tick **Trust this CA to identify websites** → OK.

Alternative: in `about:config` set `security.enterprise_roots.enabled` to `true` so Firefox also trusts the OS store (works well on Windows; on Linux it relies on the system trust store being readable by Firefox). On Linux you can also import into a specific profile with `certutil -d sql:<profile dir> -A -t "C,," -n "ProxyScope Local CA" -i ca.crt` (profile dirs live under `~/.mozilla/firefox/` or `~/.config/mozilla/firefox/`).

> The author verified the ProxyScope side of this end-to-end on Windows using `curl --cacert`; the trust-store commands above follow the standard tooling of each OS/browser but were not executed against real Arch/Firefox/Chrome/Brave installs, so double-check them on first use.

**Quick check without touching any trust store** (curl on either OS):

```bash
curl --cacert ~/.config/ekisde.dev/Proxy/ca/ca.crt -x http://127.0.0.1:8080 https://example.com/
```

## Using it

1. Start proxyscope.
2. Configure the client to use an **HTTP proxy** at `127.0.0.1:8080` **for both HTTP and HTTPS**:
   - **Firefox**: Settings → Network Settings → Manual proxy configuration → HTTP Proxy `127.0.0.1`, Port `8080`, and tick **Also use this proxy for HTTPS**. Firefox may skip the proxy for `localhost`/`127.0.0.1` by default ("No proxy for"); test with another host.
   - **Brave/Chrome/Edge**: they use the OS proxy settings (Windows: Settings → Network → Proxy; Linux: system proxy settings or `--proxy-server="127.0.0.1:8080"`). They bypass the proxy for localhost by default. Brave's Tor private windows use Tor instead and do not go through your proxy.
   - **curl**: `curl -x http://127.0.0.1:8080 http://example.com/` (add `--cacert` for HTTPS as above).
3. Install the CA (previous section) for HTTPS.
4. Open `http://127.0.0.1:8081` and browse.

## Troubleshooting

### Requests are missing, or responses look different, in Brave (Shields)

Brave's **Shields** work *inside the browser*, before a request is ever sent to the proxy. So ProxyScope can only see what Brave decides to send, and this can look like a MITM bug when it is not one. Typical symptoms while debugging:

- **Missing requests**: tracker, ad and (optionally) script/cookie blocking cancel requests in the browser; they never reach ProxyScope, so there is nothing to record.
- **Unexpected redirects / different scheme**: Brave's HTTPS upgrading can turn an `http://` navigation into `https://` before the request leaves the browser. You then see an HTTPS request (or a `CONNECT`) and never the plain HTTP one you expected to test.
- **Altered requests or responses**: Shields features such as stripping tracking parameters from URLs, redirect "debouncing", fingerprinting protection and cookie blocking can change the URL, headers or cookies compared with what the page would normally send, or change what the page loads.

How to rule it out: for the specific site under test, click the Brave (lion) icon in the address bar and turn **Shields off** for that site (or lower the Shields level for it), then reload and check whether the missing or different traffic appears. Re-enable Shields afterwards. If ProxyScope shows the traffic with Shields off, the proxy was fine. If a request is missing even then, look at the other usual suspects: the client is not using the proxy (localhost bypass, Tor window, per-app proxy settings), certificate pinning, or a failed-handshake `CONNECT` row in the history.

The same logic applies to other browsers' built-in blockers and to extensions (ad blockers, privacy tools): anything that acts before the network request is invisible to a network proxy.

## Architecture

```
cmd/proxyscope/        main: parse flags, load/create the CA, wire packages, run both servers, graceful shutdown
internal/
  model/               Exchange + Summary types shared by all packages (no internal deps)
  config/              Flag parsing into a Config struct (incl. default CA directory)
  ca/                  Root CA generation/loading, leaf certificate issuing + cache, name validation, cert export
  proxy/               Proxy engine
    proxy.go             http.Handler, forward() (used by HTTP and HTTPS), error classification, transports
    tunnel.go            CONNECT handling: hijack, TLS handshake with the client (SNI), per-tunnel HTTP server
    capture.go           size-capped io.Writer used to record bodies while streaming
    headers.go           hop-by-hop header handling, Upgrade detection
  store/               SQLite persistence (Save/List/Get/Clear), schema versioning
  ui/                  Web UI server + JSON API
    ui.go                routes, host/CSRF guard, CA download, detail view
    body.go              body rendering for the browser (gzip/deflate decode, hex dump)
    web/                 embedded static frontend (index.html, style.css, app.js)
```

Dependency direction: `cmd` → `proxy`, `store`, `ui`, `config`, `ca`; `proxy` and `ui` depend only on `model` and on small interfaces they define themselves (`proxy.Sink`, `proxy.CertIssuer`, `ui.Store`) that `store.Store` / `ca.Authority` satisfy. `store` and `ca` are leaves (`store` → `model`). Nothing depends on `cmd`. All private-key handling is confined to the `ca` package.

### Request flow

**HTTP:** the client sends `GET http://host/path` to the proxy → `proxy.forward` builds an outbound request, strips hop-by-hop headers, streams the body through a size-capped recorder, relays the response while recording it → one `model.Exchange` goes to the `Sink` (`store.Save`).

**HTTPS:** `CONNECT` → `proxy.handleConnect` hijacks the connection → `serveTunnel` completes the TLS handshake using `ca.CertificateFor(sni-or-host)` → a per-tunnel `http.Server` reads the decrypted requests, rewrites them to absolute `https://` URLs and calls the **same** `forward`, with a per-tunnel transport that validates (or, with `-insecure-upstream`, skips validation of) the upstream certificate.

Both paths use `http.Transport.RoundTrip` directly (no redirect following, no cookie jar, no compression handling, no env proxies), so redirects and encodings reach the client untouched. The UI polls `GET /api/exchanges?after=<lastId>` and loads detail with `GET /api/exchanges/{id}`.

### UI API

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/exchanges?after=ID&limit=N` | Summaries in ascending id. `after=0` returns the latest `limit` (default 500, max 1000). |
| GET | `/api/exchanges/{id}` | Full detail: sorted headers and rendered bodies. |
| DELETE | `/api/exchanges` | Clears history. Requires header `X-Requested-With: proxyscope`. |
| GET | `/ca.crt` | Public root CA certificate (PEM download). Never the key. |

Security notes: when the UI is bound to loopback, requests whose `Host` is not a loopback name are rejected (DNS-rebinding defense), non-GET requests need the custom header above (CSRF defense), and the frontend renders all captured data with `textContent` only (no HTML injection from captured traffic).

### Database

SQLite file (`-db`), WAL mode, one table `exchanges`; headers are stored as JSON, bodies as BLOBs, timestamps/durations as integer nanoseconds. Schema version is kept in `PRAGMA user_version` (currently 1; **unchanged in Phase 2**: HTTPS is distinguished by the `https://` URL prefix, and failed TLS handshakes are stored as `CONNECT` rows with status 0 and an `error`). Add a migration step in `store.migrate` when changing the schema. Ids use `AUTOINCREMENT`, so they are never reused after "Clear history". You can inspect the file with any SQLite client (`sqlite3 proxyscope.db`). The database contains decrypted traffic (credentials, cookies): protect and delete it accordingly.

## Windows vs Linux

There is currently **no OS-specific code**; everything goes through Go's cross-platform APIs. Differences you will notice:

- Build output name (`proxyscope.exe` vs `proxyscope`) and shell syntax.
- CA directory (`%AppData%\ekisde.dev\Proxy\ca` vs `~/.config/ekisde.dev/Proxy/ca`) and how the key file is protected (mode `0600` vs the user-profile ACL).
- Trust-store installation steps (documented above); nothing in the code touches OS trust stores, you install `ca.crt` yourself.
- Error text for network failures comes from the OS (e.g. Windows says "connectex: …refused", Linux "connection refused", possibly localized). The proxy therefore matches on Go error types, not on errno values.
- Windows Firewall may prompt the first time the listeners start; allow private-network access only if you need LAN access.

Any future OS-specific code must live in a clearly named file (`*_windows.go` / `*_linux.go`, build tags) and be listed here.

## Development

```bash
go vet ./...
go test ./...          # add -race where a C compiler is available
gofmt -l .             # must print nothing
```

Tests cover forwarding, chunked bodies in both directions, body truncation, connection-refused → 502, header timeout → 504, CA creation/reload/tamper detection, leaf issuing/verification/caching and name validation, full HTTPS interception (decrypt, record, keep-alive), upstream validation on/off, a client rejecting the fake certificate, a client vanishing mid-handshake, invalid SNI, CONNECT target parsing, the SQLite round trip, body rendering, and the UI guard. See `CLAUDE.md` for repo conventions (also intended for future Claude sessions).

## Roadmap (not implemented)

- **Phase 3**: live intercept queue (pause/edit/forward/drop) and a Repeater to resend edited requests.
- **Phase 4**: match & replace rules on requests/responses.
- **Phase 5**: generic TCP/UDP relay as a separate module in the same project.
