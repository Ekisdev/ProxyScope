# proxyscope

A local intercepting HTTP/HTTPS proxy with a web UI, in the spirit of Burp Suite, for **personal use in authorized web pentesting and network traffic reverse engineering**.

> **Use only against your own traffic or systems you have explicit authorization to test.**

You point your browser (or any HTTP client) at proxyscope as a manual HTTP proxy. It forwards every request to the real server, stores each request/response pair in a local SQLite database, and shows the history in a web UI at `http://127.0.0.1:8081`. For HTTPS it terminates TLS with certificates signed by a local CA that you install in your trust store, so encrypted traffic is decrypted, logged and displayed exactly like plain HTTP.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Plain HTTP proxy, SQLite history, web UI | **Implemented** |
| 2 | HTTPS via TLS MITM with a custom local CA | **Implemented** |
| 3 | Live intercept (pause/edit/forward/drop) + Repeater | **Implemented** |
| 4 | Match & replace rules | **Implemented (this version)** |
| 5 | Generic TCP/UDP relay (separate module) | Not started |

### What works now

- HTTP/1.1 forward proxy: keep-alive, `Content-Length` and chunked bodies (both directions), streaming responses are flushed as they arrive.
- **HTTPS interception**: `CONNECT` tunnels are terminated with an on-the-fly leaf certificate (correct SAN, signed by the local root CA, cached per host), a real TLS connection is opened to the upstream server, and the decrypted requests go through the same forwarding, storage and UI pipeline as plain HTTP. Stored URLs are `https://host[:port]/path`; the UI shows `https://` in the Host column of these rows.
- A root CA is generated on first run and can be exported (`-export-ca`) or downloaded from the UI (`/ca.crt`).
- Every exchange is stored in SQLite: method, full URL, request/response headers, request/response bodies, timestamp, status code, duration, and an error message when no response could be obtained.
- **Live intercept** (default off): hold every request after it is fully received and before it goes upstream, and/or hold every response before it goes to the client. Inspect and edit method, URL, headers, body (or status, headers, body for responses), then **Forward**, **Forward edited** or **Drop**. Works identically for HTTP and decrypted HTTPS, and many requests can be held at once. See [Live intercept](#live-intercept).
- **Repeater**: "Send to Repeater" on any history row opens an editable copy that you can tweak and re-send as often as you like; each result is stored in history marked as *replayed*. See [Repeater](#repeater).
- **Match & replace rules** (default: none configured): structured, declarative rules loaded from a YAML file automatically rewrite matching requests/responses (headers, body, status code) with no manual intervention, independently of whether live intercept is on. This is what makes automated, scripted traffic tampering possible (e.g. spoofing a license-check response for reverse engineering) without touching the target binary. See [Match & replace rules](#match--replace-rules).
- Web UI: four tabs (History, Intercept, Repeater, Rules); history table with click-for-detail, near-real-time updates by polling, client-side filter, "hide replayed", pause, clear history, CA download link.
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
- Intercept: bodies larger than `-max-body` and streaming responses (`text/event-stream`) are **not held**; they flow through untouched and the history row gets a note. Binary bodies can be held and forwarded/dropped and their headers edited, but not edited as text. Held bodies are buffered in memory (up to `-max-body` each). The intercept toggles and held items are in memory only: they reset when ProxyScope restarts. Scope/filter rules ("intercept only matching requests") do not exist yet; intercept applies to all requests. See [Live intercept](#live-intercept) and [Repeater](#repeater) for more details.
- Rules: like intercept, a rule whose condition or action touches the body **never fires** on a body larger than `-max-body` or a streaming (`text/event-stream`) response — it cannot see or usefully rewrite what it never buffered, so the message flows through untouched and the history row gets a note; header/status-only rules are unaffected by this limit. A rule cannot decompress a `gzip`/`deflate` body to match/replace its logical content: matching/replacement always operates on the raw wire bytes, so a compressed body needs a companion request-direction rule that strips/rewrites `Accept-Encoding` so the upstream sends it uncompressed in the first place (see the example below). Each rule has exactly one action (chain several rules for multiple effects). Conditions are AND-only; there is no OR/grouping yet. `scope.host` matches the hostname only (no port); `scope.path` matches the URL path only (no query string). Rules **do not run on Repeater sends** (the repeater bypasses the proxy listener and the intercept queue by design, and now the rule engine too). Reordering rules is done by editing the YAML array order (by hand, or via "Edit as raw YAML" in the UI); there is no drag-to-reorder list.

## Requirements

- Go **1.25 or newer** (`go version`).
- SQLite is provided by [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite), a pure-Go driver, so **no CGO / C compiler is needed** on either OS. TLS and certificates use Go's standard library.
- The match & replace rules file is parsed with [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) (pure Go, no CGO) — the standard library has no YAML support.

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
| `-intercept-timeout` | `60s` | Auto-forward a held (intercepted) request/response, unmodified, after this long. `0` = no timeout (wait until resolved or the client disconnects) |
| `-ca-dir` | see [CA location](#where-the-ca-lives) | Directory of the root CA (`ca.crt`, `ca.key`); generated if missing |
| `-export-ca` | *(unset)* | Write the public CA certificate (PEM) to this path and exit |
| `-insecure-upstream` | `false` | **Do not validate upstream servers' TLS certificates** |
| `-rules-file` | see [Match & replace rules](#match--replace-rules) | Match & replace rules file (YAML); a missing file means no rules, a malformed one refuses to start |

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
4. Open `http://127.0.0.1:8081` and browse. To pause and edit traffic, use the **Intercept** tab; to replay a request, use **Send to Repeater** on a history row; to have traffic rewritten automatically, use the **Rules** tab (all below).

## Live intercept

Open the **Intercept** tab. Two independent switches, both **off by default** so normal browsing is never disrupted until you turn them on (and off again after every restart):

- **Intercept requests**: every request is held *after it has been fully received from the client and before anything is sent upstream*.
- **Intercept responses**: every response is held *after it has been fully received from the upstream server and before anything is sent to the client*. You can use either switch alone, or both (a request is then held twice: once on the way out, once on the way back).

The same two pause points are used for plain HTTP and for decrypted HTTPS, because both go through the same forwarding code.

### The pending panel

Every held item appears in the list on the left with its type (REQ/RESP), method, URL (and status for responses) and an auto-forward countdown; the **Intercept** tab shows a red badge with the number of held items so you notice them from other tabs. Several items can be held at the same time (e.g. a page loading many resources): each one waits independently and you can resolve them in any order. Click one to open it:

- **Requests**: method, URL, headers (one `Name: value` per line, `Host` first) and body are editable. Changing the URL's host/scheme sends the request to a different server.
- **Responses**: status code (200-599), headers and body are editable. The request that produced the response is shown for context.
- **Forward** sends the original untouched. **Forward edited** sends your changes. **Drop** answers the client with a `403` plain-text page ("request/response dropped by ProxyScope intercept") instead of forwarding: a dropped request never reaches the server, a dropped response is discarded. If an edit is invalid (bad URL, malformed header line, status out of range) you get an error message and the item stays held.

When you edit, `Content-Length` is recalculated automatically and hop-by-hop headers are stripped. Bodies are shown and edited as text:

- Compressed (`gzip`/`deflate`) bodies are shown decoded. If you **don't** touch the body, the original compressed bytes are forwarded exactly. If you **do** edit it, your plain text is sent and the now-wrong `Content-Encoding` header is removed.
- Line endings are preserved: browsers hand textareas back with LF, so a body that used CRLF throughout (forms, multipart) is converted back to CRLF when you edit it.
- Binary bodies (not valid UTF-8, or too big to display) cannot be edited as text; they are forwarded unchanged, but headers/method/URL/status can still be edited.

The history stores what was **actually sent/delivered** (the edited version) and marks the row with an **E** flag; a note is added when something was not intercepted or was auto-forwarded. A dropped item is stored with status `403` and the error "dropped by intercept".

### How pause/resume works (concurrency)

There is no queue worker. The per-request goroutine that net/http already runs for each client request calls the intercept manager and blocks in a `select` on: the user's decision, the auto-forward timer, or the request context (the client disconnecting). So a held request blocks **only itself and its own client connection**, never other requests or the proxy. Ownership of a held item is decided under a mutex (whoever removes it from the queue owns it), so an item is resolved exactly once; resolving an already-resolved item gives a `409`. The UI learns about held items by polling `GET /api/intercept` every 500 ms (no WebSocket); the text you are typing lives in the page and is never overwritten by a poll.

Other behaviors:

- **Turning a switch off** immediately releases every item held at that pause point, forwarded unmodified (nothing is left hanging).
- **Client disconnects** while an item is held: it disappears from the list and the history row says so.
- **Shutdown** releases everything held so graceful shutdown never waits for you.
- **Not held** (flows through unchanged, with a note on the history row): a request or response whose body exceeds `-max-body` (it would have to be truncated to hold it), and streaming responses (`text/event-stream`). Holding requires buffering the whole body in memory, so the limit is `-max-body` per held item.

### Auto-forward timeout

A held item is **automatically forwarded, unmodified, after `-intercept-timeout` (default 60 seconds)** so a forgotten held request can never hang a client forever. The countdown is shown per item. The history row records "auto-forwarded unmodified after 1m0s (intercept timeout)".

Why 60 s: it is long enough to read and hand-edit a request, and short enough that it stays within the timeouts most HTTP clients and API gateways use (commonly 30-60 s); a client with a shorter timeout gives up first, which simply removes the item as described above. Raise it (e.g. `-intercept-timeout 5m`) for slow careful editing, or use `0` to wait until you act or the client disconnects (a forgotten item then holds its connection until then).

## Repeater

In **History**, click a row and press **Send to Repeater**. The Repeater tab opens an editable copy: method, URL, headers, and body. Press **Send** (or Ctrl+Enter) to send it as many times as you want; tweak the fields and send again. Each send appends a result to that tab's result list; click a result to see its full request/response (decoded/hex bodies like anywhere else). Several repeater tabs can be open at once. Tabs and the list of results are kept in the browser's `localStorage`, so a reload doesn't lose them; the results themselves are ordinary history entries. There is no version history of your edits: a tab holds the current editable request and the results sent from it.

How it sends: the repeater is a direct outbound call. It uses the same dialing, timeouts (`-dial-timeout`, `-header-timeout`), HTTP/1.1-only TLS client and upstream certificate validation (`-insecure-upstream`) as the proxy, because both use the shared `outbound` package, but it **does not go through the proxy listener and does not go through the intercept queue**. Redirects are not followed (you see the `3xx`). One send has an overall limit of 2 minutes including reading the response body. Bodies over `-max-body` are stored truncated (the real size is recorded).

Distinguishing replayed traffic: every repeater result is saved in SQLite with `source = 'repeater'` (live traffic has `source = 'proxy'`). In the History list those rows get an **R** flag and a tinted row with a purple edge; there is a **hide replayed** checkbox; and the detail view shows a "Replayed from the repeater" banner.

Details and limits:

- Body: text bodies are editable. If the original body was binary, or was truncated by `-max-body` when it was captured, it is shown read-only and **resent unchanged from the stored bytes** (a truncated body is resent truncated; the tab warns about it). If you leave a text body untouched the exact original bytes are used (e.g. compressed bodies stay compressed).
- `Content-Length` is recomputed; a `Host` header line, if present, is sent as the `Host` (handy for virtual hosts) while the URL decides where to connect. The stored headers of the replay show the real length.
- Network failures (refused, DNS, timeout, invalid upstream certificate) are results, not popups: the row is stored with status `ERR` and the error text.
- Security: the repeater can send requests to any address your machine can reach, including internal ones. The UI is loopback-only and protected by the Host/`X-Requested-With` checks below; keep it that way.

## Match & replace rules

Automated, scripted traffic tampering: a rule matches on structured conditions (host/path/method/direction, headers, body, status) and applies one action (rewrite a header, rewrite the body, change the status code) with no manual step. Unlike live intercept, rules run **whether or not the intercept toggles are on** — you can have rules running silently in the background, manual intercept for the requests you want to eyeball, or both together (see [Interaction with live intercept](#interaction-with-live-intercept) below). This is the feature for the crackme/reverse-engineering use case: point ProxyScope at a license/verification server, write one rule, and every check comes back "valid" automatically without touching the target binary.

### The rules file

Rules live in a single YAML file, loaded on startup and treated as the **single source of truth**: it is safe to commit to git, hand-edit, or share with a team, and every change made through the UI is written straight back to this same file (never only to SQLite).

- Default location: `<user config dir>/ekisde.dev/Proxy/rules.yaml` — same base directory as the CA (`%AppData%\ekisde.dev\Proxy\rules.yaml` on Windows, `~/.config/ekisde.dev/Proxy/rules.yaml` on Arch — see [Where the CA lives](#where-the-ca-lives)), but its own file, not inside the `ca/` directory.
- Override with `-rules-file /path/to/rules.yaml`.
- A **missing** file is not an error: ProxyScope starts with zero rules (a fresh install). A file that **exists but is malformed** (bad YAML, a regex that doesn't compile, an impossible condition, an action referencing a capture group its own pattern doesn't have, ...) makes ProxyScope **refuse to start**, with a specific, readable error naming the offending rule. The same validation runs on every save from the UI: an invalid save is rejected (`400` with the error message) and the previously active rules keep running untouched — a bad edit can never blank out a working rule set.

### Schema

```yaml
version: 1
rules:
  - id: unique-id              # required, unique; letters/digits/-/_/. only
    name: "Human label"        # optional, shown in the UI (defaults to id)
    enabled: true               # per-rule on/off toggle
    direction: request          # "request" or "response"
    scope:                      # all fields optional; empty = matches anything
      host: "example.com"       # exact hostname, or "*.example.com" for it + subdomains (no port)
      path: "/api/path"         # matched per path_match, against the URL path only (no query string)
      path_match: exact         # exact | prefix | regex (default: exact)
      method: POST               # exact HTTP method, case-insensitive
    conditions:                  # optional, AND-combined (no OR/grouping yet)
      - type: header             # header | body | status
        name: X-Example          # header condition only
        match: exact              # header: exact|contains|regex ; body: contains|regex
        value: "..."              # literal value, or a regex when match: regex
      - type: status              # response-direction rules only
        equals: 200
    action:                      # exactly one per rule; chain rules for more effects
      type: replace_header        # replace_header | add_header | remove_header |
                                   # replace_body | body_regex_replace | set_status
      name: X-Example             # header actions
      value: "..."                # replace_header / add_header
      body: "..."                 # replace_body: literal new full body
      pattern: "..."              # body_regex_replace: regex to find
      replacement: "$1"           # body_regex_replace: replacement, may use $1/${name} capture groups from pattern
      status: 200                 # set_status: response-direction rules only
```

### Example: crackme license-check bypass

```yaml
version: 1
rules:
  # Request direction: strip the client-side integrity header the app sends
  # on every call, so the server never even sees it was tampered with.
  - id: strip-integrity-header
    name: "Drop client integrity header"
    enabled: true
    direction: request
    scope:
      host: license.example.com
      path: /api/activate
      method: POST
    action:
      type: remove_header
      name: X-App-Integrity

  # Response direction: whatever the real server says, force the
  # verification result to "valid".
  - id: verify-bypass
    name: "Force verification response to valid"
    enabled: true
    direction: response
    scope:
      host: license.example.com
      path: /api/verify
    conditions:
      - type: status
        equals: 200
      - type: body
        match: regex
        value: '"valid"\s*:\s*false'
    action:
      type: replace_body
      body: '{"valid": true, "reason": "ok"}'
```

If the server compresses that response (`Content-Encoding: gzip`), add a third, request-direction rule that removes or rewrites `Accept-Encoding` so it is asked for uncompressed instead (rules match/replace raw wire bytes, not decompressed content — see [Known limitations](#known-limitations)).

### Evaluation order

**Array order in the YAML file is evaluation order.** Rules run top to bottom; every rule matching a given request/response applies in order, and each one sees the **result of the previous one's edits** (so a later rule's conditions can match text a previous action just introduced). A rule only ever runs at its own `direction`: a `request` rule never sees responses and vice versa. There is one such pass at each of the two pause points already used by live intercept (see [Architecture](#architecture)): once for the request, before it goes upstream, and once for the response, before it goes to the client.

### Interaction with live intercept

**Rules run first, then live intercept (if enabled) holds the already-rule-transformed message.** Concretely, at each pause point: rules are applied automatically and unconditionally (independent of the intercept toggles) → *then*, if the matching intercept toggle is on, the (possibly rule-modified) request/response is held for you to inspect/edit/forward/drop as usual. This means:

- Rules alone (intercept off): fully automated, no UI interaction needed — the point of this feature.
- Intercept alone (no rules configured): behaves exactly like Phase 3, unchanged.
- Both together: you see and can further edit what the rules already produced, not the original — so a human reviewing a held item always sees the final, post-automation state, and can override or refine what the rules did before it goes out.

Rules never run on **Repeater** sends: like live intercept, the repeater bypasses the proxy listener entirely by design.

### Performance

Every regex (in scopes, conditions, and `body_regex_replace` actions) is compiled exactly once — when the rules file is loaded, reloaded, or saved from the UI — never per request. A rule whose condition or action does not touch the body (header/status-only rules) never forces the request/response body to be buffered, so a ruleset with only header/status rules adds no memory or latency cost beyond evaluating a handful of string/regex comparisons per message.

### The Rules tab

Lists every rule (enabled toggle, direction, scope/condition/action summary); click one to edit it in a structured form matching the schema above (scope, AND-combined conditions, one action), or use **Edit as raw YAML** to edit/paste the whole file's text directly (useful for reordering rules or keeping hand-written comments — the structured form regenerates the file without them). **New rule** starts a blank one; **Save** validates before writing anything (see above); **Delete** removes a rule. **Reload from file** re-reads `rules.yaml` from disk, for when you hand-edit it outside the UI (a save from the UI itself takes effect immediately without needing this button).

When a rule fires on live traffic, the affected history row gets an **M** flag (next to R for replayed and E for edited) and the detail view shows a banner naming which rule(s) fired, in firing order — so after the fact it's obvious which traffic was auto-modified and by what.

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
cmd/proxyscope/        main: parse flags, load/create the CA, load rules, wire packages, run both servers, graceful shutdown
internal/
  model/               Shared types (Exchange, Summary, intercept Request/Response/Outcome/Pending,
                       match & replace Rule/Scope/Condition/Action...); no internal deps
  config/              Flag parsing into a Config struct (incl. default CA directory, default rules file)
  ca/                  Root CA generation/loading, leaf certificate issuing + cache, name validation, cert export
  outbound/            Talking to upstream servers, shared by proxy and repeater: transports, timeouts,
                       upstream TLS validation, request building, hop-by-hop stripping, body capture, error classification
  intercept/           Live intercept queue (Manager): pause points, held items, timeout, resolve/drop
  rules/               Match & replace engine (Engine): YAML load/validate/compile, scope + condition
                       matching, action application, atomic reload; see "Match & replace rules" above
  proxy/               Proxy engine
    proxy.go             http.Handler, forward() (used by HTTP and HTTPS; hosts both pause points:
                         rules always run first, then intercept if enabled)
    tunnel.go            CONNECT handling: hijack, TLS handshake with the client (SNI), per-tunnel HTTP server
    headers.go           Upgrade detection
  repeater/            Direct re-send of an edited request; stores the result as "replayed"; no rules, no intercept
  store/               SQLite persistence (Save/List/Get/Clear), schema versioning
  ui/                  Web UI server + JSON API
    ui.go                routes, host/CSRF guard, CA download, history detail view
    intercept.go         /api/intercept handlers (state, settings, item detail, forward/drop)
    repeater.go          repeater seed + send handlers
    rules.go             /api/rules handlers (structured save, raw YAML save, reload)
    edit.go              edit forms <-> model types: header text, body edit rules, validation
    body.go              body rendering for the browser (gzip/deflate decode, hex dump)
    web/                 embedded static frontend: index.html, style.css,
                         core.js (helpers, tabs, detail renderer), history.js, intercept.js, repeater.js, rules.js
```

Dependency direction: `cmd` → everything; `proxy`, `ui` and `repeater` depend on `model`, `outbound` (proxy, repeater) and on small interfaces they define themselves (`proxy.Sink`, `proxy.CertIssuer`, `proxy.Interceptor`, `proxy.RuleEngine`, `ui.Store`, `ui.Interceptor`, `ui.Repeater`, `ui.Rules`) that `store.Store`, `ca.Authority`, `intercept.Manager`, `repeater.Service` and `rules.Engine` satisfy. `store`, `ca`, `outbound`, `intercept` and `rules` are leaves (they depend at most on `model`). Nothing depends on `cmd`. All private-key handling is confined to the `ca` package. `proxy` and `repeater` never import each other, and the repeater never touches the proxy, the intercept queue, or the rule engine. The match & replace rule types (`Rule`, `Scope`, `Condition`, `Action`, ...) live in `model`, not in `rules`, so `ui` and `proxy` never need to import `internal/rules` directly — the same reason `Request`/`Response`/`Outcome` live in `model` for intercept.

### Request flow

**HTTP:** the client sends `GET http://host/path` to the proxy → `proxy.forward` builds an outbound request, strips hop-by-hop headers, streams the body through a size-capped recorder, relays the response while recording it → one `model.Exchange` goes to the `Sink` (`store.Save`).

**HTTPS:** `CONNECT` → `proxy.handleConnect` hijacks the connection → `serveTunnel` completes the TLS handshake using `ca.CertificateFor(sni-or-host)` → a per-tunnel `http.Server` reads the decrypted requests, rewrites them to absolute `https://` URLs and calls the **same** `forward`, with a per-tunnel transport that validates (or, with `-insecure-upstream`, skips validation of) the upstream certificate.

Both paths use `http.Transport.RoundTrip` directly (no redirect following, no cookie jar, no compression handling, no env proxies), so redirects and encodings reach the client untouched. The UI polls `GET /api/exchanges?after=<lastId>` and loads detail with `GET /api/exchanges/{id}`.

**Inside `forward` (Phase 3 + 4):** receive the request → *[pause point 1: if a rule needs the body or request intercept is on, read the whole body (≤ `-max-body`); apply every matching request-direction rule in file order; if request intercept is on, hold the (rule-transformed) request, apply edits or drop]* → build the outbound request (`outbound.BuildRequest`) → `RoundTrip` upstream → *[pause point 2: same thing for the response — rules first, then intercept if enabled]* → relay to the client (streamed normally when nothing needed the body) → save one `model.Exchange`, including which rule(s) fired. A rule that doesn't need the body (header/status-only) still runs even when nothing was buffered.

**Repeater:** UI → `POST /api/repeater/send` → validate the edit form → `repeater.Service.Send` → `outbound.BuildRequest` + shared transport → store the result with `source = repeater`. No listener, no intercept queue.

### UI API

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/exchanges?after=ID&limit=N` | Summaries in ascending id. `after=0` returns the latest `limit` (default 500, max 1000). |
| GET | `/api/exchanges/{id}` | Full detail: sorted headers and rendered bodies. |
| DELETE | `/api/exchanges` | Clears history. |
| GET | `/ca.crt` | Public root CA certificate (PEM download). Never the key. |
| GET | `/api/intercept` | Toggle state, auto-forward timeout, list of held items (polled every 500 ms). |
| PUT | `/api/intercept/settings` | Body `{"request":bool,"response":bool}`. Turning a side off releases its held items. |
| GET | `/api/intercept/{id}` | One held item with edit forms (`409` if no longer held). |
| POST | `/api/intercept/{id}/forward` | Empty/`{}` = forward as-is; `{"request":{method,url,headers,body}}` or `{"response":{status,headers,body}}` = forward edited. `400` on an invalid edit (item stays held), `409` if already resolved. |
| POST | `/api/intercept/{id}/drop` | Drop the item (client gets a `403`). |
| GET | `/api/exchanges/{id}/repeater` | Editable copy of a stored request for the repeater. |
| POST | `/api/repeater/send` | Body `{sourceId,method,url,headers,body}`; sends directly and returns the stored result in history-detail shape. |
| GET | `/api/rules` | `{path, rules, raw}`: the rules file's path, structured rules (file order), and raw YAML text. |
| PUT | `/api/rules` | Body `{rules:[...]}`; replaces the whole structured rule list. `400` with a readable error on an invalid rule (previous rules keep running); success returns the same shape as `GET`. |
| PUT | `/api/rules/raw` | Body `{yaml:"..."}`; replaces the file's raw text verbatim (preserves comments/formatting). Same validation/response as above. |
| POST | `/api/rules/reload` | Re-reads the rules file from disk (for hand-edits made outside the UI). Same validation/response as above. |

Every non-GET request must carry the header `X-Requested-With: proxyscope`.

Security notes: when the UI is bound to loopback, requests whose `Host` is not a loopback name are rejected (DNS-rebinding defense), non-GET requests need the custom header above (CSRF defense: a cross-site page cannot set it without a CORS preflight, which is never answered), and the frontend renders all captured data with `textContent` only (no HTML injection from captured traffic). Because the repeater and the edit forms can make the machine send arbitrary requests, keep the UI on loopback.

### Database

SQLite file (`-db`), WAL mode, one table `exchanges`; headers are stored as JSON, bodies as BLOBs, timestamps/durations as integer nanoseconds. Schema version is kept in `PRAGMA user_version` (currently **3**). HTTPS is distinguished by the `https://` URL prefix, and failed TLS handshakes are stored as `CONNECT` rows with status 0 and an `error`. **Phase 3 added schema v2** with four columns: `source` (`proxy` = live-captured, `repeater` = replayed), `req_edited` and `resp_edited` (modified in the intercept queue; the stored copy is what was actually sent/delivered), and `note` (non-error annotations such as auto-forwarded or not intercepted). **Phase 4 added schema v3** with two columns: `rule_fired` (cheap boolean for the history list's **M** flag) and `rules_applied` (JSON array of the rule ids that fired, in firing order, used by the detail view). An existing v1 or v2 database is migrated automatically on startup (each in its own transaction; old rows get `rule_fired = 0`, `rules_applied = '[]'`). **A database written by a newer schema version cannot be opened by an older ProxyScope** (it refuses a newer schema). Add a migration step in `store.migrate` when changing the schema. Ids use `AUTOINCREMENT`, so they are never reused after "Clear history". You can inspect the file with any SQLite client (`sqlite3 proxyscope.db`). The database contains decrypted traffic (credentials, cookies): protect and delete it accordingly.

Match & replace rules themselves are **not** stored in SQLite: the YAML file (see [Match & replace rules](#match--replace-rules)) is the single source of truth, on purpose, so it stays version-controllable and shareable. Only the *effect* of a rule firing on a given exchange (which rule id(s), in `rules_applied`) is recorded in the database.

## Windows vs Linux

There is currently **no OS-specific code**; everything goes through Go's cross-platform APIs. Differences you will notice:

- Build output name (`proxyscope.exe` vs `proxyscope`) and shell syntax.
- CA directory (`%AppData%\ekisde.dev\Proxy\ca` vs `~/.config/ekisde.dev/Proxy/ca`) and how the key file is protected (mode `0600` vs the user-profile ACL).
- Trust-store installation steps (documented above); nothing in the code touches OS trust stores, you install `ca.crt` yourself.
- Error text for network failures comes from the OS (e.g. Windows says "connectex: …refused", Linux "connection refused", possibly localized). The proxy therefore matches on Go error types, not on errno values.
- Windows Firewall may prompt the first time the listeners start; allow private-network access only if you need LAN access.

Any future OS-specific code must live in a clearly named file (`*_windows.go` / `*_linux.go`, build tags) and be listed here.

### Verification status per platform

| | Windows | Arch Linux |
|---|---|---|
| Builds, unit tests, end-to-end runs | Yes, on every phase | Phase 1 was build-tested; **Phases 2-4 have only been cross-compiled (`GOOS=linux`), not built, tested or run on Arch** |

Phase 4 deliberately adds nothing platform-specific: no syscalls, no file locking, no OS-specific paths; it uses the standard library plus the pure-Go `gopkg.in/yaml.v3` (no CGO, same as the SQLite driver). The rules file lives next to the CA directory using the same `os.UserConfigDir()` layout already used (and cross-compile-verified) since Phase 2, and rules are reloaded with a plain file write + rename, not a platform-specific file-watch API (see [Match & replace rules](#match--replace-rules) for why a UI button was chosen over file-watching). Even so, treat **Phase 4 on Arch as unverified**: on your first run there, do `go vet ./... && go test ./...` and then load a rule, confirm it fires on a real request, and edit it via both the structured form and raw YAML before relying on it. The same applies to Phases 2-3 (see above).

## Development

```bash
go vet ./...
go test ./...          # add -race where a C compiler is available
gofmt -l .             # must print nothing
```

Tests cover forwarding, chunked bodies in both directions, body truncation, connection-refused → 502, header timeout → 504, CA creation/reload/tamper detection, leaf issuing/verification/caching and name validation, full HTTPS interception (decrypt, record, keep-alive), upstream validation on/off, a client rejecting the fake certificate, a client vanishing mid-handshake, invalid SNI, CONNECT target parsing, the SQLite round trip and the v1 → v2 migration, body rendering, and the UI guard. Phase 3 adds tests for the intercept manager (edit, drop, timeout, client disconnect, releasing on toggle-off, 25 concurrent held requests resolved out of order), the pause points in the real proxy (request/response edit and drop over HTTP and HTTPS, editing the target host, oversized/streaming bodies not held, a held request not blocking others), the intercept and repeater APIs (including invalid edits leaving the item held), body edit rules (gzip, CRLF), and the repeater (replayed marking, no redirect following, error results, upstream validation flag, body cap). Phase 4 adds tests for the rules engine (validation errors including malformed regex/impossible conditions/bad capture-group references, scope matching including wildcard hosts and path prefix/regex, every condition and action type, multi-rule ordering where a later rule sees an earlier one's edit, a body-touching rule never firing without a buffered body, atomic reload where a bad file leaves the previous rules running), the pause points (a rule firing with intercept off, rules running before an enabled intercept hold sees the message, a header-only rule not forcing body buffering, the oversized-body skip note), the rules API (structured save, raw YAML save, reload, validation failures leaving the previous rules active), and the v2 → v3 migration. See `CLAUDE.md` for repo conventions (also intended for future Claude sessions).

## Roadmap (not implemented)

- **Phase 5**: generic TCP/UDP relay as a separate module in the same project.
