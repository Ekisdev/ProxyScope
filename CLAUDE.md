# CLAUDE.md — instructions for Claude working on proxyscope

proxyscope is a local intercepting HTTP proxy (Burp-Suite-like) written in Go, with SQLite storage and a small web UI. See `README.md` for what it is and how it is laid out.

## Mandatory rule: keep README.md up to date

**Any change to the project — new functionality, refactor, relevant fix, new dependency, new flag, new package, changed behavior, important design decision — MUST update `README.md` in the same work turn (and in the same commit if the repo is under git).** Never leave a README update as a pending follow-up. Concretely, update whichever apply: the Status table / "What works now", Known limitations, Configuration (flags), Architecture (package list, dependency direction, request flow), UI API, Database notes, Windows vs Linux section, Requirements, Development, Roadmap. If a change genuinely needs no README edit, say so explicitly in your final message. Also update this file if a convention below changes.

## Intended use

Only for the owner's own traffic or systems with **explicit authorization** to test. Do not add features aimed at unauthorized targets, and keep defaults conservative (loopback binding, no exposure of captured data).

## Phased project — do not work ahead

- **Phase 1 (done)**: plain HTTP proxy, SQLite history, web UI.
- **Phase 2 (done)**: TLS MITM with a custom local CA (`internal/ca`, `proxy/tunnel.go`).
- **Phase 3 (done)**: live intercept (`internal/intercept`, pause points in `proxy.forward`) + Repeater (`internal/repeater`), on the shared `internal/outbound`.
- **Phase 4 (done)**: match & replace rules (`internal/rules`, YAML-loaded, same pause points in `proxy.forward`, before the intercept hold).
- **Phase 5**: generic TCP/UDP relay, as a **separate module** in the same project.

Do **not** implement future-phase functionality unless explicitly asked, even if it looks easy. It is fine (and encouraged) to keep seams for them, e.g. the `proxy.Sink` interface, the schema version in `PRAGMA user_version`. When a phase is implemented, update the README Status table.

## Cross-platform (Windows + Linux/Arch)

The project must build and run on both. Use Go's standard cross-platform APIs (`filepath`, `os/signal` with `os.Interrupt` + `syscall.SIGTERM`, etc.). No CGO (that is why the SQLite driver is `modernc.org/sqlite`). Don't match on errno values (`syscall.ECONNREFUSED` differs on Windows); classify network errors by Go type (`net.OpError`, `net.DNSError`, `net.Error.Timeout()`). If OS-specific code is unavoidable, isolate it in `*_windows.go` / `*_linux.go` files (or build tags), keep it minimal, and document it in the README "Windows vs Linux" section. Currently there is none. Test on Windows when possible; write path handling and shell examples for both OSes in docs.

**Verification status:** Windows is built, tested and run on every phase; Arch Linux was build-tested for Phase 1 only, and Phases 2-4 are only cross-compiled (`GOOS=linux go build`). Don't add platform-specific behavior (syscalls, file locking, path assumptions) without flagging it in the README as unverified on Arch, and keep the README "Verification status per platform" table current.

## Code conventions (decided in Phases 1-4)

**Layout**
- Module name and binary: `proxyscope`. Entry point `cmd/proxyscope/main.go` only wires things together; no logic there beyond flag → construct → run → shut down.
- All code under `internal/`. One package per concern: `model` (shared types, no internal deps), `config`, `ca` (root CA + leaf certs), `outbound` (talking to upstreams: transports, timeouts, TLS validation, request building, capture, error classification), `intercept` (hold queue), `rules` (match & replace engine), `proxy`, `repeater`, `store`, `ui`. New concerns (relay) get their own package; don't grow `proxy` into a catch-all.
- Dependency direction: `cmd` → everything; `proxy`/`ui`/`repeater` → `model` (+ `outbound` for `proxy` and `repeater`), plus small interfaces they define themselves (`proxy.Sink`, `proxy.CertIssuer`, `proxy.Interceptor`, `proxy.RuleEngine`, `ui.Store`, `ui.Interceptor`, `ui.Repeater`, `ui.Rules`) which `store.Store`, `ca.Authority`, `intercept.Manager`, `repeater.Service` and `rules.Engine` satisfy. `store`, `ca`, `outbound`, `intercept` and `rules` are leaves (at most → `model`). Types that cross these interfaces (e.g. `model.Request`, `model.Outcome`, `model.ErrInvalidRequest`, `model.Rule`/`Scope`/`Condition`/`Action`) live in `model`, so `ui` and `proxy` never import `intercept`/`repeater`/`rules`; `proxy` and `repeater` never import each other. No cycles, no package importing `cmd`. Define interfaces where they are consumed. (Tests may import `ca` to get a real issuer, and `rules`/`intercept` to get a real engine/manager.)
- Frontend is plain HTML/CSS/JS embedded with `go:embed` in `internal/ui/web`. No build step, no npm, no external CDN. One file per view (`history.js`, `intercept.js`, `repeater.js`, `rules.js`) on top of `core.js` (shared `window.PS` helpers, tabs, detail renderer). Live updates are polling (history 1s, intercept 500ms), not WebSocket; `rules.js` fetches once per tab entry instead of polling (rules don't change from live traffic, only from explicit user action).
- Anything that lives only in the browser (repeater tabs in `localStorage`) is optional: wrap storage access in try/catch and work without it.

**Naming / style**
- Standard Go: `gofmt` clean (`gofmt -l .` prints nothing), `go vet ./...` clean. Exported identifiers have doc comments; each package has a package comment.
- Constructors are `New(...)`; servers expose `ListenAndServe() error` (returns nil on clean shutdown) and `Shutdown(ctx) error`. Listen inside `ListenAndServe` so bind errors surface immediately.
- Config is a plain struct built in `internal/config` from flags; defaults live in `config.Default()`. Add new settings there and document them in the README table.
- Comments explain *why* (constraints, security, protocol quirks), not what. Keep density similar to existing files.

**Error handling**
- Return errors, don't panic (only exception: `panic(http.ErrAbortHandler)` to abort a half-sent response, and programmer errors on compile-time constants). Wrap with context using `fmt.Errorf("doing x: %w", err)`; compare with `errors.Is/As`. Sentinel errors live in `model` (e.g. `model.ErrNotFound`).
- The proxy must never crash on network errors: map them to a readable plain-text response (`502` unreachable/DNS, `504` timeout, `400` bad request, `501` unsupported), record the error in `Exchange.Error`, and log it. A failed `Sink.Save` is logged, never propagated to the client.
- Logging uses `log/slog` (structured key/value), passed in as `*slog.Logger`; no global loggers, no `fmt.Println` for logs.
- Everything received through the proxy or read back from the database is **untrusted data**: render it in the UI only via `textContent`, never `innerHTML`.

**Proxy engine specifics**
- Use `http.Transport.RoundTrip` directly (not `http.Client`): no redirect following, no cookies, no env proxies, `DisableCompression: true`, so traffic is relayed and stored byte-exact. Strip hop-by-hop headers in both directions. Bodies are streamed and captured through `outbound.Capture` (size-capped); always forward the full body even if capture is truncated. Shared upstream logic (transports, `BuildRequest`, `RemoveHopByHop`, `Classify`, `Capture`, `ReadUpTo`) lives in `internal/outbound`; the proxy and the repeater must both use it so dialing, timeouts and the `-insecure-upstream` behavior can never diverge.
- Store the raw wire bytes; decoding for display (gzip etc.) happens only in `ui/body.go`.
- HTTP and HTTPS share one code path: `forward(w, r, transport)` in `proxy.go`. `tunnel.go` only does CONNECT plumbing (hijack → TLS handshake → per-tunnel `http.Server` → rewrite to absolute `https://` URL → `forward`). Don't duplicate forwarding/recording logic for new transports; extend `forward`.
- Names on an intercepted connection: leaf cert name = SNI, else CONNECT host; upstream address = CONNECT host:port; upstream TLS ServerName = leaf name. Keep it consistent if you touch this.
- Anything that can hang on a peer (TLS handshake, upstream dial/headers) needs a timeout. A failing handshake or invalid SNI must be **logged and recorded** as a `CONNECT` exchange with `Error` set (status 0), never silent.

**Live intercept (`internal/intercept`, pause points in `proxy.forward`)**
- **Pause/resume structure.** There are exactly two pause points, both in `proxy.forward`: (1) after the request is fully received and before `BuildRequest`/`RoundTrip`; (2) after the response is fully received and before anything is written to the client. At each, `forward` computes whether the body must be buffered (`Interceptor.RequestEnabled()/ResponseEnabled()` **or** `RuleEngine.NeedsRequestBody()/NeedsResponseBody()`), buffers it once if so (`outbound.ReadUpTo`, limited by `-max-body`), runs the rule engine (see below; it always runs, buffered or not), and only then, if the matching intercept toggle is on **and** the body was buffered, calls `HoldRequest/HoldResponse`, which mutates the `model.Request`/`model.Response` in place and returns a `model.Outcome` (Verdict, Edited, Note). Anything that transforms traffic at these points operates on the same `model.Request`/`model.Response` objects and reports through `Outcome`/`Exchange` flags the same way; a new pause-point consumer goes **after** rules and **before** the hold, matching this order.
- **No worker goroutines.** The request's own goroutine blocks in `Manager.wait` (a `select` on the item's buffered channel, the timeout timer and `ctx.Done()`). Ownership of an item is decided by removing it from the map under the manager mutex (`take`, `Resolve`, `SetSettings`); only the owner sends on the channel (buffer 1, so it never blocks). Preserve this: a held message must block nothing but its own request, each item is resolved exactly once, and the mutex is never held while sending on a channel or calling out.
- Every hold must end: user action, `-intercept-timeout` (default 60s, 0 = none), client disconnect (`ctx`), toggle-off (`SetSettings` releases), shutdown (`main` releases). New hold paths keep that property.
- The history stores what was **actually sent/delivered** (the edited version) with `req_edited`/`resp_edited`, plus `note` for annotations (auto-forward, not intercepted). A drop is stored as status 403 with `Error`. Messages that cannot be held (body larger than `-max-body`, `text/event-stream`) must stream through unchanged with a note, never truncated (`skipNote` in `proxy.go` builds that note, naming whichever of intercept/rules needed the body).
- `ui/edit.go` is the only place that turns edit forms into model types. Validate everything (method token, http/https URL with a host, header lines, status 200-599); on a validation error answer 400 and leave the item held. Unchanged text bodies keep their original bytes exactly; an edited compressed body drops `Content-Encoding`; CRLF bodies stay CRLF; binary bodies are not editable as text.

**Match & replace rules (`internal/rules`, hooks in `proxy.forward` before the intercept hold)**
- **Where things live.** Rule-definition types (`Rule`, `Scope`, `Condition`, `Action` and their enum types) live in `model`, exactly like `Request`/`Response`/`Outcome` for intercept, so `ui`/`proxy` reference them without importing `internal/rules`. `internal/rules` holds: `rules.go` (small package-local aliases to the `model` types, kept only so this package's own code/tests can spell them unqualified — don't add new fields here, add them in `model`), `compile.go` (validation + one-time regex compilation into an unexported `compiled`/`compiledSet`), `match.go` (scope + condition matching against a `target`), `action.go` (`compiledAction.apply` mutates header/body/status in place), `engine.go` (`Engine`: file I/O, atomic active-set swap, `ApplyRequest`/`ApplyResponse`). A future rule condition/action type is added the same way: a new `model` field/enum value, a `compileCondition`/`compileAction` case, a `matches`/`apply` case, in that order.
- **Compile once, swap atomically.** `Engine` holds the active rule set behind `atomic.Pointer[compiledSet]`; `Load`/`SaveRules`/`SaveRaw` validate + compile a whole new `compiledSet` and only then `Store` it, so a request never observes a half-updated rule set and a failed validation never touches the previously-active one. Regexes (scope path, header/body condition patterns, `body_regex_replace` pattern) are compiled exactly once there, never in `ApplyRequest`/`ApplyResponse`. Keep new rule state inside `compiledSet`/`compiled`, not separate package globals, so the atomic swap stays the only synchronization needed (no mutex, unlike `intercept.Manager`, because there is nothing to block on: `Apply*` never waits on anything).
- **The file is the source of truth**, not SQLite: `Engine.Path()`/`Load`/`SaveRules`/`SaveRaw`/`ReadRaw` are the only ways rules are read or written, and `store` never gets a rules table. A UI save validates first, writes the file (`SaveRules` regenerates YAML from the structured list; `SaveRaw` writes the caller's text verbatim, preserving comments), and only then swaps the active set — in that order, always. A missing file at `Load` is zero rules (not an error); a malformed *existing* file is (both at startup, fatal, and from the UI, `400` with the previous rules kept running).
- **`NeedsRequestBody()`/`NeedsResponseBody()`** are cheap precomputed flags on the active `compiledSet` (true iff some *enabled* rule's condition or action touches the body) that `proxy.forward` checks before deciding whether to buffer at all — keep this precomputation up to date if a new condition/action type can touch the body, or a body-only ruleset will silently stop forcing buffering. `ApplyRequest`/`ApplyResponse` additionally take a `bodyAvailable bool` (true only when the caller actually buffered the body this time) and a rule whose condition/action needs the body **never fires** when it is false — this is what stops an oversized/streaming body from producing a false "rule fired" record while the wire still streams the untouched original.
- **Evaluation**: rules run in `File.Rules` (YAML array) order; every enabled rule matching its own `direction` and scope/conditions applies its one action and is recorded as fired, in order, **before the next rule is evaluated** — so rule N+1's conditions can see rule N's edit. `Apply*` returns the fired rule ids; `proxy.forward` appends them to `Exchange.RulesApplied` (store as JSON, `rule_fired` bool mirrors `len(RulesApplied) > 0` for the cheap history-list flag, schema v3). One action per rule; chain rules for multiple effects on one message.
- **Never touches Repeater.** Like the intercept queue, `repeater.Service` does not call into `rules.Engine` — the repeater bypasses both by design (see below).

**Repeater (`internal/repeater`)**
- A direct outbound send through `outbound` only. It must **never** go through the proxy listener, the intercept queue, or the rule engine, and must use the same `outbound.Config` (timeouts, `-insecure-upstream`) as the proxy. Network failures are stored as results (`Exchange.Error`, status 0), not returned as Go errors; only unusable requests return `model.ErrInvalidRequest`. Results are stored with `Source = model.SourceRepeater` so replayed traffic stays visibly distinct (UI flag, row style, filter). Keep the stored `Content-Length` truthful (`outbound.SyncContentLength`).

**Crypto / certificates (`internal/ca`)**
- All key and certificate code lives in `internal/ca`. Other packages get certificates only through the `proxy.CertIssuer` interface and the public PEM via `Authority.CertPEM()`. **The private key must never leave the package**: no exported accessor, never logged, never written anywhere but `ca.key`, never served by the UI (only `/ca.crt`, public).
- Standard library `crypto/*` only, ECDSA P-256. Validate every name before issuing (`ca.NormalizeName`); reject rather than sanitize.
- CA files live in `<os.UserConfigDir()>/ekisde.dev/Proxy/ca/` (override `-ca-dir`), key mode `0600`, created with `O_EXCL`. Never overwrite an existing CA; refuse inconsistent or expired state with an actionable error.
- Upstream certificate validation is **ON by default**; only `-insecure-upstream` turns it off (and logs a warning). Don't add code that skips verification any other way.
- The code never modifies OS/browser trust stores; the user installs `ca.crt` (steps are in the README). If you change CA behavior, update the README install/rotation sections too.

**Storage**
- SQLite via `database/sql` + `modernc.org/sqlite`, single connection. Schema changes: bump `schemaVersion` (currently 3), add a migration step that runs in its own transaction (see `schemaV3`), never edit an old schema constant, test migrating a real old-version database (`TestSchemaV1DatabaseIsMigrated`, `TestSchemaV2DatabaseIsMigrated`), and document it in the README (including that older versions cannot open the new database). Use parameterized queries only. Match & replace rules themselves are **not** stored here (the YAML file is authoritative, see above); only the fired-rule-ids result of a rule running goes into `exchanges`.

**Tests**
- Concurrency code (`intercept`, the pause points) needs tests that run under `-race`: many simultaneous held items resolved out of order, timeout, client disconnect, release on toggle-off. Wait with deadlines (`waitHeld`-style polling), never with fixed sleeps as assertions.
- Table/behavior tests next to the code (`*_test.go`), using `httptest` for the proxy (`httptest.NewTLSServer` + `Config.UpstreamRootCAs` for HTTPS upstreams) and `t.TempDir()` for SQLite, CA and rules-file directories. Tests must never touch the real user CA/rules directory or OS trust stores. New behavior needs a test. Rule validation needs a table test naming the exact substring expected in the error (see `internal/rules/rules_test.go`'s `TestValidationErrors`), not just "an error occurred". Run `gofmt -l . && go vet ./... && go test ./...` before finishing a change.

**Dependencies**
- Prefer the standard library. Adding a dependency needs a reason, a README mention (Requirements/Architecture), and must not require CGO. Current exceptions: `modernc.org/sqlite` (no CGO SQLite driver) and `gopkg.in/yaml.v3` (rules file parsing; no YAML in the standard library).

## Workflow checklist for every change

1. Implement (only the requested phase/scope).
2. `gofmt -l .`, `go vet ./...`, `go test ./...`.
3. Update `README.md` (and this file if conventions changed) **in the same turn**.
4. Don't commit binaries or `*.db` files (see `.gitignore`).
