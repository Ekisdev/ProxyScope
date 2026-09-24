# CLAUDE.md — instructions for Claude working on proxyscope

proxyscope is a local intercepting HTTP proxy (Burp-Suite-like) written in Go, with SQLite storage and a small web UI. See `README.md` for what it is and how it is laid out.

## Mandatory rule: keep README.md up to date

**Any change to the project — new functionality, refactor, relevant fix, new dependency, new flag, new package, changed behavior, important design decision — MUST update `README.md` in the same work turn (and in the same commit if the repo is under git).** Never leave a README update as a pending follow-up. Concretely, update whichever apply: the Status table / "What works now", Known limitations, Configuration (flags), Architecture (package list, dependency direction, request flow), UI API, Database notes, Windows vs Linux section, Requirements, Development, Roadmap. If a change genuinely needs no README edit, say so explicitly in your final message. Also update this file if a convention below changes.

## Intended use

Only for the owner's own traffic or systems with **explicit authorization** to test. Do not add features aimed at unauthorized targets, and keep defaults conservative (loopback binding, no exposure of captured data).

## Phased project — do not work ahead

- **Phase 1 (done)**: plain HTTP proxy, SQLite history, web UI.
- **Phase 2**: TLS MITM with a custom CA.
- **Phase 3**: live intercept (pause/edit/forward) + Repeater.
- **Phase 4**: match & replace rules.
- **Phase 5**: generic TCP/UDP relay, as a **separate module** in the same project.

Do **not** implement future-phase functionality unless explicitly asked, even if it looks easy. It is fine (and encouraged) to keep seams for them, e.g. the `proxy.Sink` interface, the schema version in `PRAGMA user_version`. When a phase is implemented, update the README Status table.

## Cross-platform (Windows + Linux/Arch)

The project must build and run on both. Use Go's standard cross-platform APIs (`filepath`, `os/signal` with `os.Interrupt` + `syscall.SIGTERM`, etc.). No CGO (that is why the SQLite driver is `modernc.org/sqlite`). Don't match on errno values (`syscall.ECONNREFUSED` differs on Windows); classify network errors by Go type (`net.OpError`, `net.DNSError`, `net.Error.Timeout()`). If OS-specific code is unavoidable, isolate it in `*_windows.go` / `*_linux.go` files (or build tags), keep it minimal, and document it in the README "Windows vs Linux" section. Currently there is none. Test on Windows when possible; write path handling and shell examples for both OSes in docs.

## Code conventions (decided in Phase 1)

**Layout**
- Module name and binary: `proxyscope`. Entry point `cmd/proxyscope/main.go` only wires things together; no logic there beyond flag → construct → run → shut down.
- All code under `internal/`. One package per concern: `model` (shared types, no internal deps), `config`, `proxy`, `store`, `ui`. New concerns (intercept, repeater, rules, TLS/CA, relay) get their own package; don't grow `proxy` into a catch-all.
- Dependency direction: `cmd` → everything; `proxy`/`ui` → `model` only, plus small interfaces they define themselves (`proxy.Sink`, `ui.Store`) which `store.Store` satisfies. `store` → `model`. No cycles, no package importing `cmd`. Define interfaces where they are consumed.
- Frontend is plain HTML/CSS/JS embedded with `go:embed` in `internal/ui/web`. No build step, no npm, no external CDN.

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
- Use `http.Transport.RoundTrip` directly (not `http.Client`): no redirect following, no cookies, no env proxies, `DisableCompression: true`, so traffic is relayed and stored byte-exact. Strip hop-by-hop headers in both directions. Bodies are streamed and captured through the size-capped `capture` writer; always forward the full body even if capture is truncated.
- Store the raw wire bytes; decoding for display (gzip etc.) happens only in `ui/body.go`.

**Storage**
- SQLite via `database/sql` + `modernc.org/sqlite`, single connection. Schema changes: bump `schemaVersion`, add a migration step, document in README. Use parameterized queries only.

**Tests**
- Table/behavior tests next to the code (`*_test.go`), using `httptest` for the proxy and `t.TempDir()` for SQLite. New behavior needs a test. Run `gofmt -l . && go vet ./... && go test ./...` before finishing a change.

**Dependencies**
- Prefer the standard library. Adding a dependency needs a reason, a README mention (Requirements/Architecture), and must not require CGO.

## Workflow checklist for every change

1. Implement (only the requested phase/scope).
2. `gofmt -l .`, `go vet ./...`, `go test ./...`.
3. Update `README.md` (and this file if conventions changed) **in the same turn**.
4. Don't commit binaries or `*.db` files (see `.gitignore`).
