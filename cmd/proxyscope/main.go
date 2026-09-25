// Command proxyscope is a local intercepting HTTP proxy with a web UI.
// Use it only against your own traffic or systems you are authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"proxyscope/internal/ca"
	"proxyscope/internal/config"
	"proxyscope/internal/intercept"
	"proxyscope/internal/model"
	"proxyscope/internal/outbound"
	"proxyscope/internal/proxy"
	"proxyscope/internal/relay"
	"proxyscope/internal/repeater"
	"proxyscope/internal/rules"
	"proxyscope/internal/store"
	"proxyscope/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "proxyscope:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if cfg.ExportCA != "" {
		authority, _, err := ca.LoadOrCreate(cfg.CADir)
		if err != nil {
			return fmt.Errorf("root CA: %w", err)
		}
		if err := authority.ExportCert(cfg.ExportCA); err != nil {
			return err
		}
		fmt.Printf("CA certificate written to %s\nSHA-256 fingerprint: %s\n", cfg.ExportCA, authority.Fingerprint())
		return nil
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("database opened", "path", cfg.DBPath)

	authority, created, err := ca.LoadOrCreate(cfg.CADir)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	if created {
		log.Info("generated a new root CA; install ca.crt in your trust store to intercept HTTPS (see README)")
	}
	// Only public information is logged: never the key.
	log.Info("root CA loaded", "cert", authority.CertPath(), "sha256", authority.Fingerprint())

	// Dialing, timeouts and upstream TLS validation are shared by the proxy and
	// the repeater, so both behave identically.
	out := outbound.Config{
		DialTimeout:      cfg.DialTimeout,
		HeaderTimeout:    cfg.HeaderTimeout,
		InsecureUpstream: cfg.InsecureUpstream,
	}
	icpt := intercept.New(cfg.InterceptTimeout)

	re := rules.New(cfg.RulesFile)
	if err := re.Load(); err != nil {
		return fmt.Errorf("match & replace rules: %w", err)
	}
	log.Info("match & replace rules loaded", "path", re.Path(), "count", len(re.Rules()))

	px := proxy.New(proxy.Config{
		Addr:         cfg.ProxyAddr,
		MaxBodyBytes: cfg.MaxBodyBytes,
		Outbound:     out,
	}, st, authority, icpt, re, log)
	rep := repeater.New(repeater.Config{MaxBodyBytes: cfg.MaxBodyBytes, Outbound: out}, st)
	defer rep.Close()
	if cfg.InsecureUpstream {
		log.Warn("upstream TLS certificate validation is DISABLED (-insecure-upstream)")
	}

	relayTargets := make([]relay.Target, len(cfg.RelayTargets))
	for i, t := range cfg.RelayTargets {
		relayTargets[i] = relay.Target{Name: t.Name, Protocol: model.RelayProtocol(t.Protocol), Listen: t.Listen, Upstream: t.Upstream}
		if !isLoopbackHostPort(t.Listen) {
			log.Warn("relay target listens on a non-loopback address; captured traffic (credentials, game/protocol secrets) will be reachable from your network", "target", t.Name, "listen", t.Listen)
		}
	}
	rel := relay.New(relay.Config{
		Targets: relayTargets, DialTimeout: cfg.DialTimeout,
		MaxCapture: cfg.RelayMaxCapture, UDPIdleTimeout: cfg.RelayUDPIdleTimeout, InterceptTimeout: cfg.InterceptTimeout,
	}, st, log)

	web := ui.New(cfg.UIAddr, ui.Deps{Store: st, Interceptor: icpt, Repeater: rep, Rules: re, Relay: rel, CAPEM: authority.CertPEM()}, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 3)
	go func() {
		if err := px.ListenAndServe(); err != nil {
			errc <- fmt.Errorf("proxy: %w", err)
		}
	}()
	go func() {
		if err := web.ListenAndServe(); err != nil {
			errc <- fmt.Errorf("ui: %w", err)
		}
	}()
	go func() {
		if err := rel.ListenAndServe(); err != nil {
			errc <- fmt.Errorf("relay: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errc: // e.g. port already in use
	}

	// Release anything held in the intercept queue so graceful shutdown does not
	// wait for requests nobody will resolve any more.
	icpt.SetSettings(model.InterceptSettings{})
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = px.Shutdown(shutCtx)
	_ = web.Shutdown(shutCtx)
	_ = rel.Shutdown(shutCtx) // also releases every held relay chunk, see relay.Service.Shutdown
	return runErr
}

// isLoopbackHostPort reports whether addr's host is loopback ("127.0.0.1",
// "::1", "localhost"); used only to decide whether to warn about a relay
// target listening on a non-loopback address.
func isLoopbackHostPort(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
