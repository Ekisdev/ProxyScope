// Command proxyscope is a local intercepting HTTP proxy with a web UI.
// Use it only against your own traffic or systems you are authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxyscope/internal/ca"
	"proxyscope/internal/config"
	"proxyscope/internal/intercept"
	"proxyscope/internal/model"
	"proxyscope/internal/outbound"
	"proxyscope/internal/proxy"
	"proxyscope/internal/repeater"
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
	px := proxy.New(proxy.Config{
		Addr:         cfg.ProxyAddr,
		MaxBodyBytes: cfg.MaxBodyBytes,
		Outbound:     out,
	}, st, authority, icpt, log)
	rep := repeater.New(repeater.Config{MaxBodyBytes: cfg.MaxBodyBytes, Outbound: out}, st)
	defer rep.Close()
	if cfg.InsecureUpstream {
		log.Warn("upstream TLS certificate validation is DISABLED (-insecure-upstream)")
	}
	web := ui.New(cfg.UIAddr, ui.Deps{Store: st, Interceptor: icpt, Repeater: rep, CAPEM: authority.CertPEM()}, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
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
	return runErr
}
