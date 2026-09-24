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

	"proxyscope/internal/config"
	"proxyscope/internal/proxy"
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

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("database opened", "path", cfg.DBPath)

	px := proxy.New(proxy.Config{
		Addr:          cfg.ProxyAddr,
		MaxBodyBytes:  cfg.MaxBodyBytes,
		DialTimeout:   cfg.DialTimeout,
		HeaderTimeout: cfg.HeaderTimeout,
	}, st, log)
	web := ui.New(cfg.UIAddr, st, log)

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

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = px.Shutdown(shutCtx)
	_ = web.Shutdown(shutCtx)
	return runErr
}
