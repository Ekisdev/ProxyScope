// Package config parses command-line configuration for proxyscope.
package config

import (
	"flag"
	"fmt"
	"io"
	"time"
)

// Config holds every user-tunable setting.
type Config struct {
	ProxyAddr     string        // listen address of the intercepting proxy
	UIAddr        string        // listen address of the web UI
	DBPath        string        // SQLite database file
	MaxBodyBytes  int64         // max bytes of each body kept in the database
	DialTimeout   time.Duration // connect timeout towards the target server
	HeaderTimeout time.Duration // wait for response headers from the target
}

// Default returns the default configuration. Both listeners bind to loopback
// only: captured traffic is sensitive, so exposing it must be an explicit choice.
func Default() Config {
	return Config{
		ProxyAddr:     "127.0.0.1:8080",
		UIAddr:        "127.0.0.1:8081",
		DBPath:        "proxyscope.db",
		MaxBodyBytes:  10 << 20,
		DialTimeout:   10 * time.Second,
		HeaderTimeout: 60 * time.Second,
	}
}

// Parse builds a Config from command-line arguments (without the program
// name). It returns flag.ErrHelp when -h was requested.
func Parse(args []string, out io.Writer) (Config, error) {
	cfg := Default()
	fs := flag.NewFlagSet("proxyscope", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.ProxyAddr, "proxy-addr", cfg.ProxyAddr, "listen address of the HTTP proxy")
	fs.StringVar(&cfg.UIAddr, "ui-addr", cfg.UIAddr, "listen address of the web UI")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "path of the SQLite database file")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body", cfg.MaxBodyBytes, "max bytes stored per request/response body (larger bodies are still forwarded in full)")
	fs.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "timeout for connecting to the target server")
	fs.DurationVar(&cfg.HeaderTimeout, "header-timeout", cfg.HeaderTimeout, "timeout waiting for the target's response headers")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if cfg.MaxBodyBytes < 0 {
		return cfg, fmt.Errorf("-max-body must be >= 0")
	}
	if cfg.ProxyAddr == cfg.UIAddr {
		return cfg, fmt.Errorf("-proxy-addr and -ui-addr must differ")
	}
	return cfg, nil
}
