// Package config parses command-line configuration for proxyscope.
package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Config holds every user-tunable setting.
type Config struct {
	ProxyAddr        string        // listen address of the intercepting proxy
	UIAddr           string        // listen address of the web UI
	DBPath           string        // SQLite database file
	MaxBodyBytes     int64         // max bytes of each body kept in the database
	DialTimeout      time.Duration // connect timeout towards the target server
	HeaderTimeout    time.Duration // wait for response headers from the target
	InterceptTimeout time.Duration // auto-forward a held request/response after this long (0 = never)

	CADir            string // directory holding the MITM root CA (ca.crt, ca.key)
	ExportCA         string // if set: write the public CA certificate here and exit
	InsecureUpstream bool   // skip validation of upstream TLS certificates

	RulesFile string // match & replace rules file (YAML); missing = zero rules
}

// Default returns the default configuration. Both listeners bind to loopback
// only: captured traffic is sensitive, so exposing it must be an explicit choice.
func Default() Config {
	return Config{
		ProxyAddr:        "127.0.0.1:8080",
		UIAddr:           "127.0.0.1:8081",
		DBPath:           "proxyscope.db",
		MaxBodyBytes:     10 << 20,
		DialTimeout:      10 * time.Second,
		HeaderTimeout:    60 * time.Second,
		InterceptTimeout: 60 * time.Second,
		CADir:            defaultCADir(),
		RulesFile:        defaultRulesFile(),
	}
}

// defaultCADir returns <user config dir>/ekisde.dev/Proxy/ca:
// %AppData%\ekisde.dev\Proxy\ca on Windows, ~/.config/ekisde.dev/Proxy/ca on
// Linux (honoring XDG_CONFIG_HOME). Empty if the config dir is unknown.
func defaultCADir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "ekisde.dev", "Proxy", "ca")
}

// defaultRulesFile returns <user config dir>/ekisde.dev/Proxy/rules.yaml,
// alongside (but outside of) the CA directory: rules are meant to be
// version-controlled and shared, unlike the CA's private key. Empty if the
// config dir is unknown.
func defaultRulesFile() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "ekisde.dev", "Proxy", "rules.yaml")
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
	fs.DurationVar(&cfg.InterceptTimeout, "intercept-timeout", cfg.InterceptTimeout, "auto-forward a held (intercepted) request or response unmodified after this long; 0 = wait until resolved or the client disconnects")
	fs.StringVar(&cfg.CADir, "ca-dir", cfg.CADir, "directory of the MITM root CA (ca.crt + ca.key); generated on first run")
	fs.StringVar(&cfg.ExportCA, "export-ca", "", "write the public CA certificate to this file (PEM) and exit")
	fs.BoolVar(&cfg.InsecureUpstream, "insecure-upstream", false, "do NOT validate upstream servers' TLS certificates (invalid/expired/self-signed are accepted)")
	fs.StringVar(&cfg.RulesFile, "rules-file", cfg.RulesFile, "match & replace rules file (YAML); missing file = no rules, malformed file = refuse to start")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if cfg.MaxBodyBytes < 0 {
		return cfg, fmt.Errorf("-max-body must be >= 0")
	}
	if cfg.InterceptTimeout < 0 {
		return cfg, fmt.Errorf("-intercept-timeout must be >= 0")
	}
	if cfg.CADir == "" {
		return cfg, fmt.Errorf("cannot determine the user config directory; pass -ca-dir")
	}
	if cfg.RulesFile == "" {
		return cfg, fmt.Errorf("cannot determine the user config directory; pass -rules-file")
	}
	if cfg.ProxyAddr == cfg.UIAddr {
		return cfg, fmt.Errorf("-proxy-addr and -ui-addr must differ")
	}
	return cfg, nil
}
