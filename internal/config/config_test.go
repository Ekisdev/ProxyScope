package config

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultCADirUsesEkisdeDevLayout(t *testing.T) {
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user config dir on this machine")
	}
	want := filepath.Join(base, "ekisde.dev", "Proxy", "ca")
	if got := Default().CADir; got != want {
		t.Fatalf("CADir = %q, want %q", got, want)
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := Parse([]string{"-ca-dir", "x", "-insecure-upstream", "-export-ca", "out.crt", "-rules-file", "r.yaml"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CADir != "x" || !cfg.InsecureUpstream || cfg.ExportCA != "out.crt" || cfg.RulesFile != "r.yaml" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if def, _ := Parse(nil, io.Discard); def.InsecureUpstream {
		t.Fatal("upstream validation must be ON by default")
	}
}

func TestDefaultRulesFileUsesEkisdeDevLayout(t *testing.T) {
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user config dir on this machine")
	}
	want := filepath.Join(base, "ekisde.dev", "Proxy", "rules.yaml")
	if got := Default().RulesFile; got != want {
		t.Fatalf("RulesFile = %q, want %q", got, want)
	}
}

func TestInterceptTimeoutFlag(t *testing.T) {
	if def, _ := Parse(nil, io.Discard); def.InterceptTimeout != time.Minute {
		t.Fatalf("default = %v, want 1m", def.InterceptTimeout)
	}
	if cfg, err := Parse([]string{"-intercept-timeout", "0"}, io.Discard); err != nil || cfg.InterceptTimeout != 0 {
		t.Fatalf("0 must disable the timeout: %+v %v", cfg, err)
	}
	if cfg, err := Parse([]string{"-intercept-timeout", "5m"}, io.Discard); err != nil || cfg.InterceptTimeout != 5*time.Minute {
		t.Fatalf("5m: %+v %v", cfg, err)
	}
	if _, err := Parse([]string{"-intercept-timeout", "-1s"}, io.Discard); err == nil {
		t.Fatal("negative timeout must be rejected")
	}
}
