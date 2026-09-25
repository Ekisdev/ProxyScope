package config

import (
	"io"
	"os"
	"path/filepath"
	"testing"
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
	cfg, err := Parse([]string{"-ca-dir", "x", "-insecure-upstream", "-export-ca", "out.crt"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CADir != "x" || !cfg.InsecureUpstream || cfg.ExportCA != "out.crt" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if def, _ := Parse(nil, io.Discard); def.InsecureUpstream {
		t.Fatal("upstream validation must be ON by default")
	}
}
