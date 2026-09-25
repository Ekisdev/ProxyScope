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

func TestRelayTargetFlag(t *testing.T) {
	cfg, err := Parse([]string{
		"-relay", "name=game1,proto=tcp,listen=127.0.0.1:9100,upstream=game.example.com:9100",
		"-relay", "name=game2,proto=udp,listen=127.0.0.1:9200,upstream=game.example.com:9200",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RelayTargets) != 2 {
		t.Fatalf("targets = %+v", cfg.RelayTargets)
	}
	g1 := cfg.RelayTargets[0]
	if g1.Name != "game1" || g1.Protocol != "tcp" || g1.Listen != "127.0.0.1:9100" || g1.Upstream != "game.example.com:9100" {
		t.Fatalf("game1 = %+v", g1)
	}
	if cfg.RelayTargets[1].Protocol != "udp" {
		t.Fatalf("game2 = %+v", cfg.RelayTargets[1])
	}
}

func TestRelayTargetFlagValidation(t *testing.T) {
	cases := []string{
		"proto=tcp,listen=127.0.0.1:9100,upstream=up:1",                   // missing name
		"name=a,proto=carrier-pigeon,listen=127.0.0.1:9100,upstream=up:1", // bad proto
		"name=a,proto=tcp,listen=not-a-host-port,upstream=up:1",           // bad listen
		"name=a,proto=tcp,listen=127.0.0.1:9100,upstream=not-a-host-port", // bad upstream
		"name=a,bogus=1,proto=tcp,listen=127.0.0.1:9100,upstream=up:1",    // unknown field
	}
	for _, c := range cases {
		if _, err := Parse([]string{"-relay", c}, io.Discard); err == nil {
			t.Errorf("%q should be rejected", c)
		}
	}
	// Duplicate names across two -relay flags.
	dup := []string{
		"-relay", "name=a,proto=tcp,listen=127.0.0.1:9100,upstream=up:1",
		"-relay", "name=a,proto=tcp,listen=127.0.0.1:9200,upstream=up:2",
	}
	if _, err := Parse(dup, io.Discard); err == nil {
		t.Fatal("duplicate target name should be rejected")
	}
}

func TestRelayDefaults(t *testing.T) {
	def, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(def.RelayTargets) != 0 {
		t.Fatalf("default targets = %+v, want none", def.RelayTargets)
	}
	if def.RelayMaxCapture != 10<<20 {
		t.Fatalf("RelayMaxCapture = %d", def.RelayMaxCapture)
	}
	if def.RelayUDPIdleTimeout != 2*time.Minute {
		t.Fatalf("RelayUDPIdleTimeout = %v", def.RelayUDPIdleTimeout)
	}
	if _, err := Parse([]string{"-relay-udp-idle-timeout", "0"}, io.Discard); err == nil {
		t.Fatal("0 UDP idle timeout should be rejected (UDP sessions would never end)")
	}
	if _, err := Parse([]string{"-relay-max-capture", "-1"}, io.Discard); err == nil {
		t.Fatal("negative relay-max-capture should be rejected")
	}
}
