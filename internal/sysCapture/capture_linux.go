//go:build !windows

package sysCapture

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by ListenAndServe on any platform other
// than Windows. WinDivert has no Linux equivalent: NFQUEUE is a
// structurally different API that requires netfilter/iptables/nftables
// rules to redirect traffic into a queue before ProxyScope ever sees
// anything, rather than a driver ProxyScope opens a handle to directly, so
// it cannot be dropped in as a second backend behind the same Service
// methods without real design work. Linux/NFQUEUE support is deliberately
// deferred (see CLAUDE.md and the README's "System-level capture"
// section), consistent with this project's Arch-verification pause.
//
// This file is a real, minimal, compiling implementation of Service's
// platform surface -- not a build-tag exclusion that would break
// cross-compilation. go build/vet/test all succeed on Linux, and calling
// ListenAndServe returns this error cleanly instead of failing to compile
// or panicking.
var ErrNotImplemented = errors.New("system-level capture (-syscapture) is not implemented on this platform yet: it requires WinDivert, which is Windows-only (see README)")

// ListenAndServe always returns ErrNotImplemented on this platform.
func (s *Service) ListenAndServe() error {
	return ErrNotImplemented
}

// Shutdown releases anything sysCapture could have held (nothing, since
// ListenAndServe never started anything on this platform) via
// shutdownCommon (shared with the Windows implementation, see
// sysCapture.go), and otherwise does nothing.
func (s *Service) Shutdown(ctx context.Context) error {
	return s.shutdownCommon(ctx)
}

// Elevated always reports false: elevation is a Windows/WinDivert concept
// that does not apply to this stub.
func (s *Service) Elevated() bool { return false }
