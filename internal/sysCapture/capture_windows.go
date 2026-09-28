//go:build windows

package sysCapture

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

// recvBufSize bounds one WinDivertRecv call; 65535 covers the largest
// possible IPv4/IPv6 packet (including options/extension headers we don't
// otherwise parse, see packet.go).
const recvBufSize = 65535

// Elevated reports whether this process has Administrator privileges,
// required by WinDivertOpen. The standard library's syscall package has no
// IsElevated helper (only golang.org/x/sys/windows does); rather than
// hand-roll OpenProcessToken/GetTokenInformation(TokenElevation) byte
// parsing ourselves -- exactly the kind of fragile Win32-struct-layout work
// windivert_windows.go already has to do once, for WINDIVERT_ADDRESS, and
// doing it twice adds risk with no benefit -- this uses
// golang.org/x/sys/windows, which was already a transitive dependency
// (modernc.org/sqlite pulls it in; see go.mod) before this line made it a
// direct one: no new module, no new go.sum entry, official Go team code.
func (s *Service) Elevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

// ListenAndServe opens the WinDivert handle with the configured filter and
// blocks, capturing and re-injecting packets, until Shutdown closes the
// handle (which makes the blocking WinDivertRecv call return, ending this
// loop). It requires Administrator privileges (see Elevated) and reports a
// clear, actionable error -- rather than a raw syscall failure or a crash
// -- if the process is not elevated or the WinDivert driver files are not
// present next to the executable (see README's "Installing WinDivert").
func (s *Service) ListenAndServe() error {
	if !s.Elevated() {
		return fmt.Errorf("system-level capture (-syscapture) requires running as Administrator; WinDivertOpen refuses otherwise (see README)")
	}
	handle, err := winDivertOpen(s.cfg.Filter)
	if err != nil {
		return fmt.Errorf("opening WinDivert with filter %q: %w -- is WinDivert.dll/WinDivert64.sys installed next to proxyscope.exe? see README's \"Installing WinDivert\"", s.cfg.Filter, err)
	}
	s.mu.Lock()
	s.divertHandle = handle
	s.mu.Unlock()
	s.log.Info("syscapture listening", "filter", s.cfg.Filter)

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.sweepLoop() }()

	buf := make([]byte, recvBufSize)
	for {
		pkt, addr, err := winDivertRecv(handle, buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return nil // Shutdown closed the handle: a clean stop, not a real error.
			}
			s.log.Error("syscapture: WinDivertRecv failed", "err", err)
			continue
		}
		out, drop := s.processPacket(pkt, addr.outbound())
		if drop {
			continue
		}
		if err := winDivertSend(handle, out, &addr); err != nil {
			s.log.Warn("syscapture: WinDivertSend failed, packet lost", "err", err)
		}
	}
}

// Shutdown closes the WinDivert handle (unblocking the receive loop) and
// releases every held packet payload via shutdownCommon (shared with the
// Linux stub, see sysCapture.go).
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	handle := s.divertHandle
	s.mu.Unlock()
	if handle != 0 {
		_ = winDivertClose(handle)
	}
	return s.shutdownCommon(ctx)
}
