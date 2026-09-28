//go:build windows

package sysCapture

import "testing"

// TestEnsureLoadedReturnsErrorNotPanicOnMissingDLL is a regression test for a
// bug where a missing or wrong-architecture WinDivert.dll (see README's
// "Installing WinDivert") panicked the whole process instead of surfacing a
// normal, wrapped error. It relies on this test binary genuinely not having
// a loadable WinDivert.dll next to it or on PATH (true in CI and in any dev
// environment that hasn't installed WinDivert system-wide, which is why the
// README has you place the DLL next to proxyscope.exe rather than install
// it) -- if that assumption ever breaks (the DLL becomes reachable), this
// test can no longer exercise the failure path and should be revisited.
//
// It calls ensureLoaded/winDivertOpen directly rather than going through
// Service.ListenAndServe, since ListenAndServe's own elevation check would
// short-circuit before ever reaching the DLL-loading code this test targets.
func TestEnsureLoadedReturnsErrorNotPanicOnMissingDLL(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ensureLoaded panicked instead of returning an error: %v", r)
		}
	}()
	err := ensureLoaded()
	if err == nil {
		t.Skip("WinDivert.dll is actually loadable in this environment; nothing to test here")
	}
	t.Logf("ensureLoaded correctly returned an error, not a panic: %v", err)

	// winDivertOpen must surface the same error, not panic, since it also
	// goes through ensureLoaded before ever calling procWinDivertOpen.Call.
	if _, err := winDivertOpen("tcp.DstPort == 1"); err == nil {
		t.Fatal("winDivertOpen succeeded despite ensureLoaded failing")
	}
}
