//go:build windows

package sysCapture

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// WinDivert layer/priority constants used by this package (from
// basil00/WinDivert's windivert.h, WinDivert 2.x). Only the network layer
// is used -- see README "What's actually filterable" for why (processId
// filtering is not available at this layer; port/address/protocol/
// direction filtering is).
const (
	windivertLayerNetwork    = 0
	windivertPriorityDefault = 0
)

// No new dependency: these are plain syscall.NewLazyDLL/LazyProc bindings
// against WinDivert.dll, the same mechanism the Go standard library itself
// uses for Windows API calls not wrapped by package syscall, and the same
// approach the (archived, MIT-licensed) williamfhe/godivert binding uses --
// see CLAUDE.md for why this project writes its own small wrapper instead
// of importing a binding (unmaintained, or GPL-licensed alternatives).
var (
	winDivertDLL = syscall.NewLazyDLL("WinDivert.dll")

	procWinDivertOpen                = winDivertDLL.NewProc("WinDivertOpen")
	procWinDivertRecv                = winDivertDLL.NewProc("WinDivertRecv")
	procWinDivertSend                = winDivertDLL.NewProc("WinDivertSend")
	procWinDivertClose               = winDivertDLL.NewProc("WinDivertClose")
	procWinDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

const invalidHandleValue = ^uintptr(0)

// allProcs lists every LazyProc ensureLoaded must resolve before this
// package makes its first WinDivert call.
var allProcs = []*syscall.LazyProc{
	procWinDivertOpen, procWinDivertRecv, procWinDivertSend, procWinDivertClose, procWinDivertHelperCalcChecksums,
}

var (
	loadOnce sync.Once
	loadErr  error
)

// ensureLoaded loads WinDivert.dll and resolves every proc this package
// uses, returning a normal error on failure instead of letting the DLL/proc
// be resolved lazily.
//
// syscall.LazyProc.Call finds its DLL/proc lazily via mustFind/mustLoad,
// which PANIC (not return an error) if the DLL can't be loaded (missing
// file, wrong architecture, ...) or the proc can't be found in it -- that
// is deliberate stdlib behavior for "this must always succeed" APIs like
// kernel32, but wrong here: a missing or 32-bit WinDivert.dll next to a
// 64-bit proxyscope.exe (see README's "Installing WinDivert") is exactly
// the kind of ordinary, expected-to-happen setup error this project's rule
// is "return errors, don't panic" for (see CLAUDE.md). LazyDLL.Load and
// LazyProc.Find, unlike Call, return an error instead of panicking, so
// calling them explicitly here -- once, before any Call -- lets
// winDivertOpen (and therefore Service.ListenAndServe) report a clear,
// wrapped error instead of crashing the whole process.
func ensureLoaded() error {
	loadOnce.Do(func() {
		if err := winDivertDLL.Load(); err != nil {
			loadErr = fmt.Errorf("loading WinDivert.dll: %w", err)
			return
		}
		for _, p := range allProcs {
			if err := p.Find(); err != nil {
				loadErr = fmt.Errorf("resolving %s in WinDivert.dll: %w", p.Name, err)
				return
			}
		}
	})
	return loadErr
}

// windivertAddress mirrors WINDIVERT_ADDRESS (WinDivert 2.x): an 8-byte
// timestamp, a 4-byte bitfield packing Layer/Event/Sniffed/Outbound/
// Loopback/Impostor/IPv6/IPChecksum/TCPChecksum/UDPChecksum/Reserved1 (in
// that field order, LSB first -- the standard MSVC x86/x64 bitfield
// layout, and the ABI WinDivert.dll itself was built with), a 4-byte
// reserved field, then a 64-byte union (WINDIVERT_DATA_NETWORK/FLOW/
// SOCKET/REFLECT) of which this package only ever reads the Outbound bit;
// total 80 bytes. This must match the C layout byte-for-byte -- see
// https://github.com/basil00/WinDivert's include/windivert.h.
type windivertAddress struct {
	Timestamp     int64
	layerAndFlags uint32
	reserved2     uint32
	union         [64]byte
}

const windivertAddrOutboundBit = 1 << 17

func (a *windivertAddress) outbound() bool { return a.layerAndFlags&windivertAddrOutboundBit != 0 }

// winDivertOpen calls WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0).
// The calling process must already be elevated (see Service.Elevated);
// WinDivertOpen itself enforces that, and its error is returned unchanged
// (ListenAndServe wraps it with a clearer message).
func winDivertOpen(filter string) (uintptr, error) {
	if err := ensureLoaded(); err != nil {
		return 0, err
	}
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, fmt.Errorf("invalid filter: %w", err)
	}
	h, _, callErr := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(windivertLayerNetwork),
		uintptr(windivertPriorityDefault),
		0,
	)
	if h == invalidHandleValue {
		return 0, callErr
	}
	return h, nil
}

// winDivertRecv reads one packet into buf, returning the slice actually
// filled and its address metadata (direction, interface, ...). The
// returned slice aliases buf; the caller (capture_windows.go's receive
// loop) must finish using it (or copy what it needs) before calling
// winDivertRecv again with the same buf. Like winDivertSend/winDivertClose
// below, it is only ever called after winDivertOpen has already succeeded
// (so ensureLoaded has already resolved every proc it uses), hence no
// ensureLoaded call of its own.
func winDivertRecv(handle uintptr, buf []byte) ([]byte, windivertAddress, error) {
	var addr windivertAddress
	var recvLen uint32
	ok, _, callErr := procWinDivertRecv.Call(
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if ok == 0 {
		return nil, addr, callErr
	}
	return buf[:recvLen], addr, nil
}

// winDivertSend recomputes checksums for pkt and re-injects it using
// addr's original metadata (direction, interface indices) from the Recv
// call that produced it -- WinDivert routes the packet based on addr, not
// just its bytes, since intercepting at this layer makes this process
// responsible for delivery.
func winDivertSend(handle uintptr, pkt []byte, addr *windivertAddress) error {
	if len(pkt) == 0 {
		return nil
	}
	// flags=0: recompute every checksum WinDivertHelperCalcChecksums knows
	// how to fix. Needed whenever a payload was replaced (a length-changing
	// UDP edit invalidates the IP and UDP checksums; a same-length TCP edit
	// invalidates the TCP checksum) and harmless on an unmodified packet.
	procWinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
	var sendLen uint32
	ok, _, callErr := procWinDivertSend.Call(
		handle,
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if ok == 0 {
		return callErr
	}
	return nil
}

func winDivertClose(handle uintptr) error {
	ok, _, callErr := procWinDivertClose.Call(handle)
	if ok == 0 {
		return callErr
	}
	return nil
}
