package sysCapture

import (
	"encoding/binary"
	"net"
	"testing"

	"proxyscope/internal/model"
)

// buildIPv4TCP builds a minimal, valid IPv4+TCP packet with the given
// payload, no options, no fragmentation.
func buildIPv4TCP(t *testing.T, src, dst string, srcPort, dstPort uint16, flags byte, payload []byte) []byte {
	t.Helper()
	ihl, tcpLen := 20, 20
	total := ihl + tcpLen + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())

	th := pkt[ihl:]
	binary.BigEndian.PutUint16(th[0:2], srcPort)
	binary.BigEndian.PutUint16(th[2:4], dstPort)
	th[12] = 5 << 4 // data offset 5 (20 bytes), no options
	th[13] = flags
	copy(pkt[ihl+tcpLen:], payload)
	return pkt
}

// buildIPv4UDP builds a minimal, valid IPv4+UDP packet.
func buildIPv4UDP(t *testing.T, src, dst string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	ihl, udpLen := 20, 8+len(payload)
	total := ihl + udpLen
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())

	uh := pkt[ihl:]
	binary.BigEndian.PutUint16(uh[0:2], srcPort)
	binary.BigEndian.PutUint16(uh[2:4], dstPort)
	binary.BigEndian.PutUint16(uh[4:6], uint16(udpLen))
	copy(pkt[ihl+8:], payload)
	return pkt
}

func TestParseIPv4TCP(t *testing.T) {
	pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 5555, 80, tcpFlagSYN, []byte("hello"))
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != model.RelayTCP || p.SrcPort != 5555 || p.DstPort != 80 || p.IPv6 {
		t.Fatalf("parsed = %+v", p)
	}
	if !p.SrcIP.Equal(net.ParseIP("10.0.0.1")) || !p.DstIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("addrs = %v -> %v", p.SrcIP, p.DstIP)
	}
	if string(p.payload(pkt)) != "hello" {
		t.Fatalf("payload = %q", p.payload(pkt))
	}
	if p.TCPFlags != tcpFlagSYN {
		t.Fatalf("flags = %x", p.TCPFlags)
	}
}

func TestParseIPv4UDP(t *testing.T) {
	pkt := buildIPv4UDP(t, "10.0.0.1", "10.0.0.2", 12345, 53, []byte("query"))
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != model.RelayUDP || p.SrcPort != 12345 || p.DstPort != 53 {
		t.Fatalf("parsed = %+v", p)
	}
	if string(p.payload(pkt)) != "query" {
		t.Fatalf("payload = %q", p.payload(pkt))
	}
}

func TestParseRejectsFragments(t *testing.T) {
	pkt := buildIPv4UDP(t, "10.0.0.1", "10.0.0.2", 1, 2, []byte("x"))
	// Set the "more fragments" flag.
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000)
	if _, err := parsePacket(pkt); err != errUnparseable {
		t.Fatalf("err = %v, want errUnparseable", err)
	}
}

func TestParseRejectsUnknownProtocol(t *testing.T) {
	pkt := buildIPv4UDP(t, "10.0.0.1", "10.0.0.2", 1, 2, []byte("x"))
	pkt[9] = 1 // ICMP, not TCP/UDP
	if _, err := parsePacket(pkt); err != errUnparseable {
		t.Fatalf("err = %v, want errUnparseable", err)
	}
}

func TestParseRejectsTooShort(t *testing.T) {
	if _, err := parsePacket([]byte{0x45, 0, 0}); err != errUnparseable {
		t.Fatalf("err = %v, want errUnparseable", err)
	}
	if _, err := parsePacket(nil); err != errUnparseable {
		t.Fatalf("err = %v, want errUnparseable", err)
	}
}

func TestFlowKeySymmetric(t *testing.T) {
	a := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1111, 80, 0, nil)
	b := buildIPv4TCP(t, "10.0.0.2", "10.0.0.1", 80, 1111, 0, nil)
	pa, err := parsePacket(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := parsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if flowKey(pa) != flowKey(pb) {
		t.Fatalf("flow keys differ: %q vs %q", flowKey(pa), flowKey(pb))
	}
	// A different remote port is a different flow.
	c := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1111, 81, 0, nil)
	pc, _ := parsePacket(c)
	if flowKey(pa) == flowKey(pc) {
		t.Fatal("different destination ports must not share a flow key")
	}
}

func TestReplacePayloadTCPSameLength(t *testing.T) {
	pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1, 2, 0, []byte("hello"))
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	out, err := replacePayload(pkt, p, []byte("HELLO"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := parsePacket(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(p2.payload(out)) != "HELLO" {
		t.Fatalf("payload = %q", p2.payload(out))
	}
	if len(out) != len(pkt) {
		t.Fatalf("length changed: %d -> %d", len(pkt), len(out))
	}
}

func TestReplacePayloadTCPLengthMismatch(t *testing.T) {
	pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1, 2, 0, []byte("hello"))
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacePayload(pkt, p, []byte("hi")); err != ErrTCPPayloadLengthMismatch {
		t.Fatalf("err = %v, want ErrTCPPayloadLengthMismatch", err)
	}
	if _, err := replacePayload(pkt, p, []byte("much longer than original")); err != ErrTCPPayloadLengthMismatch {
		t.Fatalf("err = %v, want ErrTCPPayloadLengthMismatch", err)
	}
}

func TestReplacePayloadUDPLengthChange(t *testing.T) {
	pkt := buildIPv4UDP(t, "10.0.0.1", "10.0.0.2", 1, 2, []byte("hi"))
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	out, err := replacePayload(pkt, p, []byte("a much longer replacement payload"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := parsePacket(out)
	if err != nil {
		t.Fatalf("rebuilt packet must still parse: %v", err)
	}
	if string(p2.payload(out)) != "a much longer replacement payload" {
		t.Fatalf("payload = %q", p2.payload(out))
	}
	// IPv4 total length and UDP length fields must reflect the new size.
	if got := int(binary.BigEndian.Uint16(out[2:4])); got != len(out) {
		t.Fatalf("IP total length = %d, want %d", got, len(out))
	}
}
