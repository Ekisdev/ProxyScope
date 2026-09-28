package sysCapture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"proxyscope/internal/model"
)

// errUnparseable means a packet is not one processPacket can make sense of:
// not IPv4/IPv6, a non-TCP/UDP protocol, an IP fragment other than the
// first, or an IPv6 packet with extension headers before TCP/UDP. Such
// packets are forwarded unmodified without a session or capture, exactly
// like a body over -max-body streams through the HTTP proxy untouched (see
// README "Known limitations").
var errUnparseable = errors.New("syscapture: packet not parseable (unsupported protocol, fragment, or IPv6 extension headers)")

// ErrTCPPayloadLengthMismatch is returned by replacePayload (and surfaces
// through Resolve/the UI as a specific 400, not a generic validation error)
// when a manual edit changes a TCP payload's length. Re-injection replays
// the whole packet, so a length-changing TCP edit would desync the sequence
// numbers for the rest of that connection -- the same problem any
// raw-packet-level MITM has without implementing a full TCP stack. UDP has
// no such constraint (no seq/ack) and is not subject to this check.
var ErrTCPPayloadLengthMismatch = errors.New("TCP payload length must match the original on system-capture edits (re-injection replays the whole packet; a length change would desync sequence numbers for the rest of the connection) -- see README")

// parsedPacket is the subset of a captured IP packet processPacket needs:
// enough to identify the flow (4-tuple + protocol) and locate the payload.
type parsedPacket struct {
	IPv6       bool
	Protocol   model.RelayProtocol // RelayTCP or RelayUDP
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   byte // only meaningful when Protocol == RelayTCP
	payloadOff int
	payloadLen int
}

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
)

// parsePacket parses an IPv4 or IPv6 packet down to its TCP/UDP payload.
// It deliberately supports only the common case: no IPv4 fragmentation
// (other than being the first fragment) and no IPv6 extension headers
// before the transport header. Anything else returns errUnparseable so the
// caller forwards the packet unmodified rather than misinterpreting it.
func parsePacket(pkt []byte) (parsedPacket, error) {
	if len(pkt) < 1 {
		return parsedPacket{}, errUnparseable
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4(pkt)
	case 6:
		return parseIPv6(pkt)
	default:
		return parsedPacket{}, errUnparseable
	}
}

func parseIPv4(pkt []byte) (parsedPacket, error) {
	if len(pkt) < 20 {
		return parsedPacket{}, errUnparseable
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return parsedPacket{}, errUnparseable
	}
	flagsAndFrag := binary.BigEndian.Uint16(pkt[6:8])
	moreFragments := flagsAndFrag&0x2000 != 0
	fragOffset := flagsAndFrag & 0x1FFF
	if moreFragments || fragOffset != 0 {
		// Not the first fragment (or a fragmented first one): the transport
		// header is only present in the first fragment, and even then
		// reassembling the full payload is out of scope for this phase.
		return parsedPacket{}, errUnparseable
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) {
		totalLen = len(pkt) // tolerate a padded capture buffer
	}
	p := parsedPacket{
		SrcIP: net.IP(pkt[12:16]),
		DstIP: net.IP(pkt[16:20]),
	}
	return parseTransport(pkt[:totalLen], ihl, pkt[9], p)
}

func parseIPv6(pkt []byte) (parsedPacket, error) {
	if len(pkt) < 40 {
		return parsedPacket{}, errUnparseable
	}
	nextHdr := pkt[6]
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	total := 40 + payloadLen
	if total > len(pkt) {
		total = len(pkt)
	}
	p := parsedPacket{
		IPv6:  true,
		SrcIP: net.IP(pkt[8:24]),
		DstIP: net.IP(pkt[24:40]),
	}
	// Extension headers before TCP/UDP are deliberately not walked; a
	// packet with one is reported unparseable (see parsePacket's doc
	// comment) rather than risk misreading an unfamiliar header chain.
	return parseTransport(pkt[:total], 40, nextHdr, p)
}

func parseTransport(pkt []byte, transportOff int, protocol byte, p parsedPacket) (parsedPacket, error) {
	switch protocol {
	case 6: // TCP
		if len(pkt) < transportOff+20 {
			return parsedPacket{}, errUnparseable
		}
		th := pkt[transportOff:]
		dataOff := int(th[12]>>4) * 4
		if dataOff < 20 || transportOff+dataOff > len(pkt) {
			return parsedPacket{}, errUnparseable
		}
		p.Protocol = model.RelayTCP
		p.SrcPort = binary.BigEndian.Uint16(th[0:2])
		p.DstPort = binary.BigEndian.Uint16(th[2:4])
		p.TCPFlags = th[13]
		p.payloadOff = transportOff + dataOff
		p.payloadLen = len(pkt) - p.payloadOff
		if p.payloadLen < 0 {
			return parsedPacket{}, errUnparseable
		}
		return p, nil
	case 17: // UDP
		if len(pkt) < transportOff+8 {
			return parsedPacket{}, errUnparseable
		}
		uh := pkt[transportOff:]
		p.Protocol = model.RelayUDP
		p.SrcPort = binary.BigEndian.Uint16(uh[0:2])
		p.DstPort = binary.BigEndian.Uint16(uh[2:4])
		p.payloadOff = transportOff + 8
		p.payloadLen = len(pkt) - p.payloadOff
		if p.payloadLen < 0 {
			return parsedPacket{}, errUnparseable
		}
		return p, nil
	default:
		return parsedPacket{}, errUnparseable
	}
}

// payload returns the packet's transport payload bytes.
func (p parsedPacket) payload(pkt []byte) []byte {
	return pkt[p.payloadOff : p.payloadOff+p.payloadLen]
}

// flowKey identifies a session regardless of which direction a given packet
// is travelling: both endpoints' addresses are sorted so packet A->B and
// B->A produce the same key (see Service.processPacket).
func flowKey(p parsedPacket) string {
	a := net.JoinHostPort(p.SrcIP.String(), portString(p.SrcPort))
	b := net.JoinHostPort(p.DstIP.String(), portString(p.DstPort))
	if a > b {
		a, b = b, a
	}
	return string(p.Protocol) + "|" + a + "|" + b
}

func portString(port uint16) string { return fmt.Sprintf("%d", port) }

// replacePayload writes newPayload into pkt in place (TCP: only when the
// length is unchanged, see ErrTCPPayloadLengthMismatch) or returns a new
// packet buffer with newPayload substituted and the IPv4/UDP length fields
// patched (UDP: any length is allowed, there is no sequence number to
// desync). It never touches IP options or an IPv6 header's own fields
// beyond the payload-length field, since parsePacket already refused
// anything with extension headers.
func replacePayload(pkt []byte, p parsedPacket, newPayload []byte) ([]byte, error) {
	if p.Protocol == model.RelayTCP {
		if len(newPayload) != p.payloadLen {
			return nil, ErrTCPPayloadLengthMismatch
		}
		out := append([]byte(nil), pkt...)
		copy(out[p.payloadOff:p.payloadOff+p.payloadLen], newPayload)
		return out, nil
	}
	// UDP: rebuild with the new payload length. Header bytes up to the
	// payload are kept verbatim except for the length fields that must
	// reflect the new size; WinDivertHelperCalcChecksums (called by the
	// caller after this) recomputes the checksums.
	out := append([]byte(nil), pkt[:p.payloadOff]...)
	out = append(out, newPayload...)
	newPayloadLen := len(newPayload)
	udpOff := p.payloadOff - 8
	binary.BigEndian.PutUint16(out[udpOff+4:udpOff+6], uint16(8+newPayloadLen))
	if p.IPv6 {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	} else {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	}
	return out, nil
}
