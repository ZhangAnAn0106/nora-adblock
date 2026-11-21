package main

import (
	"encoding/binary"
	"net"
	"strings"
)

// pktInfo is the minimal L3/L4 view of one queued packet.
type pktInfo struct {
	family  int // 4 or 6
	proto   uint8
	src     net.IP
	dst     net.IP
	srcPort uint16
	dstPort uint16
	payload []byte // L4 payload (after TCP/UDP header)
	tcp     bool
	udp     bool
}

const (
	protoTCP = 6
	protoUDP = 17
)

// parsePacket decodes an IPv4/IPv6 packet as delivered by NFQUEUE.
// ok=false means "cannot parse" and callers must ACCEPT.
func parsePacket(p []byte) (pktInfo, bool) {
	var pi pktInfo
	if len(p) < 1 {
		return pi, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return pi, false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return pi, false
		}
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if total > 0 && total < len(p) {
			p = p[:total]
		}
		pi.family = 4
		pi.proto = p[9]
		pi.src = net.IP(p[12:16])
		pi.dst = net.IP(p[16:20])
		return parseTransport(&pi, p[ihl:])
	case 6:
		if len(p) < 40 {
			return pi, false
		}
		pi.family = 6
		pi.proto = p[6]
		// No extension-header walking: anything but plain TCP/UDP is accepted upstream.
		if pi.proto != protoTCP && pi.proto != protoUDP {
			return pi, false
		}
		pi.src = net.IP(p[8:24])
		pi.dst = net.IP(p[24:40])
		plen := int(binary.BigEndian.Uint16(p[4:6]))
		body := p[40:]
		if plen > 0 && plen < len(body) {
			body = body[:plen]
		}
		return parseTransport(&pi, body)
	}
	return pi, false
}

func parseTransport(pi *pktInfo, t []byte) (pktInfo, bool) {
	switch pi.proto {
	case protoUDP:
		if len(t) < 8 {
			return *pi, false
		}
		pi.udp = true
		pi.srcPort = binary.BigEndian.Uint16(t[0:2])
		pi.dstPort = binary.BigEndian.Uint16(t[2:4])
		pi.payload = t[8:]
		return *pi, true
	case protoTCP:
		if len(t) < 20 {
			return *pi, false
		}
		pi.tcp = true
		pi.srcPort = binary.BigEndian.Uint16(t[0:2])
		pi.dstPort = binary.BigEndian.Uint16(t[2:4])
		doff := int(t[12]>>4) * 4
		if doff < 20 || len(t) < doff {
			return *pi, false
		}
		pi.payload = t[doff:]
		return *pi, true
	}
	return *pi, false
}

// parseDNSQueryName extracts the first QNAME from a DNS message.
// For TCP transport the 2-byte length prefix must already be stripped by the caller.
func parseDNSQueryName(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	if qd < 1 {
		return "", false
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l > 63 || off+l > len(msg) {
			return "", false // compression pointers / truncation are not valid here
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
		if len(labels) > 32 {
			return "", false
		}
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.ToLower(strings.Join(labels, ".")), true
}

// stripTCPFrame removes the RFC 7766 2-byte length prefix of DNS-over-TCP.
func stripTCPFrame(b []byte) []byte {
	if len(b) >= 2 {
		n := int(binary.BigEndian.Uint16(b[0:2]))
		if n == len(b)-2 {
			return b[2:]
		}
	}
	return b
}

// parseTLSServerName extracts the SNI from a TLS ClientHello that is fully
// contained in b. Incomplete records report ok=false so callers ACCEPT.
func parseTLSServerName(b []byte) (string, bool) {
	// TLS record: type(1) version(2) length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b)-5 < recLen {
		return "", false // ClientHello not fully in this packet
	}
	b = b[5 : 5+recLen]
	// Handshake: type(1) length(3) version(2) random(32)
	if len(b) < 4+2+32 || b[0] != 0x01 {
		return "", false
	}
	off := 4 + 2 + 32
	// session id
	if off+1 > len(b) {
		return "", false
	}
	sidLen := int(b[off])
	off += 1 + sidLen
	// cipher suites
	if off+2 > len(b) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2 + csLen
	// compression methods
	if off+1 > len(b) {
		return "", false
	}
	cmLen := int(b[off])
	off += 1 + cmLen
	// extensions
	if off+2 > len(b) {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(b) {
		return "", false
	}
	for off+4 <= end {
		etype := binary.BigEndian.Uint16(b[off : off+2])
		elen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+elen > end {
			return "", false
		}
		if etype == 0 { // server_name
			return parseServerNameList(b[off : off+elen])
		}
		off += elen
	}
	return "", false
}

func parseServerNameList(b []byte) (string, bool) {
	// list length(2), then entries: type(1) name length(2) name
	if len(b) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if listLen < len(b) {
		b = b[:listLen]
	}
	for len(b) >= 3 {
		ntype := b[0]
		nlen := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if nlen > len(b) {
			return "", false
		}
		if ntype == 0 {
			return strings.ToLower(string(b[:nlen])), true
		}
		b = b[nlen:]
	}
	return "", false
}

// parseHTTPHost extracts the Host header (without port) from an HTTP request
// whose headers are contained in b.
func parseHTTPHost(b []byte) (string, bool) {
	if len(b) > 8192 {
		b = b[:8192]
	}
	s := string(b)
	// Must look like an HTTP request line.
	sp := strings.IndexByte(s, ' ')
	if sp <= 0 {
		return "", false
	}
	method := s[:sp]
	switch method {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
	default:
		return "", false
	}
	for _, line := range strings.Split(s, "\r\n") {
		if len(line) > 5 && strings.EqualFold(line[:5], "Host:") {
			host := strings.TrimSpace(line[5:])
			if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host, "]") {
				host = host[:i]
			}
			host = strings.Trim(host, "[]")
			if host == "" {
				return "", false
			}
			return strings.ToLower(host), true
		}
		if line == "" {
			break
		}
	}
	return "", false
}
