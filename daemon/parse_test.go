package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildDNSQuery(name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	labels := []byte{}
	cur := ""
	for _, ch := range name + "." {
		if ch == '.' {
			labels = append(labels, byte(len(cur)))
			labels = append(labels, cur...)
			cur = ""
		} else {
			cur += string(ch)
		}
	}
	labels = append(labels, 0)
	msg = append(msg, labels...)
	msg = append(msg, 0, 1, 0, 1) // A IN
	return msg
}

func TestParseDNSQueryName(t *testing.T) {
	for _, name := range []string{"ads.example.com", "a.b.tracker.net", "example.org"} {
		got, ok := parseDNSQueryName(buildDNSQuery(name))
		if !ok || got != name {
			t.Fatalf("name=%s got=%q ok=%v", name, got, ok)
		}
	}
	// TCP framing must be stripped by caller helper
	raw := buildDNSQuery("ads.example.com")
	framed := make([]byte, 2)
	binary.BigEndian.PutUint16(framed, uint16(len(raw)))
	framed = append(framed, raw...)
	got, ok := parseDNSQueryName(stripTCPFrame(framed))
	if !ok || got != "ads.example.com" {
		t.Fatalf("tcp framed: got=%q ok=%v", got, ok)
	}
	// garbage must not parse
	if _, ok := parseDNSQueryName([]byte{1, 2, 3}); ok {
		t.Fatal("short garbage parsed")
	}
	if _, ok := parseDNSQueryName(make([]byte, 12)); ok {
		t.Fatal("zero qdcount parsed")
	}
}

func buildClientHello(sni string) []byte {
	// server_name extension
	sn := []byte{}
	name := []byte(sni)
	entry := []byte{0}
	entry = append(entry, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)
	listLen := len(entry)
	sn = append(sn, byte(listLen>>8), byte(listLen))
	sn = append(sn, entry...)
	ext := []byte{0, 0, byte(len(sn) >> 8), byte(len(sn))}
	ext = append(ext, sn...)
	exts := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)

	body := []byte{0x03, 0x03}          // client version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)              // session id len
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)           // compression
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestParseTLSServerName(t *testing.T) {
	got, ok := parseTLSServerName(buildClientHello("tracker.example.net"))
	if !ok || got != "tracker.example.net" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
	// truncated hello must report not-ok (caller accepts)
	full := buildClientHello("tracker.example.net")
	if _, ok := parseTLSServerName(full[:len(full)-5]); ok {
		t.Fatal("truncated hello parsed")
	}
	// non-TLS bytes
	if _, ok := parseTLSServerName([]byte("GET / HTTP/1.1\r\n\r\n")); ok {
		t.Fatal("http parsed as tls")
	}
}

func TestParseHTTPHost(t *testing.T) {
	req := []byte("GET /x HTTP/1.1\r\nHost: Ads.Example.COM:8080\r\nUser-Agent: t\r\n\r\n")
	got, ok := parseHTTPHost(req)
	if !ok || got != "ads.example.com" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
	if _, ok := parseHTTPHost([]byte("garbage in garbage out")); ok {
		t.Fatal("garbage parsed as http")
	}
}

func buildIPv4Packet(proto uint8, src, dst string, sport, dport uint16, payload []byte) []byte {
	var trans []byte
	if proto == protoUDP {
		trans = make([]byte, 8)
		binary.BigEndian.PutUint16(trans[0:2], sport)
		binary.BigEndian.PutUint16(trans[2:4], dport)
		binary.BigEndian.PutUint16(trans[4:6], uint16(8+len(payload)))
	} else {
		trans = make([]byte, 20)
		binary.BigEndian.PutUint16(trans[0:2], sport)
		binary.BigEndian.PutUint16(trans[2:4], dport)
		trans[12] = 5 << 4
	}
	trans = append(trans, payload...)
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(trans)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	return append(pkt, trans...)
}

func TestParsePacket(t *testing.T) {
	dns := buildDNSQuery("ads.example.com")
	p := buildIPv4Packet(protoUDP, "10.0.0.2", "223.5.5.5", 53000, 53, dns)
	pi, ok := parsePacket(p)
	if !ok || !pi.udp || pi.dstPort != 53 {
		t.Fatalf("udp dns packet: %+v ok=%v", pi, ok)
	}
	if name, ok := parseDNSQueryName(pi.payload); !ok || name != "ads.example.com" {
		t.Fatalf("payload name=%q ok=%v", name, ok)
	}
	hello := buildClientHello("tracker.example.net")
	p2 := buildIPv4Packet(protoTCP, "10.0.0.2", "1.2.3.4", 44000, 443, hello)
	pi2, ok := parsePacket(p2)
	if !ok || !pi2.tcp || pi2.dstPort != 443 {
		t.Fatalf("tcp tls packet: %+v ok=%v", pi2, ok)
	}
	if sni, ok := parseTLSServerName(pi2.payload); !ok || sni != "tracker.example.net" {
		t.Fatalf("sni=%q ok=%v", sni, ok)
	}
	if _, ok := parsePacket([]byte{0x99, 0x00}); ok {
		t.Fatal("garbage packet parsed")
	}
}

// Forged-name regression: wire labels carrying spaces/newlines must be
// rejected by the parsers, so a crafted packet cannot inject extra
// lines into the stats files (which use a "domain count time" format).
func TestParsersRejectForgedNames(t *testing.T) {
	for _, name := range []string{"ads.exa mple.com", "ads.exa\nmple.com", ".ads.example.com"} {
		if got, ok := parseDNSQueryName(buildDNSQuery(name)); ok {
			t.Errorf("forged DNS name %q parsed as %q, want rejection", name, got)
		}
	}
	if !validParsedName("ads.example.com") || !validParsedName("xn--fiqs8s.example") || validParsedName("") || validParsedName("bad name") {
		t.Error("validParsedName boundary wrong")
	}
}
