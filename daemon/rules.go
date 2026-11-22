package main

import "strconv"

// ChainName is the only iptables chain this module ever touches.
const ChainName = "NORA_ADBLOCK"

const (
	QueueDNS = 0
	QueueSNI = 1
)

// Connmark fast path (v1.0.9): when the SNI handler has decided a TCP
// flow, its verdict stamps the connection with one of these connmarks
// (SetVerdictWithConnMark). Later packets of the same connection are
// then resolved entirely in the kernel by the two connmark rules in
// setupCommands — allowed flows RETURN before the queue rules, blocked
// flows DROP — and never round-trip to userspace again. The in-daemon
// flow table stays as the fallback for packets that were already queued
// before the mark landed (and for kernels without NFQA_CT support).
//
// The values are ours alone: they must never collide with the BoxProxy
// packet marks (16777216/33554432/50331648 — those are fwmarks matched
// with "-m mark"; these are connmarks matched with "-m connmark") nor
// with each other. 0x4E52 = "NR".
const (
	ConnMarkAllow uint32 = 0x4E520001
	ConnMarkBlock uint32 = 0x4E520002
)

// setupCommands returns the argv sequence (without the iptables binary name,
// which the caller prepends via bin) that (re)builds ChainName in the mangle
// table and hooks it at the head of OUTPUT. Exemption rules always precede
// the NFQUEUE rules so exempt traffic never enters a queue.
//
// BoxProxy exemptions are on-demand (boxProxyPresent): when BoxProxy is not
// installed, neither its fwmark rules nor its app-uid rule are emitted. Two
// generic safety exemptions stay regardless: loopback, and uid 0 (root —
// the system and any root daemon must never be filtered).
func setupCommands(cfg Config, exemptUIDs []int, boxProxyPresent bool) [][]string {
	cmds := [][]string{
		{"-w", "-t", "mangle", "-N", ChainName}, // tolerated to fail if chain exists
		{"-w", "-t", "mangle", "-F", ChainName},
	}
	add := func(args ...string) {
		full := []string{"-w", "-t", "mangle", "-A", ChainName}
		cmds = append(cmds, append(full, args...))
	}
	// 1) loopback always passes
	add("-o", "lo", "-j", "RETURN")
	// 2) packets carrying a proxy mark pass
	if boxProxyPresent {
		for _, m := range cfg.ProxyMarks {
			if m == 0 {
				continue // "--mark 0/0" matches every packet: never emit it
			}
			s := strconv.FormatUint(uint64(m), 10)
			add("-m", "mark", "--mark", s+"/"+s, "-j", "RETURN")
		}
	}
	// 3) uid exemptions: uid 0 (root) always passes; proxy app uids only
	// when BoxProxy is actually installed.
	for _, uid := range exemptUIDs {
		if !boxProxyPresent && uid != 0 {
			continue
		}
		add("-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "RETURN")
	}
	// 3b) connmark fast path: connections the daemon already decided
	// are resolved in the kernel and never enter a queue again. After
	// every exemption, before QUIC and the queue rules.
	add("-m", "connmark", "--mark", strconv.FormatUint(uint64(ConnMarkAllow), 10)+"/4294967295", "-j", "RETURN")
	add("-m", "connmark", "--mark", strconv.FormatUint(uint64(ConnMarkBlock), 10)+"/4294967295", "-j", "DROP")
	// 4) QUIC fallback: after all exemptions, drop UDP 443 outright.
	// QUIC carries its hostname inside encrypted Initial packets; instead of
	// parsing them, dropping the flow makes apps fall back to TCP, where the
	// DNS/SNI filters below decide by domain name.
	if cfg.QUICFilter {
		add("-p", "udp", "--dport", "443", "-j", "DROP")
	}
	// 5) DNS filtering
	if cfg.DNSFilter {
		add("-p", "udp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(QueueDNS), "--queue-bypass")
		add("-p", "tcp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(QueueDNS), "--queue-bypass")
	}
	// 6) SNI / Host filtering: only the first packets of a TCP flow
	if cfg.SNIFilter {
		for _, port := range []string{"443", "8443", "80"} {
			add("-p", "tcp", "--dport", port,
				"-m", "connbytes", "--connbytes", "1:8", "--connbytes-dir", "original", "--connbytes-mode", "packets",
				"-j", "NFQUEUE", "--queue-num", strconv.Itoa(QueueSNI), "--queue-bypass")
		}
	}
	// hook into OUTPUT (checked/inserted by caller)
	return cmds
}

// hookCommand inserts the OUTPUT jump if missing.
func hookCommand() []string {
	return []string{"-w", "-t", "mangle", "-I", "OUTPUT", "1", "-j", ChainName}
}

func hookCheckCommand() []string {
	return []string{"-w", "-t", "mangle", "-C", "OUTPUT", "-j", ChainName}
}

// teardownCommands removes the OUTPUT jump and deletes ChainName.
func teardownCommands() [][]string {
	return [][]string{
		{"-w", "-t", "mangle", "-D", "OUTPUT", "-j", ChainName},
		{"-w", "-t", "mangle", "-F", ChainName},
		{"-w", "-t", "mangle", "-X", ChainName},
	}
}
