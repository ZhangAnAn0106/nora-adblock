package main

import (
	"strconv"
	"strings"
	"testing"

	nfqueue "github.com/florianl/go-nfqueue"
)

func joinCmds(cmds [][]string) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func indexOf(lines []string, substr string) int {
	for i, l := range lines {
		if strings.Contains(l, substr) {
			return i
		}
	}
	return -1
}

func TestSetupCommandsExemptionsFirst(t *testing.T) {
	cfg := DefaultConfig()
	uids := []int{0, 10234} // root (core) + resolved BoxProxy app uid
	lines := joinCmds(setupCommands(cfg, uids, true))

	firstQueue := indexOf(lines, "NFQUEUE")
	if firstQueue < 0 {
		t.Fatal("no NFQUEUE rule generated")
	}
	// every exemption must precede the first NFQUEUE rule
	for _, want := range []string{
		"-o lo -j RETURN",
		"--mark 16777216/16777216 -j RETURN", // proxy TPROXY mark
		"--mark 33554432/33554432 -j RETURN",
		"--mark 50331648/50331648 -j RETURN",
		"--uid-owner 0 -j RETURN",
		"--uid-owner 10234 -j RETURN",
	} {
		i := indexOf(lines, want)
		if i < 0 {
			t.Errorf("missing rule %q", want)
		} else if i > firstQueue {
			t.Errorf("exemption %q comes after first NFQUEUE rule", want)
		}
	}
	// DNS + SNI queues present, all with bypass
	for _, want := range []string{
		"--dport 53 -j NFQUEUE --queue-num 0 --queue-bypass",
		"--dport 443",
		"--dport 8443",
		"--dport 80",
		"--queue-num 1 --queue-bypass",
		"--connbytes 1:8",
	} {
		if indexOf(lines, want) < 0 {
			t.Errorf("missing rule fragment %q", want)
		}
	}
	// chain name is ours only
	if !strings.Contains(lines[0], "-N "+ChainName) {
		t.Errorf("first command should create %s, got %q", ChainName, lines[0])
	}
}

func TestSetupCommandsFiltersOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSFilter = false
	cfg.SNIFilter = false
	lines := joinCmds(setupCommands(cfg, []int{0}, true))
	if indexOf(lines, "NFQUEUE") >= 0 {
		t.Error("NFQUEUE rules present although both filters are off")
	}
	if indexOf(lines, "--uid-owner 0 -j RETURN") < 0 {
		t.Error("exemptions should still be generated")
	}
}

func TestSetupCommandsBoxProxyAbsent(t *testing.T) {
	cfg := DefaultConfig()
	// even if a stale app uid is handed in, absent mode must not emit it
	lines := joinCmds(setupCommands(cfg, []int{0, 10234}, false))
	// no BoxProxy-specific exemptions at all (packet-mark matches are the
	// proxy exemptions; "-m connmark --mark" is our own fast path, not one)
	for _, bad := range []string{"-m mark --mark", "--uid-owner 10234"} {
		if i := indexOf(lines, bad); i >= 0 {
			t.Errorf("BoxProxy exemption %q emitted although BoxProxy is absent: %q", bad, lines[i])
		}
	}
	// generic safety exemptions stay
	if indexOf(lines, "-o lo -j RETURN") < 0 {
		t.Error("loopback exemption must stay in absent mode")
	}
	if indexOf(lines, "--uid-owner 0 -j RETURN") < 0 {
		t.Error("uid 0 exemption must stay in absent mode")
	}
	// filtering itself is unaffected
	if indexOf(lines, "NFQUEUE") < 0 {
		t.Error("NFQUEUE rules missing in absent mode")
	}
}

func TestTeardownCommands(t *testing.T) {
	lines := joinCmds(teardownCommands())
	for _, want := range []string{"-D OUTPUT -j " + ChainName, "-F " + ChainName, "-X " + ChainName} {
		if indexOf(lines, want) < 0 {
			t.Errorf("teardown missing %q", want)
		}
	}
}

func TestDaemonMarkExemption(t *testing.T) {
	d := &daemon{cfg: DefaultConfig(), exempt: map[int]bool{0: true, 10234: true}}
	d.bpPresent.Store(true)
	mark := uint32(16777216)
	if !d.isExempt(nfqueue.Attribute{Mark: &mark}) {
		t.Error("BoxProxy tproxy mark must be exempt")
	}
	other := uint32(12345)
	if d.isExempt(nfqueue.Attribute{Mark: &other}) {
		t.Error("unrelated mark must not be exempt")
	}
	uid := uint32(0)
	if !d.isExempt(nfqueue.Attribute{UID: &uid}) {
		t.Error("root uid (proxy core) must be exempt")
	}
	appUID := uint32(10555)
	if d.isExempt(nfqueue.Attribute{UID: &appUID}) {
		t.Error("random app uid must not be exempt")
	}
	boxUID := uint32(10234)
	if !d.isExempt(nfqueue.Attribute{UID: &boxUID}) {
		t.Error("BoxProxy app uid must be exempt when present")
	}
}

func TestDaemonExemptionBoxProxyAbsent(t *testing.T) {
	// stale exempt set on purpose: absent mode must ignore marks and app uids
	d := &daemon{cfg: DefaultConfig(), exempt: map[int]bool{0: true, 10234: true}}
	d.bpPresent.Store(false)
	mark := uint32(16777216)
	if d.isExempt(nfqueue.Attribute{Mark: &mark}) {
		t.Error("BoxProxy mark must NOT be exempt when BoxProxy is absent")
	}
	boxUID := uint32(10234)
	if d.isExempt(nfqueue.Attribute{UID: &boxUID}) {
		t.Error("BoxProxy app uid must NOT be exempt when BoxProxy is absent")
	}
	uid := uint32(0)
	if !d.isExempt(nfqueue.Attribute{UID: &uid}) {
		t.Error("root uid must stay exempt even when BoxProxy is absent")
	}
}

func TestSetupCommandsQUICFilter(t *testing.T) {
	// default config: QUIC on — UDP 443 DROP present, after exemptions
	cfg := DefaultConfig()
	if !cfg.QUICFilter {
		t.Fatal("QUIC_FILTER must default to on")
	}
	lines := joinCmds(setupCommands(cfg, []int{0, 10234}, true))
	i := indexOf(lines, "-p udp --dport 443 -j DROP")
	if i < 0 {
		t.Fatal("QUIC DROP rule missing although QUIC_FILTER is on")
	}
	if e := indexOf(lines, "--uid-owner 0 -j RETURN"); e < 0 || e > i {
		t.Error("QUIC DROP rule must come after the uid exemptions")
	}
	if e := indexOf(lines, "-o lo -j RETURN"); e < 0 || e > i {
		t.Error("QUIC DROP rule must come after the loopback exemption")
	}
	// QUIC off: no UDP 443 DROP at all
	cfg.QUICFilter = false
	lines = joinCmds(setupCommands(cfg, []int{0}, true))
	if i := indexOf(lines, "--dport 443 -j DROP"); i >= 0 {
		t.Errorf("UDP 443 DROP emitted although QUIC_FILTER is off: %q", lines[i])
	}
	if i := indexOf(lines, "-p udp --dport 443"); i >= 0 {
		t.Errorf("any UDP 443 rule emitted although QUIC_FILTER is off: %q", lines[i])
	}
}

// v1.0.9 connmark fast path: decided connections must be resolved in
// the kernel — after every exemption, before QUIC and before the first
// queue rule.
func TestSetupCommandsConnMarkFastPath(t *testing.T) {
	cfg := DefaultConfig()
	lines := joinCmds(setupCommands(cfg, []int{0, 10234}, true))

	allow := "-m connmark --mark " + strconv.FormatUint(uint64(ConnMarkAllow), 10) + "/4294967295 -j RETURN"
	block := "-m connmark --mark " + strconv.FormatUint(uint64(ConnMarkBlock), 10) + "/4294967295 -j DROP"
	ia, ib := indexOf(lines, allow), indexOf(lines, block)
	if ia < 0 || ib < 0 {
		t.Fatalf("connmark rules missing: allow=%d block=%d in %v", ia, ib, lines)
	}
	if ia > ib {
		t.Error("connmark allow rule must precede the block rule")
	}
	// every exemption precedes the connmark rules
	for _, want := range []string{
		"-o lo -j RETURN",
		"--mark 16777216/16777216 -j RETURN",
		"--uid-owner 0 -j RETURN",
		"--uid-owner 10234 -j RETURN",
	} {
		if i := indexOf(lines, want); i < 0 || i > ia {
			t.Errorf("exemption %q must precede connmark rules (at %d, allow at %d)", want, i, ia)
		}
	}
	// connmark rules precede QUIC DROP and the first NFQUEUE rule
	if q := indexOf(lines, "-p udp --dport 443 -j DROP"); q < 0 || ib > q {
		t.Error("connmark rules must precede the QUIC DROP rule")
	}
	if n := indexOf(lines, "NFQUEUE"); n < 0 || ib > n {
		t.Error("connmark rules must precede the first NFQUEUE rule")
	}
	// the fast path is independent of the filter switches and of
	// BoxProxy presence: decided flows skip the queues either way
	lines = joinCmds(setupCommands(cfg, []int{0}, false))
	if indexOf(lines, allow) < 0 || indexOf(lines, block) < 0 {
		t.Error("connmark rules must be emitted without BoxProxy too")
	}
}

func TestConnMarkValuesUnique(t *testing.T) {
	if ConnMarkAllow == 0 || ConnMarkBlock == 0 {
		t.Fatal("connmark values must be non-zero (0 means 'no mark')")
	}
	if ConnMarkAllow == ConnMarkBlock {
		t.Fatal("allow and block connmarks must differ")
	}
	for _, m := range DefaultConfig().ProxyMarks {
		if ConnMarkAllow == m || ConnMarkBlock == m {
			t.Fatalf("connmark collides with BoxProxy packet mark %d", m)
		}
	}
}

// applyRules rebuilds the chain from scratch (-N tolerated, then -F),
// so re-applying the same config can never duplicate or strand rules:
// the generated sequence must be deterministic across calls.
func TestSetupCommandsDeterministicRebuild(t *testing.T) {
	cfg := DefaultConfig()
	a := joinCmds(setupCommands(cfg, []int{0, 10234}, true))
	b := joinCmds(setupCommands(cfg, []int{0, 10234}, true))
	if len(a) != len(b) {
		t.Fatalf("rule count differs across rebuilds: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("rule %d differs across rebuilds: %q vs %q", i, a[i], b[i])
		}
	}
	if !strings.Contains(a[1], "-F "+ChainName) {
		t.Errorf("second command must flush the chain, got %q", a[1])
	}
	// exactly one connmark allow and one connmark block rule per rebuild
	n := 0
	for _, l := range a {
		if strings.Contains(l, "-m connmark") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want exactly 2 connmark rules, got %d", n)
	}
}
