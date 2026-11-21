package main

import (
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
	// no BoxProxy-specific exemptions at all
	for _, bad := range []string{"--mark", "--uid-owner 10234"} {
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
