package main

import (
	"strings"
	"testing"
)

// v1.0.8: filter switches are hot-swapped by re-applying rules built
// from the new config. For every DNS/SNI/QUIC combination the generated
// rule set must match the switches exactly — in particular, turning
// QUIC off must leave no UDP 443 DROP behind, and turning DNS or SNI
// off must leave no NFQUEUE routing for it.
func TestSetupCommandsFollowFilterSwitches(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dns, sni bool
		quic     bool
	}{
		{"all on", true, true, true},
		{"all off", false, false, false},
		{"dns only", true, false, false},
		{"sni only", false, true, false},
		{"quic only", false, false, true},
		{"dns+sni", true, true, false},
		{"dns+quic", true, false, true},
		{"sni+quic", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DNSFilter = tc.dns
			cfg.SNIFilter = tc.sni
			cfg.QUICFilter = tc.quic
			lines := joinCmds(setupCommands(cfg, []int{0}, false))

			if got := indexOf(lines, "-p udp --dport 53 -j NFQUEUE") >= 0; got != tc.dns {
				t.Errorf("udp DNS queue rule present=%v, want %v", got, tc.dns)
			}
			if got := indexOf(lines, "-p tcp --dport 53 -j NFQUEUE") >= 0; got != tc.dns {
				t.Errorf("tcp DNS queue rule present=%v, want %v", got, tc.dns)
			}
			if got := indexOf(lines, "-p tcp --dport 443") >= 0; got != tc.sni {
				t.Errorf("tcp 443 SNI queue rule present=%v, want %v", got, tc.sni)
			}
			if got := indexOf(lines, "-p tcp --dport 80") >= 0; got != tc.sni {
				t.Errorf("tcp 80 Host queue rule present=%v, want %v", got, tc.sni)
			}
			if got := indexOf(lines, "-p udp --dport 443 -j DROP") >= 0; got != tc.quic {
				t.Errorf("QUIC DROP rule present=%v, want %v", got, tc.quic)
			}
			// the chain is always rebuilt from scratch (-N then -F), so a
			// re-apply can never leave rules from the previous config behind
			if len(lines) < 2 || !strings.Contains(lines[1], "-F "+ChainName) {
				t.Errorf("second command should flush the chain, got %v", lines[:2])
			}
			// exemptions are independent of the filter switches
			if indexOf(lines, "-o lo -j RETURN") < 0 {
				t.Error("loopback exemption missing")
			}
		})
	}
}

// The maintenance ticks detect filter changes by comparing the freshly
// loaded config against the daemon's live config; syncSwitches must
// report a change exactly once per flip and fold the new values in.
func TestSyncSwitchesDetectsFilterChanges(t *testing.T) {
	loggingOn.Store(true)
	defer loggingOn.Store(true)

	d := &daemon{
		cfg:    DefaultConfig(), // dns/sni/quic/logging on
		exempt: map[int]bool{0: true},
	}

	nc := DefaultConfig()
	if d.syncSwitches(nc) {
		t.Fatal("identical config reported as filter change")
	}

	nc.QUICFilter = false
	if !d.syncSwitches(nc) {
		t.Fatal("QUIC flip not detected")
	}
	if d.cfg.QUICFilter {
		t.Fatal("daemon config not updated after QUIC flip")
	}
	if d.syncSwitches(nc) {
		t.Fatal("same config reported as changed twice")
	}

	nc.DNSFilter = false
	nc.SNIFilter = false
	if !d.syncSwitches(nc) {
		t.Fatal("DNS/SNI flip not detected")
	}
	if d.cfg.DNSFilter || d.cfg.SNIFilter {
		t.Fatal("daemon config not updated after DNS/SNI flip")
	}

	// flipping back on is a change too
	nc.DNSFilter = true
	if !d.syncSwitches(nc) {
		t.Fatal("DNS flip back on not detected")
	}

	// non-filter switches never count as a filter change
	nc.Logging = false
	if d.syncSwitches(nc) {
		t.Fatal("LOGGING flip reported as filter change")
	}
}
