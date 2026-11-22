package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v1.1.0: the daemon must stop ITSELF when a maintenance tick sees
// ENABLED=0 — before this, the only stop path was adblock.sh's --stop
// signal, and a timed-out/failed stop left config=0 with the daemon
// (and the blocking) still alive: "总开关关不掉拦截".
func TestEnabledExitWanted(t *testing.T) {
	for _, tc := range []struct {
		start, now, want bool
	}{
		{true, false, true},   // running daemon, config turned off -> exit
		{true, true, false},   // still enabled -> keep running
		{false, false, false}, // never started enabled -> predicate stays inert
		{false, true, false},
	} {
		if got := enabledExitWanted(tc.start, tc.now); got != tc.want {
			t.Errorf("enabledExitWanted(%v, %v) = %v, want %v", tc.start, tc.now, got, tc.want)
		}
	}
}

// The fast tick is the ~2s beat the panel's total switch relies on:
// with ENABLED=0 in the config file it must request shutdown (and skip
// the rest of the tick); with ENABLED=1 it must not.
func TestFastTickRequestsStopOnEnabledOff(t *testing.T) {
	loggingOn.Store(true)
	defer loggingOn.Store(true)

	writeCfg := func(t *testing.T, enabled string) string {
		t.Helper()
		dir := t.TempDir()
		cfg := "ENABLED=" + enabled + "\nDNS_FILTER=1\nSNI_FILTER=1\nQUIC_FILTER=1\nLOGGING=1\n"
		if err := os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	newDaemon := func(stopped *bool) *daemon {
		return &daemon{
			cfg:    DefaultConfig(), // started enabled, all filters on
			exempt: map[int]bool{0: true},
			requestStop: func() {
				*stopped = true
			},
		}
	}

	stopped := false
	newDaemon(&stopped).fastTick(writeCfg(t, "0"))
	if !stopped {
		t.Fatal("fast tick with ENABLED=0 did not request daemon stop")
	}

	stopped = false
	newDaemon(&stopped).fastTick(writeCfg(t, "1"))
	if stopped {
		t.Fatal("fast tick with ENABLED=1 wrongly requested daemon stop")
	}

	// slow tick shares the same guard
	stopped = false
	d := newDaemon(&stopped)
	d.lists = NewListManager(writeCfg(t, "0"))
	d.blog = newBlockLog(t.TempDir())
	dir := writeCfg(t, "0")
	// slowTick loads its config from dir; noteEnabled must fire before
	// any of the heavier slow-tick work needs real lists/blog state.
	d.slowTick(dir)
	if !stopped {
		t.Fatal("slow tick with ENABLED=0 did not request daemon stop")
	}
}
