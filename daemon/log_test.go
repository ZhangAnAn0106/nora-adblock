package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setLogging(t *testing.T, on bool) {
	t.Helper()
	old := loggingOn.Load()
	loggingOn.Store(on)
	t.Cleanup(func() { loggingOn.Store(old) })
}

func TestConfigLoggingParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")

	// absent key -> default on
	if err := os.WriteFile(p, []byte("ENABLED=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !loadConfig(p).Logging {
		t.Error("LOGGING absent should default to true")
	}
	if err := os.WriteFile(p, []byte("LOGGING=0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if loadConfig(p).Logging {
		t.Error("LOGGING=0 should parse to false")
	}
	if err := os.WriteFile(p, []byte("LOGGING=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !loadConfig(p).Logging {
		t.Error("LOGGING=1 should parse to true")
	}
}

func TestLogfGatedBySwitch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NORA_ADBLOCK_DIR", dir)
	logPath := filepath.Join(dir, "daemon.log")

	setLogging(t, false)
	logf("should not be written")
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("daemon.log must not be created while LOGGING=0 (stat err=%v)", err)
	}

	setLogging(t, true)
	logf("hello daemon")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("daemon.log should exist while LOGGING=1: %v", err)
	}
	if !strings.Contains(string(b), "hello daemon") {
		t.Errorf("daemon.log missing logged line, got %q", string(b))
	}
}

func TestCountsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	setLogging(t, true)

	b := newBlockLog(dir)
	b.record("ads.example.com")
	b.record("ads.example.com")
	b.record("tracker.example.net")
	b.flush(100, 5)

	if _, err := os.Stat(filepath.Join(dir, statsFileName)); err != nil {
		t.Fatalf("blocked_stats not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "blocked.log")); err != nil {
		t.Fatalf("blocked.log detail should be written while LOGGING=1: %v", err)
	}

	// simulate daemon restart: a fresh blockLog must restore today's counts
	b2 := newBlockLog(dir)
	_, total, unique := b2.snapshot()
	if total != 3 || unique != 2 {
		t.Errorf("restored counts wrong: total=%d unique=%d, want 3/2", total, unique)
	}
	if got := b2.countOf("ads.example.com"); got != 2 {
		t.Errorf("restored per-domain count wrong: %d, want 2", got)
	}
}

func TestCountsContinueWithLoggingOff(t *testing.T) {
	dir := t.TempDir()
	setLogging(t, false)

	b := newBlockLog(dir)
	b.record("ads.example.com")
	b.record("ads.example.com")
	b.flush(100, 5)

	// counts file is the panel's data source: written regardless of LOGGING
	raw, err := os.ReadFile(filepath.Join(dir, statsFileName))
	if err != nil {
		t.Fatalf("blocked_stats must be written while LOGGING=0: %v", err)
	}
	if !strings.Contains(string(raw), "total=2") || !strings.Contains(string(raw), "ads.example.com 2") {
		t.Errorf("blocked_stats missing counts, got:\n%s", string(raw))
	}
	// but the detail log stays off
	if _, err := os.Stat(filepath.Join(dir, "blocked.log")); !os.IsNotExist(err) {
		t.Errorf("blocked.log must not be written while LOGGING=0 (stat err=%v)", err)
	}
	if _, total, _ := b.snapshot(); total != 2 {
		t.Errorf("in-memory total wrong: %d, want 2", total)
	}
}

func TestStatsStaleDayStartsFresh(t *testing.T) {
	dir := t.TempDir()
	stale := "date=2000-01-01\ntotal=9\nunique=1\nrules=1\nwhitelist=1\nold.example.com 9\n"
	if err := os.WriteFile(filepath.Join(dir, statsFileName), []byte(stale), 0644); err != nil {
		t.Fatal(err)
	}
	b := newBlockLog(dir)
	_, total, unique := b.snapshot()
	if total != 0 || unique != 0 {
		t.Errorf("stale-day stats must be discarded, got total=%d unique=%d", total, unique)
	}
}

func TestDomainCapEvictsLeastHit(t *testing.T) {
	dir := t.TempDir()
	b := newBlockLog(dir)
	for i := 0; i < 5; i++ {
		b.record("keep.example.com")
	}
	for i := 0; i < 600; i++ {
		b.record(fmt.Sprintf("d%d.example.com", i))
	}
	_, _, unique := b.snapshot()
	if unique > maxCountDomains {
		t.Errorf("domain cap violated: unique=%d > %d", unique, maxCountDomains)
	}
	if got := b.countOf("keep.example.com"); got != 5 {
		t.Errorf("most-hit domain must survive eviction, countOf=%d, want 5", got)
	}
}
