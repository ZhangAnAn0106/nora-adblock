package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Timestamps must survive the full record -> flush -> reload round trip.
func TestStatsRoundTripWithTimestamps(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Unix()

	b := newBlockLog(dir)
	b.record("ads.example.com")
	b.record("ads.example.com")
	b.record("tracker.example.net")
	// pin deterministic last-seen times (record() stamps "now" for both)
	b.lastSeen["ads.example.com"] = base - 600
	b.lastSeen["tracker.example.net"] = base - 60
	b.flush(100, 5)

	raw, err := os.ReadFile(filepath.Join(dir, statsFileName))
	if err != nil {
		t.Fatalf("blocked_stats not written: %v", err)
	}
	if !strings.Contains(string(raw), "ads.example.com 2 "+strconv.FormatInt(base-600, 10)) {
		t.Errorf("stats line missing count+timestamp, got:\n%s", string(raw))
	}

	b2 := newBlockLog(dir)
	if got := b2.countOf("ads.example.com"); got != 2 {
		t.Errorf("restored count wrong: %d, want 2", got)
	}
	if got := b2.lastOf("ads.example.com"); got != base-600 {
		t.Errorf("restored lastSeen wrong: %d, want %d", got, base-600)
	}
	if got := b2.lastOf("tracker.example.net"); got != base-60 {
		t.Errorf("restored lastSeen wrong: %d, want %d", got, base-60)
	}
}

// Legacy stats files (pre-1.0.4, "domain count" with no timestamp) must
// load with counts intact and lastSeen = 0, never dropping the day's data.
func TestStatsLegacyFormatCompat(t *testing.T) {
	dir := t.TempDir()
	legacy := "date=" + today() + "\ntotal=7\nunique=2\nrules=1\nwhitelist=1\nold.example.com 4\nolder.example.net 3\n"
	if err := os.WriteFile(filepath.Join(dir, statsFileName), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	b := newBlockLog(dir)
	_, total, unique := b.snapshot()
	if total != 7 || unique != 2 {
		t.Errorf("legacy counts must be restored, got total=%d unique=%d, want 7/2", total, unique)
	}
	if got := b.countOf("old.example.com"); got != 4 {
		t.Errorf("legacy per-domain count wrong: %d, want 4", got)
	}
	if got := b.lastOf("old.example.com"); got != 0 {
		t.Errorf("legacy domain must have lastSeen=0, got %d", got)
	}
	// and a flush upgrades the file to the 3-field format without loss
	b.flush(1, 1)
	raw, err := os.ReadFile(filepath.Join(dir, statsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "old.example.com 4 0") {
		t.Errorf("legacy domain should be rewritten with timestamp 0, got:\n%s", string(raw))
	}
}

// The stats file's domain lines must come out most-recently-blocked first.
func TestStatsFileSortedByRecent(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Unix()

	b := newBlockLog(dir)
	for i := 0; i < 5; i++ {
		b.record("frequent.example.com") // highest count, oldest hit
	}
	b.record("mid.example.com")
	b.record("newest.example.com") // lowest count, most recent hit
	b.lastSeen["frequent.example.com"] = base - 3600
	b.lastSeen["mid.example.com"] = base - 600
	b.lastSeen["newest.example.com"] = base - 10
	b.flush(100, 5)

	raw, err := os.ReadFile(filepath.Join(dir, statsFileName))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			order = append(order, f[0])
		}
	}
	want := []string{"newest.example.com", "mid.example.com", "frequent.example.com"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("recent order wrong: got %v, want %v", order, want)
	}
}

// sortedRecent tie-breaking: equal timestamps fall back to count desc.
func TestSortedRecentOrder(t *testing.T) {
	counts := map[string]int{"a.example.com": 1, "b.example.com": 9, "c.example.com": 9, "d.example.com": 3}
	last := map[string]int64{
		"a.example.com": 300,
		"b.example.com": 100,
		"c.example.com": 100,
		"d.example.com": 200,
	}
	got := sortedRecent(counts, last)
	want := []string{"a.example.com", "d.example.com", "b.example.com", "c.example.com"}
	if len(got) != len(want) {
		t.Fatalf("sortedRecent len=%d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].domain != w {
			t.Errorf("position %d: got %s, want %s", i, got[i].domain, w)
		}
	}
	// unknown (legacy) domains have last=0 and sink to the bottom
	got = sortedRecent(map[string]int{"x.example.com": 5}, map[string]int64{})
	if len(got) != 1 || got[0].last != 0 {
		t.Errorf("missing timestamp must yield last=0, got %+v", got)
	}
}
