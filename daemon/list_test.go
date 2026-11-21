package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDomainSetSuffixMatch(t *testing.T) {
	ds := NewDomainSet()
	ds.Add("example.com")
	ds.Add("ads.foo.net")
	ds.Add("*.wild.org")
	cases := map[string]bool{
		"example.com":       true,
		"a.example.com":     true,
		"a.b.example.com":   true,
		"notexample.com":    false,
		"example.com.evil.": false,
		"foo.net":           false,
		"x.ads.foo.net":     true,
		"anything.wild.org": true,
		"wild.org":          true,
		"EXAMPLE.com":       true,
	}
	for name, want := range cases {
		if got := ds.Match(name); got != want {
			t.Errorf("Match(%q)=%v want %v", name, got, want)
		}
	}
}

func writeList(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func bumpMtime(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	nt := st.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(p, nt, nt); err != nil {
		t.Fatal(err)
	}
}

func TestListPriorityAndReload(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, "blocklist.txt", "# anti-AD snapshot\nqq.com\nads.example.com\n")
	writeList(t, dir, "whitelist.txt", "tmgp.qq.com\nexample.com\n")
	writeList(t, dir, "user_blocklist.txt", "example.com\nuserblocked.net\n")
	writeList(t, dir, "user_whitelist.txt", "ads.example.com\n")

	lm := NewListManager(dir)
	if !lm.ReloadIfChanged() {
		t.Fatal("initial load not reported as change")
	}
	checks := map[string]bool{
		// user whitelist beats built-in blocklist
		"ads.example.com": false,
		"x.ads.example.com": false,
		// built-in whitelist beats user blocklist (example.com is in both)
		"www.example.com": false,
		// built-in whitelist protects game domains under a blocked parent
		"tmgp.qq.com":     false,
		"login.tmgp.qq.com": false,
		// user blocklist blocks on its own
		"userblocked.net":     true,
		"cdn.userblocked.net": true,
		// built-in blocklist blocks
		"other.qq.com": true,
		// untouched
		"unrelated.org": false,
	}
	for name, want := range checks {
		if got := lm.Blocked(name); got != want {
			t.Errorf("Blocked(%q)=%v want %v", name, got, want)
		}
	}

	// hot reload of the user blocklist
	writeList(t, dir, "user_blocklist.txt", "example.com\nuserblocked.net\nnewad.net\n")
	bumpMtime(t, dir, "user_blocklist.txt")
	if !lm.ReloadIfChanged() {
		t.Fatal("reload after edit not detected")
	}
	if !lm.Blocked("newad.net") {
		t.Error("newad.net should be blocked after reload")
	}
	// no change -> no reload
	if lm.ReloadIfChanged() {
		t.Error("unchanged files reported as changed")
	}
}
