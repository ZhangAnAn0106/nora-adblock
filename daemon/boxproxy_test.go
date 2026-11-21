package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withFixtures points packagesListPath and appDataDirPrefix at a temp tree
// and restores them afterwards.
func withFixtures(t *testing.T, listContent string) string {
	t.Helper()
	dir := t.TempDir()
	listPath := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(listPath, []byte(listContent), 0644); err != nil {
		t.Fatal(err)
	}
	dataPrefix := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataPrefix, 0755); err != nil {
		t.Fatal(err)
	}
	oldList, oldPrefix := packagesListPath, appDataDirPrefix
	packagesListPath, appDataDirPrefix = listPath, dataPrefix
	t.Cleanup(func() { packagesListPath, appDataDirPrefix = oldList, oldPrefix })
	return dataPrefix
}

func TestDetectBoxProxyPresentInPackagesList(t *testing.T) {
	withFixtures(t, "com.example.app 10123 0 /data/data/com.example.app\ncom.boxproxy.box 10234 0 /data/data/com.boxproxy.box\n")
	if !detectBoxProxy([]string{"com.boxproxy.box"}) {
		t.Error("BoxProxy listed in packages.list must be detected as present")
	}
}

func TestDetectBoxProxyAbsent(t *testing.T) {
	withFixtures(t, "com.example.app 10123 0 /data/data/com.example.app\n")
	if detectBoxProxy([]string{"com.boxproxy.box"}) {
		t.Error("BoxProxy must be absent when neither packages.list nor data dir has it")
	}
}

func TestDetectBoxProxyPresentViaDataDir(t *testing.T) {
	prefix := withFixtures(t, "com.example.app 10123 0 /data/data/com.example.app\n")
	if err := os.MkdirAll(filepath.Join(prefix, "com.boxproxy.box"), 0755); err != nil {
		t.Fatal(err)
	}
	if !detectBoxProxy([]string{"com.boxproxy.box"}) {
		t.Error("BoxProxy data dir alone must count as present (fallback path)")
	}
}

func TestBoxProxyStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readBoxProxyState(dir); ok {
		t.Error("missing state file must report ok=false")
	}
	writeBoxProxyState(dir, true)
	if p, ok := readBoxProxyState(dir); !ok || !p {
		t.Errorf("state after write(present): got present=%v ok=%v", p, ok)
	}
	writeBoxProxyState(dir, false)
	if p, ok := readBoxProxyState(dir); !ok || p {
		t.Errorf("state after write(absent): got present=%v ok=%v", p, ok)
	}
}
