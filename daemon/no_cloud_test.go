package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v1.1.1 removed the cloud rule subscription feature end to end. These
// assertions keep it from creeping back: the panel must not carry the
// subscription card or any of its element ids, the WebUI backend must
// not expose the cloud commands or config keys, and the package must
// not ship the preset sources file.
func TestNoCloudRemnants(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "module", "webroot", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"规则订阅",
		`id="swCloud"`, `id="swCloudAuto"`, `id="taSources"`,
		`id="btnSaveSources"`, `id="btnUpdateRules"`, `id="btnCloudStatus"`,
		`id="btnClearCloud"`, `id="cloudList"`, `id="cloudSummary"`, `id="stCloud"`,
		"get-sources", "sources-status", "cloud_rules", "cloud_total",
	} {
		if strings.Contains(string(panel), bad) {
			t.Errorf("panel still contains cloud remnant %q", bad)
		}
	}

	backend, err := os.ReadFile(filepath.Join("..", "module", "adblock.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"get-sources", "save-sources", "update-rules", "sources-status",
		"clear-cloud", "CLOUD_RULES", "CLOUD_AUTO", "cloud_blocklist",
		"rule_sources", "cloud_status", "cloud_request",
	} {
		if strings.Contains(string(backend), bad) {
			t.Errorf("adblock.sh still contains cloud remnant %q", bad)
		}
	}

	if _, err := os.Stat(filepath.Join("..", "module", "data", "rule_sources.txt")); !os.IsNotExist(err) {
		t.Errorf("module/data/rule_sources.txt must not be shipped (stat err = %v)", err)
	}
}
