package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// boxProxyStateFile records the BoxProxy detection result in the data dir.
// It is runtime state, NOT user config: customize.sh writes it at install
// time and the daemon refreshes it on every startup (and whenever the
// result flips while running).
const boxProxyStateFile = "boxproxy.state"

// appDataDirPrefix is where Android keeps per-app data directories; an
// installed package has one even if packages.list cannot be read.
// (var so tests can point it at a fixture tree)
var appDataDirPrefix = "/data/data"

// detectBoxProxy reports whether any of pkgs (the configured proxy
// packages, com.boxproxy.box by default) is installed. Two independent
// paths: the packages.list registry, then the per-app data directory.
func detectBoxProxy(pkgs []string) bool {
	if len(resolvePackageUIDs(pkgs)) > 0 {
		return true
	}
	for _, p := range pkgs {
		if st, err := os.Stat(filepath.Join(appDataDirPrefix, p)); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

func boxProxyWord(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

func exemptionsWord(present bool) string {
	if present {
		return "on"
	}
	return "off"
}

// writeBoxProxyState persists the latest detection result:
// boxproxy=present|absent, exemptions=on|off, checked=<timestamp>.
func writeBoxProxyState(dir string, present bool) {
	content := "boxproxy=" + boxProxyWord(present) + "\n" +
		"exemptions=" + exemptionsWord(present) + "\n" +
		"checked=" + time.Now().Format("2006-01-02 15:04:05") + "\n"
	_ = os.WriteFile(filepath.Join(dir, boxProxyStateFile), []byte(content), 0644)
}

// readBoxProxyState returns the previously recorded result; ok=false when
// no state file exists yet (e.g. daemon runs before any install wrote one).
func readBoxProxyState(dir string) (present bool, ok bool) {
	b, err := os.ReadFile(filepath.Join(dir, boxProxyStateFile))
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "boxproxy=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "boxproxy=")) == "present", true
		}
	}
	return false, false
}
