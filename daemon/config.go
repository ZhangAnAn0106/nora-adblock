package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Config mirrors /data/adb/nora_adblock/config (KEY=VALUE).
type Config struct {
	Enabled    bool
	DNSFilter  bool
	SNIFilter  bool
	Logging    bool     // LOGGING: gates daemon.log + blocked.log writes; counts are independent
	ProxyUIDs  []int    // static uids from PROXY_UIDS (0 = root, the proxy core)
	ProxyPkgs  []string // packages whose uid is resolved at runtime (BoxProxy app)
	ProxyMarks []uint32 // fwmarks used by the proxy core (coexistence exemptions)
}

// DefaultConfig carries the BoxProxy coexistence defaults: the proxy core
// runs as root (uid 0); its traffic marks are 16777216 (0x1000000),
// 33554432 (0x2000000), 50331648 (0x3000000).
func DefaultConfig() Config {
	return Config{
		Enabled:    true,
		DNSFilter:  true,
		SNIFilter:  true,
		Logging:    true,
		ProxyUIDs:  []int{0},
		ProxyPkgs:  []string{"com.boxproxy.box"},
		ProxyMarks: []uint32{16777216, 33554432, 50331648},
	}
}

func loadConfig(path string) Config {
	cfg := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "ENABLED":
			cfg.Enabled = v == "1"
		case "DNS_FILTER":
			cfg.DNSFilter = v == "1"
		case "SNI_FILTER":
			cfg.SNIFilter = v == "1"
		case "LOGGING":
			cfg.Logging = v == "1"
		case "PROXY_UIDS":
			cfg.ProxyUIDs = parseIntList(v)
		case "PROXY_PACKAGES":
			cfg.ProxyPkgs = parseStringList(v)
		case "PROXY_MARKS":
			var marks []uint32
			for _, n := range parseIntList(v) {
				if n >= 0 {
					marks = append(marks, uint32(n))
				}
			}
			cfg.ProxyMarks = marks
		}
	}
	return cfg
}

func parseIntList(v string) []int {
	var out []int
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func parseStringList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// packagesListPath is Android's package->uid registry.
var packagesListPath = "/data/system/packages.list"

// resolvePackageUIDs reads packages.list and returns uids for the wanted packages.
func resolvePackageUIDs(pkgs []string) []int {
	if len(pkgs) == 0 {
		return nil
	}
	want := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		want[p] = true
	}
	f, err := os.Open(packagesListPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && want[fields[0]] {
			if uid, err := strconv.Atoi(fields[1]); err == nil {
				out = append(out, uid)
			}
		}
	}
	return out
}

// exemptUIDSet merges static proxy uids with runtime-resolved package uids.
func exemptUIDSet(cfg Config) map[int]bool {
	set := make(map[int]bool)
	for _, uid := range cfg.ProxyUIDs {
		set[uid] = true
	}
	for _, uid := range resolvePackageUIDs(cfg.ProxyPkgs) {
		set[uid] = true
	}
	return set
}

func sortedUIDs(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for uid := range set {
		out = append(out, uid)
	}
	// small N; simple insertion sort keeps imports light
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
