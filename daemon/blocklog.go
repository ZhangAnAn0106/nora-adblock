package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// statsFileName is the dedicated counts store: the WebUI's only data source
// for 今日拦截 / 最近拦截. It is deliberately decoupled from the log files —
// counts accumulate whether or not LOGGING is on.
const statsFileName = "blocked_stats"

// Hard caps so data files can never grow unbounded:
//   - daemon.log / blocked.log: maxLogBytes each, one rotated backup kept
//     (2 files x (current + backup) x 512 KiB = ~2 MiB total).
//   - blocked_stats: today only, at most maxCountDomains domains.
const (
	maxLogBytes     = 512 << 10
	maxCountDomains = 500
)

// blockLog counts blocked domains (never payloads). Cumulative per-domain
// counts for today are persisted to blocked_stats on every flush and restored
// on startup, so they survive daemon restarts. blocked.log is only a detail
// log (one aggregated batch per flush) and is written solely when logging is
// enabled; the counts never depend on it.
// statsFlushInterval throttles write-through persistence of blocked_stats:
// the first record after a flush writes immediately, later records at
// most once per interval.
const statsFlushInterval = 2 * time.Second

type blockLog struct {
	mu        sync.Mutex
	dir       string
	day       string
	counts    map[string]int   // today's cumulative counts (persisted)
	lastSeen  map[string]int64 // domain -> unix time of its most recent block (persisted)
	total     int
	pending   map[string]int // counts since last flush, feeds blocked.log
	lastFlush time.Time      // last flush (zero = never)
	// last flush's header counts, reused by record-triggered write-through
	// flushes (the daemon's tick refreshes them with live list counts).
	lastRules, lastWhite int
}

func newBlockLog(dir string) *blockLog {
	b := &blockLog{
		dir:      dir,
		day:      today(),
		counts:   make(map[string]int),
		lastSeen: make(map[string]int64),
		pending:  make(map[string]int),
	}
	b.loadStats()
	return b
}

func today() string { return time.Now().Format("2006-01-02") }

// loadStats restores today's counts from blocked_stats; a stale (previous
// day) or unreadable file simply starts the day fresh.
func (b *blockLog) loadStats() {
	f, err := os.Open(filepath.Join(b.dir, statsFileName))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if k == "date" && v != b.day {
				b.counts = make(map[string]int)
				b.lastSeen = make(map[string]int64)
				b.total = 0
				return
			}
			continue
		}
		// Domain lines: "domain count" (legacy, pre-1.0.4: no timestamp,
		// lastSeen stays 0 and the panel shows "—") or
		// "domain count unixtime" (current).
		fields := strings.Fields(line)
		if len(fields) == 2 || len(fields) == 3 {
			if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
				b.counts[fields[0]] = n
				b.total += n
				if len(fields) == 3 {
					if ts, err := strconv.ParseInt(fields[2], 10, 64); err == nil && ts > 0 {
						b.lastSeen[fields[0]] = ts
					}
				}
			}
		}
	}
}

func (b *blockLog) record(domain string) {
	b.mu.Lock()
	if d := today(); d != b.day {
		b.day = d
		b.counts = make(map[string]int)
		b.lastSeen = make(map[string]int64)
		b.pending = make(map[string]int)
		b.total = 0
	}
	if _, ok := b.counts[domain]; !ok && len(b.counts) >= maxCountDomains {
		b.evictMinLocked()
	}
	b.counts[domain]++
	b.lastSeen[domain] = time.Now().Unix()
	b.pending[domain]++
	b.total++
	due := b.lastFlush.IsZero() || time.Since(b.lastFlush) >= statsFlushInterval
	rules, white := b.lastRules, b.lastWhite
	b.mu.Unlock()
	if due {
		// Write-through: blocked_stats reaches disk within ~2s of a block,
		// not only on the 15s tick — a daemon restart inside the old window
		// used to erase the newest 最近拦截 entries with it.
		b.flush(rules, white)
	}
}

// evictMinLocked drops the least-hit domain to make room for a new one.
func (b *blockLog) evictMinLocked() {
	minDom, minN := "", 0
	for d, n := range b.counts {
		if minDom == "" || n < minN {
			minDom, minN = d, n
		}
	}
	if minDom != "" {
		b.total -= b.counts[minDom]
		delete(b.counts, minDom)
		delete(b.lastSeen, minDom)
	}
}

func (b *blockLog) snapshot() (day string, total, unique int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.day, b.total, len(b.counts)
}

func (b *blockLog) countOf(domain string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counts[domain]
}

// lastOf returns the unix time of the domain's most recent block today,
// or 0 if unknown (e.g. restored from a legacy stats file without times).
func (b *blockLog) lastOf(domain string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastSeen[domain]
}

// statEntry is one domain's row in blocked_stats.
type statEntry struct {
	domain string
	count  int
	last   int64
}

// sortedRecent orders entries for the 最近拦截 list: most recently blocked
// first; ties fall back to higher count, then domain name for stability.
func sortedRecent(counts map[string]int, lastSeen map[string]int64) []statEntry {
	entries := make([]statEntry, 0, len(counts))
	for d, n := range counts {
		entries = append(entries, statEntry{domain: d, count: n, last: lastSeen[d]})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].last != entries[j].last {
			return entries[i].last > entries[j].last
		}
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].domain < entries[j].domain
	})
	return entries
}

// flush persists the counts file (always) and appends the pending batch to
// the blocked.log detail log (only when logging is enabled).
func (b *blockLog) flush(blockRules, whiteRules int) {
	b.mu.Lock()
	b.lastRules, b.lastWhite = blockRules, whiteRules
	b.lastFlush = time.Now()
	pending := b.pending
	b.pending = make(map[string]int)
	day, total := b.day, b.total
	counts := make(map[string]int, len(b.counts))
	for d, n := range b.counts {
		counts[d] = n
	}
	lastSeen := make(map[string]int64, len(b.lastSeen))
	for d, ts := range b.lastSeen {
		lastSeen[d] = ts
	}
	b.mu.Unlock()

	b.writeStats(day, total, counts, lastSeen, blockRules, whiteRules)

	if len(pending) == 0 || !loggingOn.Load() {
		return
	}
	path := filepath.Join(b.dir, "blocked.log")
	rotateIfLarge(path, maxLogBytes)
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		domains := make([]string, 0, len(pending))
		for d := range pending {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		ts := time.Now().Format("2006-01-02 15:04:05")
		for _, d := range domains {
			fmt.Fprintf(f, "%s %s %d\n", ts, d, pending[d])
		}
		f.Close()
	}
}

// writeStats atomically rewrites blocked_stats: summary lines first
// (date/total/unique/rules/whitelist), then "domain count unixtime" lines,
// most recently blocked first — the file order IS the panel's 最近拦截
// order (the panel re-sorts client-side as well).
func (b *blockLog) writeStats(day string, total int, counts map[string]int, lastSeen map[string]int64, blockRules, whiteRules int) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "date=%s\ntotal=%d\nunique=%d\nrules=%d\nwhitelist=%d\n", day, total, len(counts), blockRules, whiteRules)
	for _, e := range sortedRecent(counts, lastSeen) {
		fmt.Fprintf(&sb, "%s %d %d\n", e.domain, e.count, e.last)
	}
	tmp := filepath.Join(b.dir, statsFileName+".tmp")
	if err := os.WriteFile(tmp, []byte(sb.String()), 0644); err == nil {
		os.Rename(tmp, filepath.Join(b.dir, statsFileName))
	}
}

func rotateIfLarge(path string, max int64) {
	if st, err := os.Stat(path); err == nil && st.Size() > max {
		os.Rename(path, path+".1")
	}
}
