package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

// daemonVersion is stamped into the startup log line so daemon.log alone
// proves which binary is actually running on the device (a cover-install
// without reboot keeps the old process alive — this is how you tell).
const daemonVersion = "1.0.5"

const defaultDataDir = "/data/adb/nora_adblock"

func dataDir() string {
	if d := os.Getenv("NORA_ADBLOCK_DIR"); d != "" {
		return d
	}
	return defaultDataDir
}

// loggingOn gates daemon.log file writes (config LOGGING). It defaults to on
// and is refreshed from the config file at startup and on every maintenance
// tick, so flipping LOGGING in the WebUI takes effect without a restart.
// Block counts (blocked_stats) are NOT tied to this switch.
var loggingOn atomic.Bool

func init() { loggingOn.Store(true) }

func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "nora-adblockd: %s\n", msg)
	if !loggingOn.Load() {
		return
	}
	path := filepath.Join(dataDir(), "daemon.log")
	rotateIfLarge(path, maxLogBytes)
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
		f.Close()
	}
}

// ---------- iptables plumbing ----------

func runCmd(bin string, args []string) error {
	return exec.Command(bin, args...).Run()
}

func iptablesBins() []string {
	var bins []string
	for _, b := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(b); err == nil {
			bins = append(bins, b)
		}
	}
	return bins
}

func applyRules(cfg Config, uids []int, boxProxyPresent bool) {
	for _, bin := range iptablesBins() {
		for _, args := range setupCommands(cfg, uids, boxProxyPresent) {
			_ = runCmd(bin, args) // -N may fail when chain exists; flush follows anyway
		}
		if runCmd(bin, hookCheckCommand()) != nil {
			_ = runCmd(bin, hookCommand())
		}
	}
}

func clearRules() {
	for _, bin := range iptablesBins() {
		for _, args := range teardownCommands() {
			_ = runCmd(bin, args)
		}
		// a second delete pass in case the jump was inserted twice
		_ = runCmd(bin, []string{"-w", "-t", "mangle", "-D", "OUTPUT", "-j", ChainName})
	}
}

// ---------- flow table (SNI decisions) ----------

type flowEntry struct {
	blocked bool
	exp     time.Time
}

type flowTable struct {
	mu sync.Mutex
	m  map[string]flowEntry
}

func newFlowTable() *flowTable { return &flowTable{m: make(map[string]flowEntry)} }

func (f *flowTable) get(key string) (blocked, found bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[key]
	if !ok {
		return false, false
	}
	if time.Now().After(e.exp) {
		delete(f.m, key)
		return false, false
	}
	return e.blocked, true
}

func (f *flowTable) put(key string, blocked bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.m) > 20000 {
		now := time.Now()
		for k, e := range f.m {
			if now.After(e.exp) {
				delete(f.m, k)
			}
		}
	}
	f.m[key] = flowEntry{blocked: blocked, exp: time.Now().Add(120 * time.Second)}
}

// ---------- daemon core ----------

type daemon struct {
	cfg    Config
	lists  *ListManager
	blog   *blockLog
	flows  *flowTable
	mu     sync.RWMutex
	exempt map[int]bool
	// bpPresent is the latest BoxProxy detection result; it gates both the
	// iptables exemptions and the in-daemon mark/uid skip logic. uid 0
	// (root) stays exempt either way.
	bpPresent atomic.Bool
	// requestStop is wired by run() to the shutdown path: a maintenance
	// tick that sees ENABLED=0 in the config calls it so the daemon stops
	// itself, instead of depending solely on an external --stop signal
	// (v1.1.0: the panel's total switch could report success while a
	// slow/failed stop left the daemon — and the blocking — alive).
	requestStop func()
}

func (d *daemon) refreshExempt() []int {
	var set map[int]bool
	if d.bpPresent.Load() {
		set = exemptUIDSet(d.cfg)
	} else {
		set = map[int]bool{0: true}
	}
	d.mu.Lock()
	d.exempt = set
	d.mu.Unlock()
	return sortedUIDs(set)
}

func (d *daemon) isExempt(a nfqueue.Attribute) bool {
	if a.Mark != nil && d.bpPresent.Load() {
		for _, m := range d.cfg.ProxyMarks {
			if *a.Mark&m == m && m != 0 {
				return true
			}
		}
	}
	if a.UID != nil {
		if *a.UID == 0 {
			return true // root is never filtered, BoxProxy or not
		}
		if !d.bpPresent.Load() {
			return false
		}
		d.mu.RLock()
		ok := d.exempt[int(*a.UID)]
		d.mu.RUnlock()
		return ok
	}
	return false
}

func verdict(nf *nfqueue.Nfqueue, a nfqueue.Attribute, accept bool) {
	if a.PacketID == nil {
		return
	}
	v := nfqueue.NfAccept
	if !accept {
		v = nfqueue.NfDrop
	}
	_ = nf.SetVerdict(*a.PacketID, v)
}

// verdictDecided is verdict() plus the connmark fast path: the decision
// is stamped onto the connection, so the kernel resolves the rest of
// the flow without userspace (see ConnMarkAllow/ConnMarkBlock). Used
// only by the SNI handler — deliberately never for DNS: UDP "flows"
// are 5-tuple buckets that later, unrelated queries can share, and
// stamping them would let those queries skip the DNS filter entirely.
// If the kernel refuses the connmark verdict, fall back to a plain
// verdict (the flow table then keeps deciding, as before v1.0.9).
func verdictDecided(nf *nfqueue.Nfqueue, a nfqueue.Attribute, accept bool) {
	if a.PacketID == nil {
		return
	}
	v := nfqueue.NfAccept
	mark := int(ConnMarkAllow)
	if !accept {
		v = nfqueue.NfDrop
		mark = int(ConnMarkBlock)
	}
	if err := nf.SetVerdictWithConnMark(*a.PacketID, v, mark); err != nil {
		_ = nf.SetVerdict(*a.PacketID, v)
	}
}

func (d *daemon) handleDNS(nf *nfqueue.Nfqueue) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		if d.isExempt(a) || a.Payload == nil {
			verdict(nf, a, true)
			return 0
		}
		pi, ok := parsePacket(*a.Payload)
		if !ok || pi.dstPort != 53 || len(pi.payload) == 0 {
			verdict(nf, a, true)
			return 0
		}
		msg := pi.payload
		if pi.tcp {
			msg = stripTCPFrame(msg)
		}
		name, ok := parseDNSQueryName(msg)
		if ok && d.lists.Blocked(name) {
			d.blog.record(name)
			verdict(nf, a, false)
			return 0
		}
		verdict(nf, a, true)
		return 0
	}
}

func (d *daemon) handleSNI(nf *nfqueue.Nfqueue) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		if d.isExempt(a) || a.Payload == nil {
			verdict(nf, a, true)
			return 0
		}
		pi, ok := parsePacket(*a.Payload)
		if !ok || !pi.tcp || len(pi.payload) == 0 {
			verdict(nf, a, true)
			return 0
		}
		key := flowKey(pi)
		if blocked, found := d.flows.get(key); found {
			verdictDecided(nf, a, !blocked)
			return 0
		}
		var name string
		var got bool
		switch pi.dstPort {
		case 80:
			name, got = parseHTTPHost(pi.payload)
		case 443, 8443:
			name, got = parseTLSServerName(pi.payload)
		default:
			verdict(nf, a, true)
			return 0
		}
		if !got {
			// Unparseable / fragmented / non-TLS: never block on uncertainty.
			verdict(nf, a, true)
			return 0
		}
		if d.lists.Blocked(name) {
			d.flows.put(key, true)
			d.blog.record(name)
			verdictDecided(nf, a, false)
			return 0
		}
		d.flows.put(key, false)
		verdictDecided(nf, a, true)
		return 0
	}
}

// flowKey builds the flow-table key without fmt.Sprintf (this runs on
// every queued packet): "src:port>dst:port/family".
func flowKey(pi pktInfo) string {
	var b strings.Builder
	b.Grow(96)
	b.WriteString(pi.src.String())
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(pi.srcPort)))
	b.WriteByte('>')
	b.WriteString(pi.dst.String())
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(pi.dstPort)))
	b.WriteByte('/')
	b.WriteString(strconv.Itoa(pi.family))
	return b.String()
}

func openQueue(num uint16, handler func(*nfqueue.Nfqueue) nfqueue.HookFunc, ctx context.Context) (*nfqueue.Nfqueue, error) {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      num,
		MaxQueueLen:  8192,
		MaxPacketLen: 0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagUIDGid,
	})
	if err != nil {
		return nil, err
	}
	// The error handler is NOT a plain logger: go-nfqueue's receive
	// loop only stops when the ErrorFunc returns non-zero, so an
	// unconditional "log + return 0" spun 6443 identical EBADF lines
	// into daemon.log in one second when the fd died during a restart
	// (v1.1.1 and earlier). queueErrHandler classifies, rate-limits
	// and stops the loop on fatal errors — see queueerr.go. The hook
	// wrapper reports every delivered packet as a recovery, which
	// settles any pending repeat-suppression streak.
	qeh := newQueueErrHandler(num, ctx)
	hook := handler(nf)
	wrapped := func(a nfqueue.Attribute) int {
		qeh.recovered()
		return hook(a)
	}
	go func() {
		if err := nf.RegisterWithErrorFunc(ctx, wrapped, qeh.handle); err != nil {
			logf("queue %d register stopped: %v", num, err)
		}
	}()
	return nf, nil
}

// syncSwitches folds a freshly loaded config into the daemon's live
// switch state: LOGGING takes effect immediately, and the
// DNS/SNI/QUIC filter fields in d.cfg are updated. It reports whether
// the filter triple changed — the caller must then re-apply the
// iptables rules so the new switch positions take effect. Called only
// from the maintenance goroutine (and never concurrently with itself).
func (d *daemon) syncSwitches(nc Config) (filtersChanged bool) {
	if nc.Logging != loggingOn.Load() {
		loggingOn.Store(nc.Logging)
		if nc.Logging {
			logf("logging enabled")
		}
	}
	if nc.DNSFilter != d.cfg.DNSFilter || nc.SNIFilter != d.cfg.SNIFilter || nc.QUICFilter != d.cfg.QUICFilter {
		d.cfg.DNSFilter = nc.DNSFilter
		d.cfg.SNIFilter = nc.SNIFilter
		d.cfg.QUICFilter = nc.QUICFilter
		return true
	}
	return false
}

// enabledExitWanted is the pure decision behind the daemon's ENABLED
// self-stop: a daemon that was started enabled must shut down when the
// config now says disabled. A daemon never runs with startEnabled=false
// (run() refuses to start), so the first operand is a guard, not a
// second input source — it keeps the predicate honest in tests.
func enabledExitWanted(startEnabled, nowEnabled bool) bool {
	return startEnabled && !nowEnabled
}

// noteEnabled folds the ENABLED switch into a running daemon: when the
// freshly loaded config turns the module off, it asks run() to shut
// down through the normal exit path (flush stats, clear rules, remove
// pid file). It reports whether shutdown was requested, so the caller
// skips the rest of the tick. Before v1.1.0 the ONLY stop path was
// adblock.sh's --stop signal: if that timed out or failed, the config
// said 0 while the daemon kept filtering — "总开关关不掉拦截".
func (d *daemon) noteEnabled(nc Config) (exit bool) {
	if !enabledExitWanted(d.cfg.Enabled, nc.Enabled) {
		return false
	}
	logf("ENABLED=0 in config: daemon stopping itself")
	if d.requestStop != nil {
		d.requestStop()
	}
	return true
}

// currentExemptUIDs snapshots the exemption set last computed by
// refreshExempt, for rule re-application on the fast path (which must
// not re-read packages.list just to flip a filter switch).
func (d *daemon) currentExemptUIDs() []int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return sortedUIDs(d.exempt)
}

// fastTick is the ~2s maintenance beat: config-driven switches only.
// A filter change re-applies the rules with the current exemptions —
// applyRules rebuilds the whole chain from the new config, so turning
// QUIC off really removes the UDP 443 DROP rule (no stale leftovers),
// and turning a filter on starts routing its traffic to the (already
// open) queue.
func (d *daemon) fastTick(dir string) {
	nc := loadConfig(filepath.Join(dir, "config"))
	if d.noteEnabled(nc) {
		return
	}
	if d.syncSwitches(nc) {
		applyRules(d.cfg, d.currentExemptUIDs(), d.bpPresent.Load())
		logf("filter switches changed: dns=%v sni=%v quic=%v (rules re-applied)", d.cfg.DNSFilter, d.cfg.SNIFilter, d.cfg.QUICFilter)
	}
}

// slowTick is the ~15s maintenance beat: the same switch sync as the
// fast tick, plus list hot-reload, BoxProxy presence following and
// stats flushing. Rule re-application is
// merged: at most one applyRules per tick, however many inputs changed.
func (d *daemon) slowTick(dir string) {
	nc := loadConfig(filepath.Join(dir, "config"))
	if d.noteEnabled(nc) {
		return
	}
	filtersChanged := d.syncSwitches(nc)
	if d.lists.ReloadIfChanged() {
		bc, wc, _, _ := d.lists.Counts()
		logf("lists reloaded: rules=%d whitelist=%d", bc, wc)
	}
	// follow BoxProxy installs/uninstalls while running
	presenceChanged := false
	if now := detectBoxProxy(d.cfg.ProxyPkgs); now != d.bpPresent.Load() {
		d.bpPresent.Store(now)
		writeBoxProxyState(dir, now)
		logf("boxproxy detection changed: %s (exemptions %s)", boxProxyWord(now), exemptionsWord(now))
		presenceChanged = true
	}
	before := len(d.exempt)
	uids := d.refreshExempt()
	if filtersChanged || presenceChanged || len(uids) != before {
		applyRules(d.cfg, uids, d.bpPresent.Load())
		if filtersChanged {
			logf("filter switches changed: dns=%v sni=%v quic=%v (rules re-applied)", d.cfg.DNSFilter, d.cfg.SNIFilter, d.cfg.QUICFilter)
		} else if !presenceChanged {
			logf("proxy uid exemptions refreshed: %v", uids)
		}
	}
	bc, wc, _, _ := d.lists.Counts()
	d.blog.flush(bc, wc)
}

func run() int {
	dir := dataDir()
	cfg := loadConfig(filepath.Join(dir, "config"))
	loggingOn.Store(cfg.Logging)
	if !cfg.Enabled {
		logf("ENABLED=0, not starting")
		return 0
	}
	_ = os.MkdirAll(dir, 0755)
	pidPath := filepath.Join(dir, "daemon.pid")
	_ = os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	// Only remove the pid file if it still names THIS process: a slow-exiting
	// old daemon must not delete the pid file a freshly started daemon just
	// wrote (that made --status report "stopped" for a live daemon).
	defer func() {
		if b, err := os.ReadFile(pidPath); err == nil {
			var p int
			if _, err := fmt.Sscanf(string(b), "%d", &p); err == nil && p == os.Getpid() {
				os.Remove(pidPath)
			}
		}
	}()

	// quit is closed (once) by a maintenance tick that sees ENABLED=0 in
	// the config — the daemon's self-stop path, parallel to signals.
	quit := make(chan struct{})
	var quitOnce sync.Once
	d := &daemon{
		lists: NewListManager(dir),
		blog:  newBlockLog(dir),
		flows: newFlowTable(),
		cfg:   cfg,
		requestStop: func() {
			quitOnce.Do(func() { close(quit) })
		},
	}
	d.lists.ReloadIfChanged()
	// BoxProxy exemptions are on-demand: re-check presence on every daemon
	// start (install-time result lives in boxproxy.state). Installing or
	// removing BoxProxy later is picked up without reflashing the module.
	present := detectBoxProxy(cfg.ProxyPkgs)
	d.bpPresent.Store(present)
	if prev, ok := readBoxProxyState(dir); ok && prev != present {
		logf("boxproxy detection changed: %s -> %s (exemptions %s)", boxProxyWord(prev), boxProxyWord(present), exemptionsWord(present))
	}
	writeBoxProxyState(dir, present)
	uids := d.refreshExempt()
	applyRules(cfg, uids, present)
	defer clearRules()
	bc, wc, _, _ := d.lists.Counts()
	logf("started: version=%s rules=%d whitelist=%d exempt_uids=%v marks=%v dns=%v sni=%v quic=%v logging=%v boxproxy=%s exemptions=%s", daemonVersion, bc, wc, uids, cfg.ProxyMarks, cfg.DNSFilter, cfg.SNIFilter, cfg.QUICFilter, cfg.Logging, boxProxyWord(present), exemptionsWord(present))

	ctx, cancel := context.WithCancel(context.Background())
	// Both queues are opened unconditionally: whether packets reach them
	// is decided solely by the iptables rules, which the maintenance loop
	// re-applies in place when the filter switches change. That is what
	// makes DNS/SNI/QUIC hot-swappable without a daemon restart (v1.0.7
	// restarted the daemon on every switch flip — seconds of panel lag,
	// and a slow old-daemon exit was misreported as a save failure).
	var queues []*nfqueue.Nfqueue
	for _, q := range []struct {
		num     uint16
		name    string
		handler func(*nfqueue.Nfqueue) nfqueue.HookFunc
	}{
		{QueueDNS, "DNS", d.handleDNS},
		{QueueSNI, "SNI", d.handleSNI},
	} {
		nf, err := openQueue(q.num, q.handler, ctx)
		if err != nil {
			logf("open %s queue failed: %v", q.name, err)
			cancel()
			for _, q := range queues {
				q.Close()
			}
			return 1
		}
		queues = append(queues, nf)
	}
	// NOTE: no defer cancel() / defer queues.Close() here — the shutdown
	// sequence after the wait below runs them explicitly, in order.

	// maintenance: a fast tick (~2s) picks up config switch changes
	// (LOGGING state, and the DNS/SNI/QUIC filter triple — a
	// filter change re-applies the iptables rules in place, no restart);
	// a slow tick (~15s) does the heavier periodic work (list hot-reload,
	// BoxProxy re-detection, stats flush). Both run in one goroutine, so
	// the two paths never race each other.
	go func() {
		fast := time.NewTicker(2 * time.Second)
		slow := time.NewTicker(15 * time.Second)
		defer fast.Stop()
		defer slow.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-fast.C:
				d.fastTick(dir)
			case <-slow.C:
				d.slowTick(dir)
			}
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		logf("stopping (signal)")
	case <-quit:
		logf("stopping (ENABLED=0 in config)")
	}
	// Shutdown order matters (v1.1.0): cancel the maintenance context
	// FIRST — that stops the tick goroutine and the queues' registration
	// loops — and only then close the queues. As defers this came out
	// backwards: the queue-close defer was registered after
	// defer cancel(), so LIFO closed the queues first, and a Close
	// blocked on a live registration loop could stall the whole exit —
	// one of the ways the total switch failed to stop the daemon.
	cancel()
	for _, q := range queues {
		q.Close()
	}
	bc, wc, _, _ = d.lists.Counts()
	d.blog.flush(bc, wc)
	return 0
}

func stop() int {
	clearRules()
	pidPath := filepath.Join(dataDir(), "daemon.pid")
	if b, err := os.ReadFile(pidPath); err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(b), "%d", &pid); err == nil && pid > 0 {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Signal(syscall.SIGTERM)
			}
		}
	}
	fmt.Println("nora-adblockd: rules cleared, daemon signalled")
	return 0
}

func status() int {
	pidPath := filepath.Join(dataDir(), "daemon.pid")
	if b, err := os.ReadFile(pidPath); err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(b), "%d", &pid); err == nil && pid > 0 {
			if err := syscall.Kill(pid, 0); err == nil {
				fmt.Printf("running pid=%d\n", pid)
				return 0
			}
		}
	}
	fmt.Println("stopped")
	return 0
}

func main() {
	mode := "--start"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "--stop":
		os.Exit(stop())
	case "--status":
		os.Exit(status())
	default:
		os.Exit(run())
	}
}
