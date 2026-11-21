package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

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
		key := fmt.Sprintf("%s:%d>%s:%d/%d", pi.src.String(), pi.srcPort, pi.dst.String(), pi.dstPort, pi.family)
		if blocked, found := d.flows.get(key); found {
			verdict(nf, a, !blocked)
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
			verdict(nf, a, false)
			return 0
		}
		d.flows.put(key, false)
		verdict(nf, a, true)
		return 0
	}
}

func openQueue(num uint16, handler func(*nfqueue.Nfqueue) nfqueue.HookFunc, ctx context.Context) (*nfqueue.Nfqueue, error) {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      num,
		MaxQueueLen:  4096,
		MaxPacketLen: 0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagUIDGid,
	})
	if err != nil {
		return nil, err
	}
	errFn := func(e error) int {
		logf("queue %d error: %v", num, e)
		return 0
	}
	go func() {
		if err := nf.RegisterWithErrorFunc(ctx, handler(nf), errFn); err != nil {
			logf("queue %d register stopped: %v", num, err)
		}
	}()
	return nf, nil
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
	defer os.Remove(pidPath)

	d := &daemon{
		lists: NewListManager(dir),
		blog:  newBlockLog(dir),
		flows: newFlowTable(),
		cfg:   cfg,
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
	logf("started: rules=%d whitelist=%d exempt_uids=%v marks=%v dns=%v sni=%v logging=%v boxproxy=%s exemptions=%s", bc, wc, uids, cfg.ProxyMarks, cfg.DNSFilter, cfg.SNIFilter, cfg.Logging, boxProxyWord(present), exemptionsWord(present))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var queues []*nfqueue.Nfqueue
	if cfg.DNSFilter {
		nf, err := openQueue(QueueDNS, d.handleDNS, ctx)
		if err != nil {
			logf("open DNS queue failed: %v", err)
			return 1
		}
		queues = append(queues, nf)
	}
	if cfg.SNIFilter {
		nf, err := openQueue(QueueSNI, d.handleSNI, ctx)
		if err != nil {
			logf("open SNI queue failed: %v", err)
			return 1
		}
		queues = append(queues, nf)
	}
	defer func() {
		for _, q := range queues {
			q.Close()
		}
	}()

	// maintenance: hot-reload lists, refresh proxy uid exemptions, flush stats
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if nc := loadConfig(filepath.Join(dir, "config")); nc.Logging != loggingOn.Load() {
					loggingOn.Store(nc.Logging)
					if nc.Logging {
						logf("logging enabled")
					}
				}
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
				if presenceChanged || len(uids) != before {
					applyRules(d.cfg, uids, d.bpPresent.Load())
					if !presenceChanged {
						logf("proxy uid exemptions refreshed: %v", uids)
					}
				}
				bc, wc, _, _ := d.lists.Counts()
				d.blog.flush(bc, wc)
			}
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	logf("stopping")
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
