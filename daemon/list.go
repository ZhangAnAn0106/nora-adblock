package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DomainSet matches a name against a set of domains by suffix:
// an entry "example.com" matches "example.com" and any "*.example.com".
type DomainSet struct {
	set map[string]struct{}
}

func NewDomainSet() *DomainSet { return &DomainSet{set: make(map[string]struct{})} }

func (d *DomainSet) Add(name string) {
	name = normalizeDomain(name)
	if name != "" {
		d.set[name] = struct{}{}
	}
}

func (d *DomainSet) Len() int { return len(d.set) }

func (d *DomainSet) Match(name string) bool {
	name = normalizeDomain(name)
	for {
		if _, ok := d.set[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	return s
}

func loadDomainFile(path string) (*DomainSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ds := NewDomainSet()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		// tolerate "0.0.0.0 domain" hosts-style lines
		if fields := strings.Fields(line); len(fields) == 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::") {
			line = fields[1]
		} else if len(fields) != 1 {
			continue
		}
		ds.Add(line)
	}
	return ds, sc.Err()
}

// ListManager owns the list files in the data dir and hot-reloads each
// on mtime change. Decision priority (highest first):
//
//	user_whitelist.txt > whitelist.txt (built-in safety) >
//	user_blocklist.txt > blocklist.txt (built-in anti-AD snapshot)
type ListManager struct {
	mu        sync.RWMutex
	dir       string
	block     *DomainSet
	white     *DomainSet
	userBlock *DomainSet
	userWhite *DomainSet
	mods      map[string]time.Time
}

func NewListManager(dir string) *ListManager {
	return &ListManager{
		dir:       dir,
		block:     NewDomainSet(),
		white:     NewDomainSet(),
		userBlock: NewDomainSet(),
		userWhite: NewDomainSet(),
		mods:      make(map[string]time.Time),
	}
}

func (lm *ListManager) path(name string) string { return filepath.Join(lm.dir, name) }

var listFiles = []string{"blocklist.txt", "whitelist.txt", "user_blocklist.txt", "user_whitelist.txt"}

func (lm *ListManager) setFor(name string, ds *DomainSet) {
	switch name {
	case "blocklist.txt":
		lm.block = ds
	case "whitelist.txt":
		lm.white = ds
	case "user_blocklist.txt":
		lm.userBlock = ds
	case "user_whitelist.txt":
		lm.userWhite = ds
	}
}

// ReloadIfChanged re-reads any list whose file changed. A file that
// disappeared after being loaded reloads as empty, without touching
// the other lists.
func (lm *ListManager) ReloadIfChanged() bool {
	changed := false
	for _, name := range listFiles {
		p := lm.path(name)
		st, err := os.Stat(p)
		if err != nil {
			lm.mu.Lock()
			if _, seen := lm.mods[name]; seen {
				lm.setFor(name, NewDomainSet())
				delete(lm.mods, name)
				changed = true
			}
			lm.mu.Unlock()
			continue
		}
		if st.ModTime().Equal(lm.mods[name]) {
			continue
		}
		ds, err := loadDomainFile(p)
		if err != nil {
			continue
		}
		lm.mu.Lock()
		lm.setFor(name, ds)
		lm.mods[name] = st.ModTime()
		lm.mu.Unlock()
		changed = true
	}
	return changed
}

// Blocked applies the priority ladder.
func (lm *ListManager) Blocked(name string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	if lm.userWhite.Match(name) {
		return false
	}
	if lm.white.Match(name) {
		return false
	}
	if lm.userBlock.Match(name) {
		return true
	}
	return lm.block.Match(name)
}

// Counts returns (built-in block, built-in white, user block, user white) sizes.
func (lm *ListManager) Counts() (int, int, int, int) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.block.Len(), lm.white.Len(), lm.userBlock.Len(), lm.userWhite.Len()
}

