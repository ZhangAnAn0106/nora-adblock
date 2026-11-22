package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testRig is a queueErrHandler with a fake clock, a recording sleep and
// a line-collecting log, so error storms can be replayed instantly.
type testRig struct {
	h      *queueErrHandler
	lines  []string
	sleeps int
	now    time.Time
}

func newTestRig(ctx context.Context) *testRig {
	r := &testRig{now: time.Date(2026, 11, 22, 4, 5, 33, 0, time.UTC)}
	h := newQueueErrHandler(0, ctx)
	h.log = func(format string, args ...interface{}) {
		r.lines = append(r.lines, fmt.Sprintf(format, args...))
	}
	h.now = func() time.Time { return r.now }
	h.sleep = func(time.Duration) { r.sleeps++ }
	r.h = h
	return r
}

func ebadfErr() error  { return fmt.Errorf("netlink receive: recvmsg: %w", syscall.EBADF) }
func closedErr() error { return errors.New("netlink receive: recvmsg: use of closed file") }
func timeoutErr() error {
	return fmt.Errorf("netlink receive: recvmsg: %w", os.ErrDeadlineExceeded)
}
func enobufsErr() error { return fmt.Errorf("netlink receive: recvmsg: %w", syscall.ENOBUFS) }

func TestIsFatalQueueErr(t *testing.T) {
	for _, err := range []error{ebadfErr(), closedErr(), fmt.Errorf("recv: %w", os.ErrClosed)} {
		if !isFatalQueueErr(err) {
			t.Errorf("isFatalQueueErr(%v) = false, want true", err)
		}
	}
	for _, err := range []error{timeoutErr(), enobufsErr(), errors.New("boom"), nil} {
		if isFatalQueueErr(err) {
			t.Errorf("isFatalQueueErr(%v) = true, want false", err)
		}
	}
}

// The device bug: a dead fd makes Receive fail instantly forever. The
// handler must end the (simulated) library loop on the first error and
// keep the log bounded — not 6443 lines in a second.
func TestQueueErrFatalExitsLoop(t *testing.T) {
	r := newTestRig(context.Background())
	calls := 0
	for i := 0; i < 10000; i++ {
		calls++
		if r.h.handle(ebadfErr()) != 0 {
			break
		}
	}
	if calls > 2 {
		t.Fatalf("receive loop needed %d error calls to exit, want <= 2", calls)
	}
	if len(r.lines) != 1 {
		t.Fatalf("fatal error produced %d log lines, want exactly 1: %v", len(r.lines), r.lines)
	}
	if !strings.Contains(r.lines[0], "bad file descriptor") {
		t.Errorf("fatal line = %q, want it to name the error", r.lines[0])
	}
}

// A storm of the same transient error: first one logs, the rest are
// counted, and after the window a single summary settles the count.
func TestQueueErrRateLimitsRepeats(t *testing.T) {
	r := newTestRig(context.Background())
	const storm = 100
	for i := 0; i < storm; i++ {
		if got := r.h.handle(timeoutErr()); got != 0 {
			t.Fatalf("transient error #%d stopped the loop (ret=%d)", i, got)
		}
	}
	if len(r.lines) != 1 {
		t.Fatalf("%d identical errors inside the window produced %d lines, want 1: %v", storm, len(r.lines), r.lines)
	}
	if r.sleeps != storm {
		t.Errorf("backoff sleeps = %d, want %d (one per transient error)", r.sleeps, storm)
	}
	r.now = r.now.Add(queueErrWindow + time.Second)
	if got := r.h.handle(timeoutErr()); got != 0 {
		t.Fatalf("post-window error stopped the loop (ret=%d)", got)
	}
	if len(r.lines) != 2 {
		t.Fatalf("after the window: %d lines, want 2 (first + summary): %v", len(r.lines), r.lines)
	}
	// storm-1 repeats were suppressed inside the window, plus the one
	// that crossed it: the summary must account for all of them.
	want := fmt.Sprintf("suppressed %d repeats", storm)
	if !strings.Contains(r.lines[1], want) {
		t.Errorf("summary = %q, want it to contain %q", r.lines[1], want)
	}
}

// When packets flow again the streak is settled: the summary is logged
// once and the next identical error starts (and logs) a fresh streak.
func TestQueueErrRecoverySettlesStreak(t *testing.T) {
	r := newTestRig(context.Background())
	r.h.handle(timeoutErr())
	for i := 0; i < 5; i++ {
		r.h.handle(timeoutErr())
	}
	r.h.recovered()
	if len(r.lines) != 2 || !strings.Contains(r.lines[1], "suppressed 5 repeats") {
		t.Fatalf("after recovery: lines = %v, want [first, summary of 5]", r.lines)
	}
	r.h.handle(timeoutErr())
	if len(r.lines) != 3 {
		t.Fatalf("post-recovery identical error was not logged fresh: %v", r.lines)
	}
	// A recovery with nothing pending stays silent.
	r.h.recovered()
	if len(r.lines) != 3 {
		t.Fatalf("idle recovery logged something: %v", r.lines)
	}
}

// A different error flushes the previous streak's summary before its
// own first line, so no count is ever lost.
func TestQueueErrKindChangeFlushes(t *testing.T) {
	r := newTestRig(context.Background())
	r.h.handle(timeoutErr())
	r.h.handle(timeoutErr())
	r.h.handle(timeoutErr()) // 1 line + 2 suppressed
	r.h.handle(enobufsErr())
	if len(r.lines) != 3 {
		t.Fatalf("lines = %v, want [timeout, timeout summary, enobufs]", r.lines)
	}
	if !strings.Contains(r.lines[1], "suppressed 2 repeats") || !strings.Contains(r.lines[2], "no buffer space available") {
		t.Errorf("lines = %v, want summary of 2 then the ENOBUFS line", r.lines)
	}
}

// During shutdown the handler stops the loop silently for every error
// class — a normal stop must leave no error noise in the log at all.
func TestQueueErrShutdownIsSilent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := newTestRig(ctx)
	for _, err := range []error{ebadfErr(), closedErr(), timeoutErr(), enobufsErr()} {
		if got := r.h.handle(err); got == 0 {
			t.Errorf("handle(%v) during shutdown returned 0, want stop", err)
		}
	}
	if len(r.lines) != 0 {
		t.Fatalf("shutdown produced log lines: %v", r.lines)
	}
}

// A fatal error arriving mid-streak settles the streak first, then
// logs its own single line and stops the loop.
func TestQueueErrFatalSettlesStreak(t *testing.T) {
	r := newTestRig(context.Background())
	r.h.handle(timeoutErr())
	r.h.handle(timeoutErr())
	r.h.handle(timeoutErr()) // 1 line + 2 suppressed
	if got := r.h.handle(closedErr()); got == 0 {
		t.Fatal("fatal error did not stop the loop")
	}
	if len(r.lines) != 3 {
		t.Fatalf("lines = %v, want [timeout, summary of 2, fatal]", r.lines)
	}
	if !strings.Contains(r.lines[2], "use of closed file") {
		t.Errorf("fatal line = %q", r.lines[2])
	}
}
