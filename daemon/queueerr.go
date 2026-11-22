package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Receive-loop error handling for the NFQUEUE sockets (v1.1.2).
//
// Root cause of the on-device log flood (daemon.log, 2026-11-22: 6443 of
// 6457 lines were the same "queue 0 error: netlink receive: recvmsg: bad
// file descriptor" line inside a single second): go-nfqueue's
// socketCallback loop calls the ErrorFunc after every failed Receive and
// only stops when the ErrorFunc returns non-zero or the context ends.
// The old errFn in openQueue logged and returned 0 unconditionally, so
// once the queue fd was closed during a stop/restart, Receive failed
// instantly (EBADF never blocks) and the loop spun at full speed, one
// log line per iteration, until the 512KB log cap evicted everything
// useful. queueErrHandler fixes that three ways:
//
//   - shutdown is silent: once the daemon's context is cancelled the
//     handler stops the loop without logging (this also removes the
//     "use of closed file" / "i/o timeout" one-liners a normal stop
//     used to leave behind);
//   - fatal errors (closed/bad fd) stop the receive loop immediately
//     after a single log line, whatever the context state;
//   - every other error (timeouts, ENOBUFS, ...) is rate-limited: the
//     first occurrence logs, repeats are counted and summarised at
//     most once per queueErrWindow, and the handler sleeps briefly so
//     a non-blocking error can never busy-spin the CPU.
const (
	queueErrWindow  = 5 * time.Second
	queueErrBackoff = 25 * time.Millisecond
)

// isFatalQueueErr reports whether a receive error means the socket is
// gone for good: retrying can only spin. The string fallbacks cover the
// spellings the netlink/poll layers actually produce on device
// ("bad file descriptor", "use of closed file"), which do not always
// unwrap to a comparable sentinel.
func isFatalQueueErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EBADF) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "bad file descriptor") ||
		strings.Contains(s, "use of closed file") ||
		strings.Contains(s, "file already closed")
}

// queueErrHandler implements nfqueue.ErrorFunc semantics for one queue:
// the return value is 0 to keep receiving, non-zero to stop the loop.
type queueErrHandler struct {
	queue uint16
	ctx   context.Context
	log   func(format string, args ...interface{})
	now   func() time.Time
	sleep func(time.Duration)

	mu         sync.Mutex
	lastKey    string // err.Error() of the currently tracked repeat streak
	windowFrom time.Time
	suppressed int
}

func newQueueErrHandler(queue uint16, ctx context.Context) *queueErrHandler {
	return &queueErrHandler{
		queue: queue,
		ctx:   ctx,
		log:   logf,
		now:   time.Now,
		sleep: time.Sleep,
	}
}

// flushLocked emits the pending repeat summary, if any. h.mu must be held.
func (h *queueErrHandler) flushLocked() {
	if h.suppressed > 0 && h.lastKey != "" {
		h.log("queue %d error: %s (suppressed %d repeats)", h.queue, h.lastKey, h.suppressed)
	}
	h.suppressed = 0
}

// handle classifies one receive error and decides the loop's fate.
func (h *queueErrHandler) handle(err error) int {
	// Shutdown in progress: stop the loop, log nothing. The queue fd
	// is about to be (or already is) closed by run()'s shutdown path;
	// whatever Receive tripped over is expected noise, not news.
	if h.ctx != nil && h.ctx.Err() != nil {
		return 1
	}
	if isFatalQueueErr(err) {
		h.mu.Lock()
		h.flushLocked()
		h.lastKey = ""
		h.log("queue %d error: %v (fatal, receive loop exiting)", h.queue, err)
		h.mu.Unlock()
		return 1
	}
	// Transient (timeouts, ENOBUFS, ...): rate-limit the logging.
	h.mu.Lock()
	key := err.Error()
	now := h.now()
	switch {
	case key != h.lastKey:
		h.flushLocked()
		h.log("queue %d error: %v", h.queue, err)
		h.lastKey = key
		h.windowFrom = now
	case now.Sub(h.windowFrom) >= queueErrWindow:
		h.suppressed++
		h.flushLocked()
		h.windowFrom = now
	default:
		h.suppressed++
	}
	h.mu.Unlock()
	// Small backoff: a transient error that returns instantly must not
	// turn the receive loop into a busy spin.
	h.sleep(queueErrBackoff)
	return 0
}

// recovered is called for every packet the queue successfully delivers:
// a pending repeat streak is settled (summary logged, tracking reset),
// so the next error — even an identical one — logs fresh.
func (h *queueErrHandler) recovered() {
	h.mu.Lock()
	h.flushLocked()
	h.lastKey = ""
	h.mu.Unlock()
}
