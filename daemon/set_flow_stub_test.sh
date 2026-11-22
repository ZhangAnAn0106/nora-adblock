#!/bin/sh
# Stub test for adblock.sh's set flow (v1.0.8 semantics).
#
# v1.0.7 made EVERY switch flip synchronously restart the daemon
# (stop, wait for full exit, start, verify): seconds of panel lag per
# flip, and a QUIC flip was reported as "保存失败" whenever the old
# daemon needed longer than the wait budget to exit — although the
# config value had already been written.
#
# v1.0.8 semantics asserted here, against the REAL adblock.sh (copied,
# DATA repointed at a temp dir) and a fake nora-adblockd that exits
# SLOWLY (~2.5s) after SIGTERM:
#   1. set <filter/logging switch> only writes the config and
#      returns ok immediately — it must NOT call --stop at all and the
#      daemon pid must be unchanged (hot-apply is the daemon's job).
#   2. set ENABLED 0 still waits for the slow old daemon to fully exit
#      before reporting ok (the v1.0.6/v1.0.7 guarantee must not regress).
#   3. set ENABLED 1 then brings up a NEW pid and verifies it runs.
#
# Run: sh daemon/set_flow_stub_test.sh   (exit 0 = pass)
set -u
SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ADB="$SRC_DIR/../module/adblock.sh"
[ -f "$ADB" ] || { echo "FAIL: adblock.sh not found at $ADB"; exit 1; }

TMP=$(mktemp -d)
MOD="$TMP/mod"
DATA="$TMP/data"
mkdir -p "$MOD" "$DATA"
cleanup() {
  if [ -f "$DATA/daemon.pid" ]; then kill -9 "$(cat "$DATA/daemon.pid")" 2>/dev/null; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# --- fake daemon body: writes its pid, exits ~2.5s after SIGTERM ---
cat > "$MOD/stub_body.sh" <<'EOF'
#!/bin/sh
echo $$ > "$STUB_PIDFILE"
trap 'sleep 2.5; rm -f "$STUB_PIDFILE"; exit 0' TERM INT
while true; do sleep 0.2; done
EOF

# --- fake nora-adblockd binary with the real CLI surface adblock.sh uses;
#     every --stop invocation is counted in $DATA/stop_calls ---
cat > "$MOD/nora-adblockd" <<EOF
#!/bin/sh
PIDFILE="$DATA/daemon.pid"
case "\$1" in
--status)
  if [ -f "\$PIDFILE" ]; then
    pid=\$(cat "\$PIDFILE")
    if kill -0 "\$pid" 2>/dev/null; then echo "running pid=\$pid"; exit 0; fi
  fi
  echo "stopped" ;;
--stop)
  echo x >> "$DATA/stop_calls"
  if [ -f "\$PIDFILE" ]; then kill -TERM "\$(cat "\$PIDFILE")" 2>/dev/null; fi
  echo "nora-adblockd: rules cleared, daemon signalled" ;;
--start)
  STUB_PIDFILE="\$PIDFILE" setsid sh "$MOD/stub_body.sh" >/dev/null 2>&1 &
  i=0
  while [ "\$i" -lt 30 ]; do
    [ -f "\$PIDFILE" ] && break
    sleep 0.1; i=\$((i + 1))
  done
  ;;
esac
EOF
chmod 755 "$MOD/nora-adblockd" "$MOD/stub_body.sh"

# --- real adblock.sh, DATA repointed at the temp dir ---
sed "s|^DATA=.*|DATA=$DATA|" "$ADB" > "$MOD/adblock.sh"
chmod 755 "$MOD/adblock.sh"
printf 'ENABLED=1\nDNS_FILTER=1\nSNI_FILTER=1\nQUIC_FILTER=1\nLOGGING=1\n' > "$DATA/config"
: > "$DATA/stop_calls"

pid_of() { "$MOD/nora-adblockd" --status | sed -n 's/^running pid=\([0-9]*\)/\1/p'; }
stops() { wc -l < "$DATA/stop_calls" | tr -d ' '; }
now_ms() { date +%s%N 2>/dev/null || echo $(( $(date +%s) * 1000 )); }
fail() { echo "FAIL: $1"; exit 1; }

# 1) start: must come up and report a pid
out=$(sh "$MOD/adblock.sh" start) || fail "start exited non-zero: $out"
[ "$out" = "ok" ] || fail "start output not ok: $out"
pid1=$(pid_of)
[ -n "$pid1" ] || fail "no pid after start"
echo "started: pid=$pid1"

# 2) hot switches: fast ok, no --stop, same pid, config written
for kv in "QUIC_FILTER 0" "DNS_FILTER 0" "SNI_FILTER 0" "LOGGING 0"; do
  key=${kv% *}; val=${kv#* }
  t0=$(now_ms)
  out=$(sh "$MOD/adblock.sh" set "$key" "$val") || fail "set $key exited non-zero: $out"
  t1=$(now_ms)
  [ "$out" = "ok" ] || fail "set $key output not ok: $out"
  ms=$(( (t1 - t0) / 1000000 ))
  [ "$ms" -lt 2000 ] || fail "set $key took ${ms}ms — hot switches must return immediately"
  grep -q "^$key=$val" "$DATA/config" || fail "$key=$val not written to config"
  [ "$(pid_of)" = "$pid1" ] || fail "set $key changed the daemon pid — hot switches must not restart the daemon"
  echo "set $key $val: ok in ${ms}ms, daemon untouched"
done
[ "$(stops)" = "0" ] || fail "hot switches called --stop $(stops) time(s) — they must never restart the daemon"

# 3) set ENABLED 0: must wait out the slow (~2.5s) exit, then be stopped
t0=$(date +%s)
out=$(sh "$MOD/adblock.sh" set ENABLED 0) || fail "set ENABLED 0 exited non-zero: $out"
t1=$(date +%s)
[ "$out" = "ok" ] || fail "set ENABLED 0 output not ok: $out"
elapsed=$((t1 - t0))
[ "$elapsed" -ge 2 ] || fail "set ENABLED 0 returned in ${elapsed}s — it did not wait for the slow-exiting daemon"
"$MOD/nora-adblockd" --status | grep -q '^stopped' || fail "daemon still running after set ENABLED 0"
grep -q '^ENABLED=0' "$DATA/config" || fail "ENABLED=0 not written to config"
echo "set ENABLED 0: waited ${elapsed}s, daemon fully exited"

# 4) set ENABLED 1: must bring up a NEW pid and verify it
out=$(sh "$MOD/adblock.sh" set ENABLED 1) || fail "set ENABLED 1 exited non-zero: $out"
[ "$out" = "ok" ] || fail "set ENABLED 1 output not ok: $out"
pid2=$(pid_of)
[ -n "$pid2" ] || fail "daemon not running after set ENABLED 1"
[ "$pid2" != "$pid1" ] || fail "pid did not change across ENABLED off->on ($pid1 -> $pid2)"
echo "set ENABLED 1: new pid $pid2 (was $pid1)"

# 5) stop command still waits for full exit
out=$(sh "$MOD/adblock.sh" stop) || fail "stop exited non-zero: $out"
[ "$out" = "ok" ] || fail "stop output not ok: $out"
"$MOD/nora-adblockd" --status | grep -q '^stopped' || fail "daemon still running after stop"
echo "stop: daemon fully exited"

echo "PASS: hot switches are instant and restart-free; ENABLED keeps the wait-and-verify flow"
