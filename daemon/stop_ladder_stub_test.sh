#!/bin/sh
# Stub test for the v1.1.0 stop fallback ladder + watchdog convergence.
#
# v1.0.9 on a real device: flipping the panel's total switch off wrote
# ENABLED=0, but the daemon did not die (its only stop path was the
# --stop signal, and adblock.sh just reported an error when the ~5s
# wait ran out) — the daemon kept filtering with the config saying off.
#
# Scenario A (forced-kill ladder): a fake daemon that IGNORES SIGTERM
# and never exits on its own. adblock.sh stop must still succeed:
# --stop -> wait -> TERM -> wait -> kill -9 -> shell-side chain cleanup
# (fake iptables records every call and tracks the OUTPUT hook state)
# -> process dead, hook gone for BOTH iptables and ip6tables, pid file
# removed, exit ok.
#
# Scenario B (watchdog convergence): the real service.sh (DATA
# repointed, getprop stubbed) with ENABLED=0 in the config and a
# normally-behaved daemon already running must converge: the watchdog
# notices and stops the daemon via adblock.sh.
#
# Run: sh daemon/stop_ladder_stub_test.sh   (exit 0 = pass)
set -u
SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODSRC="$SRC_DIR/../module"
[ -f "$MODSRC/adblock.sh" ] && [ -f "$MODSRC/service.sh" ] || { echo "FAIL: module scripts not found"; exit 1; }

fail() { echo "FAIL: $1"; exit 1; }

# ---------- shared fakes ----------
make_fake_iptables() {
  # $1 = dir to fill with fake iptables/ip6tables. State per binary:
  # $STUB_STATE/hook.<bin> exists <=> OUTPUT jump to NORA_ADBLOCK exists.
  d=$1
  mkdir -p "$d"
  for name in iptables ip6tables; do
    cat > "$d/$name" <<'EOF'
#!/bin/sh
bin=$(basename "$0")
echo "$bin $*" >> "$STUB_STATE/iptables.log"
state="$STUB_STATE/hook.$bin"
# strip leading -w (wait) flag pairs adblock.sh always passes
case "$1" in -w) shift 2>/dev/null ;; esac
op=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-t" ]; then prev=""; continue; fi
  case "$a" in
    -C|-D|-I|-F|-X|-N|-A) op=$a ;;
    -t) prev="-t" ;;
  esac
done
case "$op" in
  -C) [ -f "$state" ] && exit 0 || exit 1 ;;
  -I|-A) : > "$state"; exit 0 ;;
  -D) if [ -f "$state" ]; then rm -f "$state"; exit 0; else exit 1; fi ;;
  *) exit 0 ;;
esac
EOF
    chmod 755 "$d/$name"
  done
}

make_fake_bin() {
  # $1 = mod dir, $2 = data dir, $3 = body kind (stubborn|polite)
  mod=$1; data=$2; kind=$3
  if [ "$kind" = "stubborn" ]; then
    cat > "$mod/stub_body.sh" <<'EOF'
#!/bin/sh
# Ignores SIGTERM/SIGINT entirely; only SIGKILL can take it down.
trap '' TERM INT
echo $$ > "$STUB_PIDFILE"
while true; do sleep 0.2; done
EOF
  else
    cat > "$mod/stub_body.sh" <<'EOF'
#!/bin/sh
echo $$ > "$STUB_PIDFILE"
trap 'rm -f "$STUB_PIDFILE"; exit 0' TERM INT
while true; do sleep 0.2; done
EOF
  fi
  cat > "$mod/nora-adblockd" <<EOF
#!/bin/sh
PIDFILE="$data/daemon.pid"
case "\$1" in
--status)
  if [ -f "\$PIDFILE" ]; then
    pid=\$(cat "\$PIDFILE")
    if kill -0 "\$pid" 2>/dev/null; then echo "running pid=\$pid"; exit 0; fi
  fi
  echo "stopped" ;;
--stop)
  echo x >> "$data/stop_calls"
  if [ -f "\$PIDFILE" ]; then kill -TERM "\$(cat "\$PIDFILE")" 2>/dev/null; fi
  echo "nora-adblockd: rules cleared, daemon signalled" ;;
--start)
  STUB_PIDFILE="\$PIDFILE" setsid sh "$mod/stub_body.sh" >/dev/null 2>&1 &
  i=0
  while [ "\$i" -lt 30 ]; do
    [ -f "\$PIDFILE" ] && break
    sleep 0.1; i=\$((i + 1))
  done
  ;;
esac
EOF
  chmod 755 "$mod/nora-adblockd" "$mod/stub_body.sh"
}

# ================= Scenario A: forced-kill ladder =================
TMP=$(mktemp -d)
MOD="$TMP/mod"; DATA="$TMP/data"; FAKEBIN="$TMP/bin"; STATE="$TMP/state"
mkdir -p "$MOD" "$DATA" "$STATE"
cleanup_a() {
  if [ -f "$DATA/daemon.pid" ]; then kill -9 "$(cat "$DATA/daemon.pid")" 2>/dev/null; fi
  rm -rf "$TMP"
}
trap cleanup_a EXIT INT TERM

make_fake_iptables "$FAKEBIN"
make_fake_bin "$MOD" "$DATA" stubborn
sed "s|^DATA=.*|DATA=$DATA|" "$MODSRC/adblock.sh" > "$MOD/adblock.sh"
chmod 755 "$MOD/adblock.sh"
printf 'ENABLED=1\nDNS_FILTER=1\nSNI_FILTER=1\nQUIC_FILTER=1\nLOGGING=1\n' > "$DATA/config"
: > "$DATA/stop_calls"
export STUB_STATE="$STATE"

# chain hooked, as a running daemon would have left it (both stacks)
PATH="$FAKEBIN:$PATH" iptables -w -t mangle -I OUTPUT 1 -j NORA_ADBLOCK
PATH="$FAKEBIN:$PATH" ip6tables -w -t mangle -I OUTPUT 1 -j NORA_ADBLOCK
: > "$STATE/iptables.log"

# start the stubborn daemon
sh "$MOD/adblock.sh" start >/dev/null 2>&1 || fail "A: start failed"
pid1=$(cat "$DATA/daemon.pid")
kill -0 "$pid1" 2>/dev/null || fail "A: stubborn daemon not running after start"
echo "A: stubborn daemon running pid=$pid1 (ignores SIGTERM)"

t0=$(date +%s)
out=$(PATH="$FAKEBIN:$PATH" sh "$MOD/adblock.sh" stop) || fail "A: stop exited non-zero: $out"
t1=$(date +%s)
[ "$out" = "ok" ] || fail "A: stop output not ok: $out"
elapsed=$((t1 - t0))
[ "$elapsed" -ge 5 ] || fail "A: stop returned in ${elapsed}s — the ladder did not wait out the TERM stages"
kill -0 "$pid1" 2>/dev/null && fail "A: stubborn daemon still alive after stop"
[ ! -f "$DATA/daemon.pid" ] || fail "A: pid file left behind after stop"
"$MOD/nora-adblockd" --status | grep -q '^stopped' || fail "A: --status not stopped after stop"
grep -q '^ENABLED=0' "$DATA/config" || fail "A: ENABLED=0 not written"
# shell-side cleanup must have removed the hook on BOTH stacks
for b in iptables ip6tables; do
  grep -q "^$b -w -t mangle -D OUTPUT -j NORA_ADBLOCK" "$STATE/iptables.log" || fail "A: no shell -D OUTPUT for $b"
  grep -q "^$b -w -t mangle -F NORA_ADBLOCK" "$STATE/iptables.log" || fail "A: no shell -F for $b"
  grep -q "^$b -w -t mangle -X NORA_ADBLOCK" "$STATE/iptables.log" || fail "A: no shell -X for $b"
  PATH="$FAKEBIN:$PATH" "$b" -w -t mangle -C OUTPUT -j NORA_ADBLOCK 2>/dev/null && fail "A: OUTPUT hook still present for $b"
done
echo "A: stop ladder killed the stubborn daemon in ${elapsed}s, chain cleaned on both stacks"
trap - EXIT INT TERM
cleanup_a

# ================= Scenario B: watchdog convergence =================
TMP=$(mktemp -d)
MOD="$TMP/mod"; DATA="$TMP/data"; FAKEBIN="$TMP/bin"; STATE="$TMP/state"
mkdir -p "$MOD" "$DATA" "$STATE"
cleanup_b() {
  [ -n "${SVC_PID:-}" ] && kill -9 "$SVC_PID" 2>/dev/null
  if [ -f "$DATA/daemon.pid" ]; then kill -9 "$(cat "$DATA/daemon.pid")" 2>/dev/null; fi
  rm -rf "$TMP"
}
trap cleanup_b EXIT INT TERM

make_fake_iptables "$FAKEBIN"
make_fake_bin "$MOD" "$DATA" polite
sed "s|^DATA=.*|DATA=$DATA|" "$MODSRC/adblock.sh" > "$MOD/adblock.sh"
sed "s|^DATA=.*|DATA=$DATA|" "$MODSRC/service.sh" > "$MOD/service.sh"
chmod 755 "$MOD/adblock.sh" "$MOD/service.sh"
# getprop stub: boot already completed
printf '#!/bin/sh\necho 1\n' > "$FAKEBIN/getprop"
chmod 755 "$FAKEBIN/getprop"
export STUB_STATE="$STATE"

# daemon already running (started by some other path), THEN user turns
# the module off in the config
printf 'ENABLED=1\n' > "$DATA/config"
"$MOD/nora-adblockd" --start
pid2=$(cat "$DATA/daemon.pid")
kill -0 "$pid2" 2>/dev/null || fail "B: daemon not running at scenario start"
printf 'ENABLED=0\n' > "$DATA/config"

PATH="$FAKEBIN:$PATH" sh "$MOD/service.sh" >/dev/null 2>&1 &
SVC_PID=$!
i=0
while [ "$i" -lt 40 ]; do
  kill -0 "$pid2" 2>/dev/null || break
  sleep 0.5; i=$((i + 1))
done
kill -0 "$pid2" 2>/dev/null && fail "B: watchdog did not stop the daemon while ENABLED=0"
echo "B: watchdog converged the off state (daemon stopped without any panel action)"
kill -9 "$SVC_PID" 2>/dev/null
SVC_PID=""
trap - EXIT INT TERM
cleanup_b

echo "PASS: stop ladder force-kills a SIGTERM-ignoring daemon and cleans the chain; watchdog converges ENABLED=0"
