#!/system/bin/sh
# 开机拉起守护进程并看护：死了重拉（连续失败退避），ENABLED=0 时不拉。
MODDIR=${0%/*}
DATA=/data/adb/nora_adblock
BIN="$MODDIR/nora-adblockd"

until [ "$(getprop sys.boot_completed)" = "1" ]; do
  sleep 2
done
sleep 5

fail=0
while true; do
  if grep -q '^ENABLED=1' "$DATA/config" 2>/dev/null; then
    if ! "$BIN" --status 2>/dev/null | grep -q '^running'; then
      # daemon.log 由守护进程自己写(受 LOGGING 开关与轮转管辖), 这里不再重定向
      "$BIN" --start >/dev/null 2>&1 &
      dpid=$!
      sleep 5
      if kill -0 "$dpid" 2>/dev/null; then
        fail=0
        wait "$dpid" 2>/dev/null
        # 正常运行后退出（被停/崩溃）计一次失败，走退避
        fail=$((fail + 1))
      else
        fail=$((fail + 1))
      fi
    fi
  fi
  s=5
  [ "$fail" -ge 2 ] && s=15
  [ "$fail" -ge 4 ] && s=30
  [ "$fail" -ge 6 ] && s=60
  sleep "$s"
done
