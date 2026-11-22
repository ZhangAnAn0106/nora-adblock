#!/system/bin/sh
# 开机拉起守护进程并看护：死了重拉（连续失败退避），ENABLED=0 时不拉；
# 且关状态要收敛：ENABLED=0 而守护还在跑时，看护主动把它停掉（v1.1.0）。
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
  else
    # 关状态收敛：config 已是 ENABLED=0 却还有守护在跑（面板关开关时
    # --stop 超时、或守护被别的路径拉起来过），看护负责停掉它。停的
    # 逻辑不另写一份：直接调 adblock.sh 的 stop（内含等退、强杀兜底
    # 与 shell 清链校验），避免两套实现漂移。守护自身也会在约 2 秒
    # 的维护周期里感知 ENABLED=0 自退，这里是第二重保险。
    if "$BIN" --status 2>/dev/null | grep -q '^running'; then
      sh "$MODDIR/adblock.sh" stop >/dev/null 2>&1
    fi
  fi
  s=5
  [ "$fail" -ge 2 ] && s=15
  [ "$fail" -ge 4 ] && s=30
  [ "$fail" -ge 6 ] && s=60
  sleep "$s"
done
