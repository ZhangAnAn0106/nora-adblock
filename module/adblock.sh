#!/system/bin/sh
# 广告拦截 WebUI 后端： sh adblock.sh <命令> [参数]
# 命令: status | recent | log | allow <域名> | get-userwhite | get-userblock
#       save-userwhite <base64> | save-userblock <base64>
#       set <ENABLED|DNS_FILTER|SNI_FILTER|QUIC_FILTER|LOGGING> <0|1> | start | stop
# 计数数据源: $DATA/blocked_stats (与日志开关无关); daemon.log/blocked.log 受 LOGGING 管辖
MODDIR=${0%/*}
DATA=/data/adb/nora_adblock
BIN="$MODDIR/nora-adblockd"
CFG="$DATA/config"

cfg_get() {
  grep "^$1=" "$CFG" 2>/dev/null | head -1 | cut -d= -f2
}

cfg_set() {
  tmp="$CFG.tmp"
  grep -v "^$1=" "$CFG" 2>/dev/null > "$tmp"
  echo "$1=$2" >> "$tmp"
  mv "$tmp" "$CFG"
}

count_domains() {
  [ -f "$1" ] || { echo 0; return; }
  grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" 2>/dev/null | wc -l | tr -d ' '
}

file_bytes() {
  [ -f "$1" ] && wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0
}

PIDFILE="$DATA/daemon.pid"

# 判活只读 pid 文件 + kill -0, 不 spawn 守护二进制: v1.0.7 每次判活都跑
# 一次 "$BIN" --status (Go 二进制冷启动), 等待循环里 0.1 秒一次、几秒
# 就是几十次, 是开关卡顿的来源之一。
pidfile_pid() {
  pid=$(cat "$PIDFILE" 2>/dev/null | tr -d ' \r\n')
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  echo "$pid"
}

current_pid() {
  pid=$(pidfile_pid)
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    echo "$pid"
  fi
}

is_running() {
  [ -n "$(current_pid)" ]
}

# wait_stopped polls until the daemon has FULLY exited (pid dead):
# $1 = max polls of 0.2s (default 25 ≈ 5s). v1.0.6 bug: set only slept
# 1s after --stop (which merely sends SIGTERM); a slow-exiting old
# daemon still looked "running", start_daemon then skipped starting a
# new one, and when the old daemon finally exited it took the rules
# chain with it — filtering and blocking stats all silently stopped.
# Only the ENABLED on/off path (and start/stop) still pays
# this wait; filter switches are hot since v1.0.8 and never restart
# the daemon.
wait_stopped() {
  n=${1:-25}
  i=0
  while [ "$i" -lt "$n" ]; do
    is_running || return 0
    sleep 0.2
    i=$((i + 1))
  done
  ! is_running
}

# shell 侧清链: 与守护 teardownCommands 等价 (删 OUTPUT 跳转、-F、-X
# 自建链), iptables 与 ip6tables 都做。只在守护自己没能清链的兜底
# 路径里用 (正常退出时守护已清, 这里是幂等的重复劳动)。
clear_chain_shell() {
  for b in iptables ip6tables; do
    command -v "$b" >/dev/null 2>&1 || continue
    i=0
    while [ "$i" -lt 4 ]; do
      "$b" -w -t mangle -D OUTPUT -j NORA_ADBLOCK 2>/dev/null || break
      i=$((i + 1))
    done
    "$b" -w -t mangle -F NORA_ADBLOCK 2>/dev/null
    "$b" -w -t mangle -X NORA_ADBLOCK 2>/dev/null
  done
}

# 链是否已清干净: 以 OUTPUT 里查不到跳转为准 (任一协议栈还挂着都算没清)。
chain_gone() {
  for b in iptables ip6tables; do
    command -v "$b" >/dev/null 2>&1 || continue
    if "$b" -w -t mangle -C OUTPUT -j NORA_ADBLOCK 2>/dev/null; then
      return 1
    fi
  done
  return 0
}

# stop_daemon 的兜底阶梯 (v1.1.0): --stop 只是发信号, 守护若卡在
# 队列关闭等路径上退不出来, 以前等满约 5 秒就只报 error 收场——
# config 已是 ENABLED=0、守护却还活着还在拦 (真机「总开关关不掉」)。
# 现在逐级加压, 全部做完并校验通过才算停成功:
#   --stop → 等约 5 秒 → 对 pid 直发 TERM → 等约 2 秒 → kill -9 →
#   shell 自己清链 → 校验进程已死且链已消失 → 清残留 pid 文件。
stop_daemon() {
  "$BIN" --stop >/dev/null 2>&1
  if wait_stopped; then
    return 0
  fi
  pid=$(pidfile_pid)
  if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null
    if wait_stopped 10; then
      clear_chain_shell
      rm -f "$PIDFILE"
      chain_gone
      return $?
    fi
  fi
  pid=$(pidfile_pid)
  if [ -n "$pid" ]; then
    kill -9 "$pid" 2>/dev/null
    wait_stopped 10
  fi
  clear_chain_shell
  if is_running; then
    echo "error: daemon still running after forced stop" >&2
    return 1
  fi
  rm -f "$PIDFILE"
  if ! chain_gone; then
    echo "error: chain NORA_ADBLOCK still hooked after cleanup" >&2
    return 1
  fi
  return 0
}

start_daemon() {
  # Already running: nothing to start (stop flows wait for full exit first).
  [ -n "$(current_pid)" ] && return 0
  if command -v setsid >/dev/null 2>&1; then
    setsid "$BIN" --start >/dev/null 2>&1 &
  else
    nohup "$BIN" --start >/dev/null 2>&1 &
  fi
  # Verify the new daemon is really up (poll up to ~5s), don't trust spawn.
  i=0
  while [ "$i" -lt 25 ]; do
    [ -n "$(current_pid)" ] && return 0
    sleep 0.2
    i=$((i + 1))
  done
  echo "error: daemon did not start" >&2
  return 1
}

case "$1" in
status)
  if is_running; then echo "running=1"; else echo "running=0"; fi
  echo "enabled=$(cfg_get ENABLED)"
  echo "dns_filter=$(cfg_get DNS_FILTER)"
  echo "sni_filter=$(cfg_get SNI_FILTER)"
  qv=$(cfg_get QUIC_FILTER)
  echo "quic_filter=${qv:-1}"
  lv=$(cfg_get LOGGING)
  echo "logging=${lv:-1}"
  echo "daemon_log_bytes=$(file_bytes "$DATA/daemon.log")"
  echo "blocked_log_bytes=$(file_bytes "$DATA/blocked.log")"
  echo "rules=$(count_domains "$DATA/blocklist.txt")"
  echo "whitelist=$(count_domains "$DATA/whitelist.txt")"
  echo "user_rules=$(count_domains "$DATA/user_blocklist.txt")"
  echo "user_whitelist=$(count_domains "$DATA/user_whitelist.txt")"
  total=$(grep '^total=' "$DATA/blocked_stats" 2>/dev/null | cut -d= -f2)
  unique=$(grep '^unique=' "$DATA/blocked_stats" 2>/dev/null | cut -d= -f2)
  echo "today_total=${total:-0}"
  echo "today_unique=${unique:-0}"
  echo "proxy_marks=$(cfg_get PROXY_MARKS)"
  # v1.0.3: BoxProxy 实时检测 (多路兜底), 豁免按需启用
  bp=absent
  if grep -q '^com.boxproxy.box ' /data/system/packages.list 2>/dev/null; then
    bp=present
  elif [ -d /data/data/com.boxproxy.box ]; then
    bp=present
  elif pm path com.boxproxy.box >/dev/null 2>&1; then
    bp=present
  fi
  echo "boxproxy=$bp"
  if [ "$bp" = "present" ]; then
    echo "exemptions=on"
    echo "proxy_found=1"
    echo "proxy_uid=$(awk '$1=="com.boxproxy.box"{print $2; exit}' /data/system/packages.list 2>/dev/null)"
  else
    echo "exemptions=off"
    echo "proxy_found=0"
    echo "proxy_uid="
  fi
  ;;
recent)
  # 数据源是计数文件 blocked_stats (域名<空格>次数<空格>最近拦截unix时间, 文件内已按
  # 最近拦截时间倒序; 旧格式无时间字段时为两列, 时间按 0 处理), 与日志开关无关
  stats="$DATA/blocked_stats"
  [ -f "$stats" ] || exit 0
  grep -v '=' "$stats" 2>/dev/null | head -30
  ;;
log)
  tail -n 200 "$DATA/daemon.log" 2>/dev/null
  exit 0
  ;;
allow)
  d=$(printf '%s' "$2" | tr 'A-Z' 'a-z' | sed 's|^https\?://||; s|/.*$||; s|:.*$||; s|\.$||')
  case "$d" in
    ''|*[!a-z0-9.-]*|.*|*..*|*.) echo "error: bad domain"; exit 1 ;;
  esac
  case "$d" in *.*) ;; *) echo "error: bad domain"; exit 1 ;; esac
  touch "$DATA/user_whitelist.txt"
  if grep -Fxq "$d" "$DATA/user_whitelist.txt"; then
    echo "ok: already"
  else
    echo "$d" >> "$DATA/user_whitelist.txt"
    echo "ok"
  fi
  ;;
get-userwhite)
  cat "$DATA/user_whitelist.txt" 2>/dev/null
  ;;
get-userblock)
  cat "$DATA/user_blocklist.txt" 2>/dev/null
  ;;
save-userwhite|save-userblock)
  if [ "$1" = "save-userwhite" ]; then target="$DATA/user_whitelist.txt"; else target="$DATA/user_blocklist.txt"; fi
  tmp="$target.tmp"
  if printf '%s' "$2" | base64 -d > "$tmp" 2>/dev/null && [ "$(wc -c < "$tmp")" -lt 262144 ] && { [ -s "$tmp" ] || [ -z "$2" ]; }; then
    mv "$tmp" "$target"
    echo "ok"
  else
    rm -f "$tmp"
    echo "error: decode failed"
    exit 1
  fi
  ;;
set)
  key="$2"; val="$3"
  case "$key" in ENABLED|DNS_FILTER|SNI_FILTER|QUIC_FILTER|LOGGING) ;; *) echo "error: bad key"; exit 1 ;; esac
  case "$val" in 0|1) ;; *) echo "error: bad value"; exit 1 ;; esac
  cfg_set "$key" "$val"
  if [ "$key" = "ENABLED" ]; then
    # 总开关低频, 仍走停-等-拉-验: 保证旧守护退干净、新守护真的在跑,
    # 失败明确报 error (v1.0.7 的语义不变, 只是判活变廉价了)
    rc=0
    if [ "$val" = "0" ]; then
      stop_daemon || rc=1
    else
      start_daemon || rc=1
    fi
    if [ "$rc" != "0" ]; then
      echo "error: set $key=$val failed (daemon did not reach the requested state)"
      exit 1
    fi
  fi
  # 其余开关 (DNS_FILTER/SNI_FILTER/QUIC_FILTER/LOGGING) 只写配置
  # 立即返回 ok: 守护进程约 2 秒的快周期会感知并热生效 (过滤开关原地
  # 重下规则, 不重启守护)。v1.0.7 每次拨开关都同步重启守护, 面板卡几秒,
  # 且旧守护退出超过等待上限还会被误判成保存失败 (配置其实已经写入)。
  echo "ok"
  ;;
start)
  cfg_set ENABLED 1
  start_daemon && echo "ok" || { echo "error: start failed"; exit 1; }
  ;;
stop)
  cfg_set ENABLED 0
  stop_daemon && echo "ok" || { echo "error: daemon did not stop"; exit 1; }
  ;;
*)
  echo "error: unknown command"
  exit 1
  ;;
esac
