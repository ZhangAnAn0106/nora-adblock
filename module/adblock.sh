#!/system/bin/sh
# 广告拦截 WebUI 后端： sh adblock.sh <命令> [参数]
# 命令: status | recent | log | allow <域名> | get-userwhite | get-userblock
#       save-userwhite <base64> | save-userblock <base64>
#       set <ENABLED|DNS_FILTER|SNI_FILTER|LOGGING> <0|1> | start | stop
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

is_running() {
  "$BIN" --status 2>/dev/null | grep -q '^running'
}

start_daemon() {
  is_running && return 0
  if command -v setsid >/dev/null 2>&1; then
    setsid "$BIN" --start >/dev/null 2>&1 &
  else
    nohup "$BIN" --start >/dev/null 2>&1 &
  fi
  sleep 1
  is_running
}

case "$1" in
status)
  if is_running; then echo "running=1"; else echo "running=0"; fi
  echo "enabled=$(cfg_get ENABLED)"
  echo "dns_filter=$(cfg_get DNS_FILTER)"
  echo "sni_filter=$(cfg_get SNI_FILTER)"
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
  if printf '%s' "$2" | base64 -d > "$tmp" 2>/dev/null && [ -s "$tmp" ] && [ "$(wc -c < "$tmp")" -lt 262144 ]; then
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
  case "$key" in ENABLED|DNS_FILTER|SNI_FILTER|LOGGING) ;; *) echo "error: bad key"; exit 1 ;; esac
  case "$val" in 0|1) ;; *) echo "error: bad value"; exit 1 ;; esac
  cfg_set "$key" "$val"
  if [ "$key" = "ENABLED" ]; then
    if [ "$val" = "0" ]; then
      "$BIN" --stop >/dev/null 2>&1
    else
      start_daemon >/dev/null 2>&1
    fi
  elif [ "$key" = "LOGGING" ]; then
    # 守护进程每 15 秒重读 config 自动感知日志开关, 不重启; 计数不受影响
    :
  elif is_running; then
    # 过滤开关变化需要重启守护进程才生效
    "$BIN" --stop >/dev/null 2>&1
    sleep 1
    start_daemon >/dev/null 2>&1
  fi
  echo "ok"
  ;;
start)
  cfg_set ENABLED 1
  start_daemon && echo "ok" || echo "error: start failed"
  ;;
stop)
  cfg_set ENABLED 0
  "$BIN" --stop >/dev/null 2>&1
  echo "ok"
  ;;
*)
  echo "error: unknown command"
  exit 1
  ;;
esac
