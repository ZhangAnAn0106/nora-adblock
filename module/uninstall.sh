#!/system/bin/sh
# 卸载时停守护进程并清干净自家 iptables 链（NORA_ADBLOCK）。
MODDIR=${0%/*}
"$MODDIR/nora-adblockd" --stop >/dev/null 2>&1
# 兜底：万一二进制不在，手动删链
for bin in iptables ip6tables; do
  command -v "$bin" >/dev/null 2>&1 || continue
  "$bin" -w -t mangle -D OUTPUT -j NORA_ADBLOCK 2>/dev/null
  "$bin" -w -t mangle -F NORA_ADBLOCK 2>/dev/null
  "$bin" -w -t mangle -X NORA_ADBLOCK 2>/dev/null
done
