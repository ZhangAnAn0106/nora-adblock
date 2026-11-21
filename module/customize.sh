#!/system/bin/sh
# 广告拦截（自研 NFQUEUE）安装脚本
# 只带 arm64 二进制；配置与名单只在缺失时播种，已有文件一律不覆盖。

if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "" ]; then
  abort "仅支持 arm64 设备（当前: $ARCH）"
fi

DATA=/data/adb/nora_adblock
mkdir -p "$DATA"

seed() {
  if [ ! -f "$DATA/$1" ]; then
    cp "$MODPATH/data/$1" "$DATA/$1"
    ui_print "- 已写入默认 $1"
  else
    ui_print "- 保留已有 $1（不覆盖）"
  fi
}

seed config
# v1.0.2 新增 LOGGING 键: 已有 config 缺这行时只补一行, 不动其它配置
if [ -f "$DATA/config" ] && ! grep -q '^LOGGING=' "$DATA/config"; then
  echo "LOGGING=1" >> "$DATA/config"
  ui_print "- 已为已有 config 补上 LOGGING=1"
fi
seed blocklist.txt
seed whitelist.txt
seed user_blocklist.txt
seed user_whitelist.txt

# v1.0.3: 安装时检测 BoxProxy 是否存在, 结果写运行状态 boxproxy.state
# (不是用户配置; 守护进程每次启动还会复查, 装/卸 BoxProxy 自动跟随)。
# 豁免按需启用: 没装 BoxProxy 就不下发它的 mark/应用 uid 豁免规则。
BP_PKG=com.boxproxy.box
BP_STATE=absent
if pm path "$BP_PKG" >/dev/null 2>&1; then
  BP_STATE=present
elif grep -q "^$BP_PKG " /data/system/packages.list 2>/dev/null; then
  BP_STATE=present
elif [ -d "/data/data/$BP_PKG" ]; then
  BP_STATE=present
fi
if [ "$BP_STATE" = "present" ]; then BP_EXEMPT=on; else BP_EXEMPT=off; fi
{
  echo "boxproxy=$BP_STATE"
  echo "exemptions=$BP_EXEMPT"
  echo "checked=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
} > "$DATA/boxproxy.state"
chmod 644 "$DATA/boxproxy.state" 2>/dev/null
ui_print "- BoxProxy 检测: $BP_STATE（代理豁免 $BP_EXEMPT）"

chmod 755 "$MODPATH/nora-adblockd" "$MODPATH/adblock.sh" "$MODPATH/service.sh" "$MODPATH/uninstall.sh" 2>/dev/null
chmod 644 "$DATA/config" "$DATA/blocklist.txt" "$DATA/whitelist.txt" "$DATA/user_blocklist.txt" "$DATA/user_whitelist.txt" 2>/dev/null

ui_print "- 广告拦截模块安装完成，重启后生效"
if [ "$BP_STATE" = "present" ]; then
  ui_print "- 已检测到 BoxProxy：代理核心(uid 0)/应用 uid/代理 mark 豁免已启用"
else
  ui_print "- 未检测到 BoxProxy：代理豁免未启用（日后装上会自动生效，无需重刷）"
fi
