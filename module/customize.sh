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
# v1.0.5 新增 QUIC_FILTER 键: 已有 config 缺这行时只补一行, 不动其它配置
if [ -f "$DATA/config" ] && ! grep -q '^QUIC_FILTER=' "$DATA/config"; then
  echo "QUIC_FILTER=1" >> "$DATA/config"
  ui_print "- 已为已有 config 补上 QUIC_FILTER=1"
fi
# 公开版不生成 capture_stats: 清掉从其它版本刷过来时留下的残留文件,
# 并从已有 config 里删掉 CAPTURE 一行 (本版守护进程不读这个键)。
rm -f "$DATA/capture_stats" "$DATA/capture_stats.tmp"
if [ -f "$DATA/config" ] && grep -q '^CAPTURE=' "$DATA/config"; then
  grep -v '^CAPTURE=' "$DATA/config" > "$DATA/config.tmpc" && mv "$DATA/config.tmpc" "$DATA/config"
fi
# v1.1.1: 云端规则订阅功能下线 (用户明确要求移除, 属例外处理): 清理它在
# 数据目录的全部残留 (订阅链接、下载成果、按源缓存、状态、请求/勾选标志),
# 并从已有 config 里删掉 CLOUD_RULES / CLOUD_AUTO 两行; 内置名单、用户名单
# 与其它配置一律不动。
rm -f "$DATA/rule_sources.txt" "$DATA/cloud_blocklist.txt" "$DATA/cloud_status.txt" \
      "$DATA/cloud_request" "$DATA/cloud_selected.txt"
rm -rf "$DATA/cloud_src"
if [ -f "$DATA/config" ]; then
  if grep -v -e '^CLOUD_RULES=' -e '^CLOUD_AUTO=' "$DATA/config" > "$DATA/config.tmp111"; then
    mv "$DATA/config.tmp111" "$DATA/config"
    ui_print "- 已清理云端订阅残留 (v1.1.1 移除该功能)"
  else
    rm -f "$DATA/config.tmp111"
  fi
fi
# 内置拦截名单是离线快照、靠新版模块更新 (文件头有此说明), 每次安装都
# 刷新为包内最新版; 用户自己的名单在 user_blocklist.txt, 不受影响。
# v1.0.9 起改为刷新 (此前只播种, 升级用户拿不到新名单)。
cp "$MODPATH/data/blocklist.txt" "$DATA/blocklist.txt"
ui_print "- 已更新内置拦截名单 blocklist.txt"
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
