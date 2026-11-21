# 广告拦截（自研 NFQUEUE）

独立模块，平板与手机通用（arm64），KernelSU / APatch / Magisk 均可安装。
与市面同类（如 YH-Hosts）的区别：**开源自研、无授权验证、不联网拉规则**，名单为离线快照；
且专门与 **BoxProxy 透明代理** 做共存适配（见下节）。

## 版本记录

- **1.0.4**：「最近拦截」能看出哪个是新拦的。计数文件 `blocked_stats` 的域名行
  增加第三列——最近一次拦截的 unix 时间戳（格式 `域名 次数 时间戳`），随计数
  一起按原 flush 节奏落盘、跨重启保留，跨天与计数一同清零；旧格式（两列、无
  时间）文件可正常读入，时间按 0 处理、当天计数不丢，首次 flush 后自动升级为
  新格式。文件内域名行按最近拦截时间倒序写入；面板「最近拦截」再按时间倒序
  渲染（同时间按次数倒序），每行显示相对时间：60 秒内「刚刚」、1 小时内
  「N 分钟前」、6 小时内「N 小时前」、今天更早显示 HH:MM、无时间显示「—」，
  次数保留。`adblock.sh recent` 输出同步带时间列。
- **1.0.3**：BoxProxy 豁免改为按需启用。安装时（customize.sh）多路检测
  `com.boxproxy.box`（pm 查询 / packages.list / /data/data 目录），结果写入运行状态
  `/data/adb/nora_adblock/boxproxy.state`（present/absent + 检测时间，不进用户配置）；
  守护进程每次启动复查一次、运行中每 15 秒跟随，装/卸 BoxProxy 与安装时结果不一致时
  记一条运行日志并自动重下发规则，无需重刷模块。未检测到 BoxProxy 时：链里不下发
  三条 fwmark 豁免与 BoxProxy 应用 uid 豁免，守护进程内的 mark/uid 二次跳过同步关闭；
  回环与 uid 0（root）两条通用安全豁免保留不动。检测到时行为与 1.0.2 完全一致。
  面板状态卡跟随显示「BoxProxy 已豁免（uid X）」/「未安装 BoxProxy，代理豁免未启用」，
  status 新增 `boxproxy=present|absent` 与 `exemptions=on|off` 字段。
- **1.0.2**：新增运行日志与计数分离。守护进程运行日志 `daemon.log`（启动/停止、名单
  加载与热重载条数、队列挂载、BoxProxy uid 解析与豁免、异常）带时间戳写入，面板新增
  「运行日志」区（开关 + 最近日志 + 文件大小）；配置新增 `LOGGING` 开关，只管
  `daemon.log` 与明细日志 `blocked.log` 写不写。拦截计数独立存入计数文件
  `blocked_stats`（持久化、跨重启保留当日数据），面板「今日拦截 / 最近拦截」改读它，
  与日志开关彻底脱钩。全部数据文件硬封顶：两类日志单个 512 KiB、轮转只留 1 个备份
  （总计约 2 MiB）；计数只留当天、域名封顶 500 条（超限淘汰次数最少的）。
  module.prop 作者改为桉桉。
- **1.0.1**：面板桥接修复——移植调度面板的探测桥。旧版在页面首跑瞬间只查一次
  `window.ksu`，KernelSU 的桥注入稍晚一步就被误判“没有 ksu 桥”、状态全是占位假值、
  按钮不可用。新版启动先轮询等桥注入（间隔递增，总计约 3 秒），再用只读命令实测
  exec 形态（3 参数优先、失败回退 2 参数）并缓存，`moduleInfo()` 定位模块目录；
  黄条只在桥始终没出现时才显示。守护进程、名单、规则均不变。
- **1.0.0**：首版（NFQUEUE 双层过滤 + BoxProxy 共存豁免 + 名单四级优先级 + WebUI 面板）。

## 原理

守护进程 `nora-adblockd`（Go 纯静态编译，无 cgo）通过 NFQUEUE 收包，两层按域名过滤：

1. **DNS 拦截**：mangle OUTPUT 自建链 `NORA_ADBLOCK` 把 53 端口（UDP/TCP）的查询送队列 0，
   解析查询域名，命中名单直接 DROP，未命中放行。
2. **SNI 拦截**：TCP 443/8443/80 只收连接前 8 个包（connbytes），解析 TLS ClientHello 的
   SNI / HTTP Host 头，命中 DROP；解析不出（分片、非 TLS、ECH 等）一律放行，绝不因不确定误拦。
   已判定的流在内存表里记 120 秒，后续包按结论直行。

全部队列带 `--queue-bypass`：守护进程万一挂了，流量自动直通，**不断网**。
iptables 只动自建链 `NORA_ADBLOCK`，启停都负责清干净，不碰别人的链。

## 与 BoxProxy 共存

本模块可与 BoxProxy（包名 `com.boxproxy.box`）同时使用，互不干扰：

- 本模块只处理自建链 `NORA_ADBLOCK`，不碰其它软件的规则；
- 检测到 BoxProxy 已安装时，自动豁免其流量：代理核心（以 root 身份运行）的出站
  连接与 DNS、带代理标记的数据包、以及 BoxProxy 应用自身的流量都不进过滤队列，
  代理分流不受影响；
- **豁免按需启用（v1.0.3 起）**：安装时检测一次，守护进程启动与运行中持续复查；
  没装 BoxProxy 的设备上不下发任何代理豁免。回环与 uid 0 是通用安全豁免
  （防系统与 root 流量被误伤），始终保留；
- 普通 App 的流量先过本模块过滤、再进 BoxProxy 分流。豁免参数可在
  `/data/adb/nora_adblock/config` 里调整（`PROXY_UIDS` / `PROXY_PACKAGES` / `PROXY_MARKS`）。

## 名单与优先级

判定顺序（高 → 低）：

1. `user_whitelist.txt`（我的放行，WebUI 可编辑）
2. `whitelist.txt`（内置保险白名单：微信/QQ 通信与支付、支付宝、一加/OPPO 系统服务、
   系统更新与时间同步、和平精英登录与对局关键域）
3. `user_blocklist.txt`（我的拦截，WebUI 可编辑）
4. `blocklist.txt`（内置 anti-AD 域名版离线快照）

- 内置快照来源：**https://anti-ad.net/domains.txt**（anti-AD），拉取日期 **2026-11-21**，
  共 110,355 条（文件头有原始版本注释）。
- 匹配方式为域名后缀匹配：写 `example.com` 即覆盖其全部子域。
- 四个文件都按 mtime 热重载，改完秒生效，不用重启。
- **不做云端自动拉取、不做授权验证。** 名单更新方式：出新版模块，或手动替换
  `/data/adb/nora_adblock/blocklist.txt`。用户名单（user_*.txt）单独存放，模块升级不覆盖。

## 运行日志与计数

- **运行日志** `daemon.log`：记录启动/停止、名单加载与热重载（各名单条数）、队列
  挂载/清除、BoxProxy uid 解析结果与豁免生效情况、错误与异常，带时间戳。
  面板「运行日志」区可看最近 200 行与当前文件大小，也可直接看文件。
- **明细日志** `blocked.log`：每次 flush 追加一批被拦域名计数，供事后查明细。
- **计数文件** `blocked_stats`：面板「今日拦截 / 最近拦截」的唯一数据源。按域名
  累计当天次数并记最近一次拦截时间（`域名 次数 unix时间戳`），持久化落盘、
  跨重启保留当日数据；跨天自动清零重计；域名条数封顶 500，超限淘汰次数最少的。
- **日志开关** `LOGGING`（配置或面板）：只管 `daemon.log` 与 `blocked.log` 写不写。
  关掉后拦截照常、计数照常累计，面板计数不受任何影响。
- **容量封顶**：`daemon.log`、`blocked.log` 单个上限 512 KiB，轮转只留 1 个备份，
  两类日志总占用约 2 MiB 封顶，不会越长越大。

## 使用说明：自己放行 / 拦截一个域名

- **放行（处理误杀）**：打开模块 WebUI →「最近拦截」里找到被误杀的域名 → 点「放行」，
  即自动写入放行名单并立即生效；也可以在「我的名单 → 放行名单」里手动加一行域名再保存。
- **拦截**：在「我的名单 → 拦截名单」里加一行域名（如 `ads.example.com`）保存即可，
  其全部子域一并拦截。
- 命令行党也可以直接编辑 `/data/adb/nora_adblock/user_whitelist.txt` /
  `user_blocklist.txt`，保存即生效。
- 查误杀：看面板「最近拦截」，或计数文件 `/data/adb/nora_adblock/blocked_stats`
  （当天按域名计数，只记域名和次数，不记任何流量内容）；明细在 `blocked.log`
  （受 `LOGGING` 开关管辖，单个 512 KiB 自动轮转）。

## v1 边界

- **QUIC（UDP 443）v1 放行**，不拦截：QUIC 的 SNI 在加密载荷里，v1 不做解密解析；
  走 QUIC 的广告域名暂时拦不到（多数 App 会回落或另有域名走 DNS/SNI 层被拦）。
- SNI 只看连接首包里的 ClientHello；用了 ECH 的连接看不到域名，只能靠 DNS 层拦。
- 名单是离线快照，不自动联网更新（见上）。
- 无授权验证、无联网回传：守护进程不主动发起任何网络连接。
- 游戏不做整 App 豁免：靠保险白名单（登录/对局关键域）+ 进局真机验证兜底。

## 真机首测清单

1. 装完重启，先开浏览器随便打开几个网站：能正常上网（验证 queue-bypass 与规则无误伤）。
2. 再开 BoxProxy 启代理：节点连通、分流正常（验证豁免生效，代理没被过滤拖累）。
3. 最后开和平精英：能登录、能进局、打一局不掉线（验证白名单兜底）。
4. WebUI 看「今日拦截」有计数、「最近拦截」能点放行。

## 首发与版权

- 作者：**桉桉**。本仓库（github.com/ZhangAnAn0106/nora-adblock）为唯一首发渠道，提交记录即原创凭证。
- 本模块代码可自由使用、修改与分享，但须保留作者署名；禁止换名盗发，禁止商业转售。
- 内置拦截名单为 anti-AD（https://anti-ad.net/）公开数据的离线快照，版权归原项目，文件头保留其原始标注。
- 可直接刷入的安装包见本仓库 Releases 页（「广告拦截-x.y.z.zip」）；仓库内不含编译好的守护进程二进制，
  自行编译：`cd daemon && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o ../module/nora-adblockd .`，
  然后把 module/ 目录按模块结构打包为 zip 即可刷入。

## 目录

- `daemon/`：Go 源码与单元测试（`go test ./...`：DNS/TLS/HTTP 解析、名单优先级、
  规则生成与豁免顺序）。
- `module/`：模块打包源（module.prop / customize.sh / service.sh / adblock.sh / webroot）。

