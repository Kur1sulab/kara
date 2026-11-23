# 更新日志

版本号按 [语义化版本](https://semver.org/lang/zh-CN/)：修 bug 走 patch，加能力走 minor，
输出格式或数据库结构不兼容才走 major。

## 1.12.0 — 2026-11-23

### 新增 · 结构化标识符检测（`identifier`）

自由文本里的身份证 / 银行卡 / 手机号靠正则捞，误报率高到没法进报告（≈0.6 的精度）。
这一版改成**只报校验位算得通的**，把精度拉到「报出来就是真的」：

| 类型 | 校验依据 | 随机串通过率 |
|---|---|---|
| 身份证 18 位 | GB 11643 / ISO 7064 MOD 11-2 + 出生日期真实性 + 省级行政区划合法 | ≈2% |
| 银行卡 13–19 位 | Luhn + 首位非 0 + 非全同 + 离线 BIN 表判发卡行 | ≈1/10 |
| 统一社会信用代码 | GB 32100-2015 base31 + 登记管理部门码 ∈ {1,5,9,Y} | ≈1/31 |
| 手机号 | 11 位格式 + 号段（**无校验位可核**，细节里明写，不冒充校验通过） | — |
| 车牌 | **无校验位** → 一律 candidate，不进命中表 | — |

命令：

```bash
kara identifier <文件|-> [--json] [--candidates]
```

- 命中区只放校验通过的；**候选默认不输出**，要看得显式加 `--candidates`；JSON 里 `candidates`
  字段只在显式开启时才存在，下游脚本不可能「顺手」把候选倒进报告。
- 所有输出路径都脱敏：身份证留前 6 后 4、银行卡留前 6 后 4、手机号 3-4-4。
- 实现落在 `engine-go/identifier/`（纯函数、只读文本、零网络），Python 侧只做转发不重复实现算法。

测试：`engine-go/identifier` 53 条用例 + CLI 契约 6 例；Python 侧 312 → 317 例。
钉死的反例：校验位差一位 / 生日 2 月 30 日（校验位却算得通）/ 行政区划 99 / Luhn 差一位 —— 必须 0 命中。

## 1.11.0 — 2026-11-23

### 新增 · 四个补充命令：diff / doctor / poc / replay

主命令（scan / list / verify）之外，补上四个「每一轮交付都会用到、但以前只能手工拼」的动作。
都放在 `vc/cli_extra.py`，主命令的阅读路径没变长。

| 命令 | 解决什么 | 关键点 |
|---|---|---|
| `kara diff --since <时间>` | 复测报告第一段要「哪些新增、哪些还在、哪些没再出现」，以前只能手写 SQL 对着看 | 按 first_seen / last_seen 分三堆（新增 / 持续 / 未再出现）；`--md` 直接出可贴报告的表格，`--csv` 出对账台账。**未再出现 ≠ 已修复**，结论仍要 `kara verify` |
| `kara doctor` | 交付前想知道「引擎找得到吗、子命令齐吗、库里能写吗、离网守卫生效吗」，以前要挨个试 | 八项自检（Python / 引擎 / 引擎子命令 9 项 / 库 / POC / 报告目录 / 离网守卫 / 零依赖守卫），有一项 ✗ 就返回 1 |
| `kara poc [--show/--run]` | `pocs/` 里躺着 YAML，但 CLI 里看不到、也没法单发；直接调引擎得记住 `poc -t -p` 的写法 | `--list` 解析出 id/名称/等级/标签（不引 YAML 依赖，只认平铺 key）；`--show` 看全文；`--run` 会真发请求，**必须 `-t` + `--yes` 两道闸** |
| `kara replay -u <url>` | 报告里每条命中都该带一条能粘着复现的 curl；以前得手敲 | 调引擎 `replay` 落 replay.json，打印状态/长度/类型，并拼出 `curl -i -sS …` 复现串（支持 `-m/-d/-H/--no-redirect`） |

测试：`tests/test_cli_extra.py` 新增 17 例（时间窗归一、三分堆、md/csv 导出、POC 元信息解析、
replay 参数拼装、doctor 缺引擎判 fail、命令注册、裸命令仍出状态）。命令城测试从「只有三个动词」改成
「三主 + 四补充」，全量 312 例全绿。

## 1.10.0 — 2026-11-21

### 新增 · 4.2 三层复验流水线 + 误报反馈闭环

原来的复验是**单层判定**：重跑同一个扫描模式，看同标题的命中还在不在。它拿不到响应体，
所以下面四种形状在它眼里一模一样，全部记成「仍存在」：**真命中** / **全站 500**（打什么都是
同一张错误页）/ **WAF 拦截页**（403 拦截页）/ **payload 根本没进业务**（静态同形）。反过来，
被 WAF 拦住的那批又会被记成「已消失」——同一个根（没有上下文对照）长出四条假漏洞和一堆漏报。

- 三层各自回答一个问题，**任一层不通过就不算确认**：
  - **L1 命中复核**（`vc/pipeline.py:layer1`）：原请求重放两次 + 无辜对照（同位置换无害值；
    路径类命中用同目录随机路径）。全站 5xx（与对照同一张错误页）、静态同形（与对照完全一致）、
    偶发 5xx（首次 500、重放 200）判 `fail`；命中落在 WAF 拦截页判 `blocked`——
    **拦截页不能拿来否定命中**，所以判定顺序是 blocked 先于「与对照一致」。
  - **L2 上下文复核**（`layer2`）：同位置换无害值（现象照旧 = 现象不是 payload 造成的）；
    payload 换到另一个参数名/位置重放（现象不变 = 通用 sink，照样算命中，理由里写明；
    现象随参数变化也写清楚）；SQLi 另做布尔对照 `1=1` vs `1=2`，两边响应一致 = 布尔差异不成立 → `fail`。
    报错型注入（orig 已 5xx）**跳过**布尔对照：两侧都会 500，比值没有判别力，硬比会把真注入判成误报。
  - **L3 最小化 PoC**（`layer3`）：剥掉无关参数只留 payload 再打一次，现象还在就产出最小 `curl` 串；
    剥完现象消失 → `unstable`（结论依赖被剥掉的部分，给不出最小复现串，不硬凑）。
- 层状态词表 `pass / fail / unstable / blocked / skip / error`，每层独立结论与理由；
  判定：任一层 `fail` → `refuted`；适用层全 `pass` → `verified`；其余 → `uncertain`。
  `skip` 是「该层对这个类别没有对象」（路径类命中没有可换的参数），不参与分母。
- **传输层**：Python 侧出站被 `tools/check_offline.py` 禁着（产品纪律），所以新增引擎子命令
  **`sweep replay`**（`engine-go/replay`）：发一次精确指定的请求，把 status/size/digest/headers/body
  落成 `replay.json`；Python 侧 `vc/probe.py` 只读产物。引擎版本旧（没有 replay）时
  `EngineProber.available()` 返回 False，明确提示「回落到整模式重跑」，**绝不假装跑过**。
- **落库**：`findings` 加 `pipe_state / pipe_pass / pipe_layers / pipe_reason / pipe_poc / pipe_at`
  与 `fb_state / fb_at`；新增 `feedback` 表（`UNIQUE(host, rule, param)`，`times` 累积次数）。
  `pipe_state` 与 `verify_state` 是同一件事的两个投影：verified→仍存在、refuted→已消失、
  uncertain/downgraded→无法判定，映射写死在 `verify.PIPE_TO_VERIFY` 一处。
- **反馈闭环**：
  - `kara verify <ID> --feedback --verdict 误报|真报 [--note …]` 写 `feedback` 表；台账 `--feedback-list`。
  - **扫描入账时**：`(host, rule, param)` 被人工判过误报的新命中标成 `downgraded` 并注明
    「历史人工判误报（N 次）」——不静默丢弃，也不照旧报高危。
  - **复验时**：历史判过误报 → 三层全过也降级为 `uncertain` 并写明理由；机器判误报且历史一致 →
    理由里标注一致；历史判过真报而本次没全过 → 提示人工复看。
- **CLI**：`kara verify <ID …>` 位置参数（`--ids` 保留）；逐条打印三层 + 结论 + 最小复现；
  `kara list` 加「三层」列（`✓3/3` / `✗1/2` / `—` / `⚠降级` / `✗人工`，分母=适用层数）与
  全库汇总行；`--pipeline verified|refuted|uncertain|downgraded|unrun` 筛选；CSV 加三层三列、
  MD 加「三层」列与抬头；`kara list -i` 详情展开三层。`verify --help` 写清三层与人工闭环。
- 弱口令 / 配置检查（brute / baseline）**没有请求上下文可换**，仍走整模式重跑（`--legacy` 可强制）：
  它们的假命中形态是「这次根本没测成」，不是全站 500。
- `tests/test_pipeline.py`（新，29 用例）：**stdlib http.server 起真靶子 + http.client 真建连**，
  覆盖真命中 / 全站 500 / 静态同形 / 偶发 5xx / WAF 拦截页 / 布尔对照不成立 / 最小化后消失 /
  无 payload 时 L2 skip / 历史人工判误报降级 / 纯逻辑（任一层 fail、无响应、状态词表）。
  `tests/test_pipeline_store.py`（新，24 用例）：落库、存活映射、台账累积、入账降级、
  `--pipeline` 筛选、人工回写、CSV 三列、`verify --help`。
- **294 个单测全绿**（存量 241 + 29 + 24）；`tools/check_offline.py` / `check_zero_deps.py` 通过。
- 真机验证（回环靶子，非外网）：5 条命中跑出 `✓3/3`（payload 触发 500）、`✓1/1`（路径类，L2/L3 不适用）、
  `⊘ blocked`（Cloudflare 拦截页）、`✗1/2`（布尔对照不成立）、`✓3/3`（读 /etc/passwd 且最小化成立）；
  人工判误报后再命中 → `⚠降级`，复验结论写成「历史人工判误报（1 次）：本层没有定论，按人工结论一并降级」。

## 1.9.4 — 2026-11-19

### 新增 · list 的存活维度——每条命中回答「现在还活着吗」

产品承诺是「每一条命中都回答：现在还活着吗」，但 `kara list` 此前只能看「命中了什么」：
列表的「状态」列是工作流状态（待验证 / 已确认 / …），复验结论（`findings.verify_state`）
一直躺在库里——存量哪些活着、哪些死了、哪些从没复验过，只能人工对库。这次把答案抬到命令行上。

- 存活从唯一真相源推导：`vc/verify.py` 新增 `liveness_of()` / `liveness_summary()`，
  只翻译 `verify_state`（`set_verify` 的写回字段），不造第二套判定。五态：
  `ALIVE`（仍存在）/ `DEAD`（已消失）/ `UNVERIFIED`（空结论 = 从没复验过）/
  `UNKNOWN`（无法判定）/ `NA`（不可复验）。**后两者不并进 UNVERIFIED**——
  「复验过但没结论」「没有可回访的目标」都不是「从没复验过」，并进去待办积压永远清不完。
  认不出的结论字符串归 UNVERIFIED：宁可再跑一遍，也不猜活着或死了。
- `kara list`：表格加「存活」列（符号 + 文字：● ALIVE / ○ DEAD / — UNVERIFIED / ? UNKNOWN / ∅ NA），
  顶部一行全库汇总（五桶之和恒等于命中总数，不随 --sev/--q/--liveness 变；筛选后条数看底部「共 N 条」）；
  `--liveness unverified` 拎出从没复验过的命中，行尾给出 `kara verify --liveness unverified`。
  `kara verify --liveness …` 同口径挑命中（--ids 优先）。状态页与 CSV/MD 导出同步：
  CSV 加「存活」列、MD 摘要加「存活：」行——导出的就是你看到的。
- 输出纪律（黑白灰为主）：三态靠符号 + 文字承载，颜色只点单个字符的符号
  （●红 / ○绿 / —黄 / ?青 / ∅暗灰）；汇总非零数字加粗、零桶淡化，不靠红黄绿；
  无整行染色、无背景色块；NO_COLOR / 非 TTY 自动关色（WCAG 1.4.1：颜色不得单独承载信息）。
- 顺手修一个既有对齐缺陷：`_w()` 量宽前先剥 ANSI 序列——原先 TTY 下带色单元格
  （表头 / 严重度）被误判「已够宽」而不垫空格，表头与数据行错位；东亚宽字符仍按 2 列计。
- `tests/test_liveness.py`（新，31 用例）：推导 / 五桶求和 / 筛选（含 NULL 兼容、
  UNKNOWN/NA 不混入 UNVERIFIED）/ 汇总全库口径 / 配色纪律（色只点符号、无背景块）/
  TTY 与非 TTY 对齐 / 中文截断对齐 / 复验闭环（假引擎：只挑 UNVERIFIED、ALIVE 不被碰）/ CSV/MD 同口径。
- 194 个单测全绿（存量 163 + 新增 31）；`tools/check_offline.py` / `check_zero_deps.py` 通过。

## 1.9.3 — 2026-11-19

### 修复 · scan 的 `--timeout` 不再依赖引擎「吐输出」才生效

`vc/scans.py` 的 `_run_target` 原先把 deadline 检查挂在 `for line in proc.stdout`
循环体里：只有读到新的一行输出，才顺手看一眼是否超时。可引擎卡死时往往一行日志
都不吐——内网 / 断网现场，朝黑洞主机的 TCP connect、卡住的 DNS 就是这种形状。
于是读循环永远等不到下一行，`--timeout` 永不触发，任务无限挂起只能 Ctrl+C，
帮助里「单目标超时秒数」的承诺对最常见的失败形状形同虚设。
（`kara verify` 的重跑走 `subprocess.run(timeout=…)`，从来不受影响；只有扫描执行路径有这个洞。）

- `vc/scans.py`：超时改由独立看门狗线程执行——到点进程还活着就标记并整组
  TERM → KILL，与有没有输出无关；读循环结束后按 `timed_out` 标记定状态。
  正常跑完由 `done_evt` 唤退看门狗、不碰进程；deadline 前手动停止仍是
  `stopped`，看门狗不抢 stop 的活。
- `tests/test_scan_timeout.py`（新，4 用例）：完全静默的引擎到点必须被杀并标
  `timeout`；吐一行后卡死同样要超时；时限内跑完的静默引擎不许被误杀误标；
  deadline 前手动停止得 `stopped`。修复前两条以 `'ok' != 'timeout'` 失败。
- 真机验证：静默假引擎（sleep 60、零输出），
  `kara --timeout 30 scan -t 10.255.255.1 -m portscan` 在 30.0s 被准时终止
  （`— TIMEOUT 用时 30.0s · 超过 30s 超时被终止`）；修复前同形状探针
  （2s 超时、引擎 sleep 6）睡满全程还报 `ok`。
- 163 个单测全绿；`tools/check_offline.py` / `check_zero_deps.py` 通过。

## 1.9.2 — 2026-11-19

### 修复 · brute 模式的 `--ports` / `--service` 被静默丢弃

`kara scan -m brute --ports 6379 --service redis`（README 里就是这么写的）实际
根本没把这两个参数交给引擎：`vc/scans.py` 的 `_run_target` 只在
`spec["sub"] == "strike"` 时追加 `mode_args`，brute 落到了 else 分支。
后果不是报错，而是引擎按自己的默认端口表自动识别服务——跑完没命中，人会
当成「目标没问题」，比报错更贵。

- `vc/scans.py`：改成只要 `self.mode_args` 非空就追加（CLI 只给 strike / brute
  填这两组参数，其余模式恒为空），并在注释里写明踩过的坑。
- `tests/test_brute_args.py`（新，3 用例）：`_mode_args` 在 brute 下给的是
  `-p/--service`、在 strike 下是 `--ports`；假引擎断言 argv 里三样齐全且目标
  没被挤掉；paths 这类模式 argv 不被污染。
- 真机验证：本机起 mock redis（16399，PING 直接可用），
  `kara scan -m brute -t 127.0.0.1 --ports 16399 --service redis` 命中
  `redis://127.0.0.1:16399`「Redis 未设口令」，入账 critical 1 条——
  修复前这个端口不在默认表里，必然漏。

## 1.9.1 — 2026-11-19

### 修复 · 复验覆盖：strike / brute / cve / sslchain 的命中不再被误标「不可复验」

1.9.0 的 `SOURCE_MODE` 只认 6 个来源标签，于是产出漏洞判定的四类命中——
`strike`（深度验证）、`brute`（弱口令）、`cve`（离线 CVE）、baseline 的 `sslchain`
（TLS 证书链）——在 `kara verify` 里全被标成「不可复验」，理由还写错了：
「不是本机引擎产物，没有可回访的目标」。它们明明就是本机引擎产物，也有可回访的目标。
产品的承诺是「每一条命中都回答：现在还活着吗」，这一版把承诺补齐。

- `vc/verify.py`：`SOURCE_MODE` / `MODE_KIND` 补齐上述四类来源（带冒号后缀的来源
  标签查表前先剥后缀）；`plan_of` 按模式生成重跑参数——strike 按原入口重跑
  （web 入口裁到 host:port，服务级命中保留裸 host:port），brute 带原端口 + 原服务名
  （引擎自带额度 / 命中即停 / 锁定识别），cve 原样回访当初那个 URL（含路径，
  不裁到首页去拿另一个页面的指纹下结论）。
- **「连不上 ≠ 已消失」的铁律同步扩展到新模式的产物形状**：
  - strike 读 coverage：要有开放端口、且至少一项后续检查 ok 才许下结论；
    0 开放端口（分不清主机挂了还是服务全停）或全 skip → 不下结论；
  - brute 读 skipped：全部「没测成」（拨号失败 / 锁定 / 协议错误）→ 不下结论；
    握手完整跑完没命中才写「已消失」；
  - cve：连不上时引擎 exit 1 不落产物 → 不下结论；落了产物但产品指纹为空
    （可能是错误页，分不清「产品没了」还是「页面坏了」）→ 同样不下结论。
- 服务级 strike 命中（裸 host:port 端点）现在也能进 `verify --deep`：
  `base_url` / `_target_of` 原样保留端口，不再裁成主机名让引擎猜端口。
- sslchain 命中的复现命令补 `openssl s_client` 建链命令（原来是空的）。

### 测试

- 新增 27 个单测（`tests/test_verify_coverage.py`）：四类命中的计划生成、
  可达性判读、假引擎端到端（仍存在 / 已消失 / 连不上 / 锁定 / 空指纹 / 退出码非 0）；
  合计 156 个全绿。`tools/check_offline.py` / `check_zero_deps.py` 通过。
- 实测（127.0.0.1 本地靶站 + mock redis）：cve / paths / strike / brute 的 6 条命中
  按原模式复验全部「仍存在」；停掉 redis 后复验「无法判定」（不是已消失）；
  删 .env 并把 Apache 2.4.49 升到 2.4.52 后，对应 3 条「已消失」，
  仍然成立的 2 条（缺安全头 / 版本泄露）保持「仍存在」。

## 1.9.0 — 2026-11-18

### 变更 · 回到产品的真实定位：断网 / 内网工具

Kara 的战场是内网、VDI、只能进不能出的现场。上一版里还挂着几个「要连公网服务」的模块，
在那种环境里必然挂着等超时，然后让人误以为「没有结果」。这一版整层删掉：

| 删掉的东西 | 它原来的外联对象 |
|---|---|
| `icp`（备案查询） | cn.apihz.cn |
| `asset`（资产测绘） | fofa.info / hunter.qianxin.com |
| `reverse`（IP 反查域名） | api.hackertarget.com |
| 子域证书日志通道 | crt.sh / certspotter / OneForAll / subfinder |
| `baseline` 的 archives / whois / geoasn / dnsrec / mailsec | web.archive.org / rdap.org / tranco / geojs.io / ipwho.is / dns.google |

现在整份引擎只剩一种出站：**朝用户给的目标发请求**。CI 里 `tools/check_offline.py` 守着这条。

### 新增 · 断网下真正能用的能力

- **`subdomain` 重写为本地 DNS 字典爆破**：内置约 4.8k 条标签（SecLists top5000 + 内网常见），
  先探测泛解析并比对解析结果集（否则泛解析域名会被写成几千个子域），支持 `--resolver 10.0.0.2:53`
  指内网 DNS。不再依赖任何证书日志服务。
- **`brute` 弱口令验证**：FTP / MySQL / PostgreSQL / Redis / Telnet / HTTP-Basic 六种协议自己实现握手
  （零第三方依赖）。有额度（默认 20 次/端口）、命中即停、识别「尝试过多/账号锁定」立即停止；
  没测成的目标会写 `skipped` 原因，不会被当成「没有弱口令」。
- **`cve` 离线 CVE 匹配**：从响应头/正文抽产品与版本，比对编译进二进制的规则库（24 条：Apache
  2.4.49/2.4.50、Struts2 S2-045/057、Ghostcat、Spring4Shell、Spring Cloud Gateway、WebLogic
  14882/2725、Shiro、Nacos、Grafana、Confluence、GitLab、Webmin、Drupal、Zabbix、Solr、ActiveMQ、
  SaltStack、Log4Shell、ThinkPHP 5.0/5.1）。产出固定 `L1 / version-range`——版本落在区间只说明
  「可能受影响」，规则里同时给出验证动作。
- `all` 流水线接入 `cve` 步骤（爆破不入 `all`，避免意外锁账号）。

### 新增 · 扫完自动出的报告带证据与发现过程

`kara scan` 结束自动写 `~/.kara/reports/<目标>-<模式>-<时间>.md`（`--no-report` 可关）：

- **发现方式**：哪个模式、判据链是什么（人话，不是只给个来源标记）
- **判据**：状态码 / 字节数 / Content-Type / 匹配关键字 / 复验结果
- **证据**：直接内联引擎落盘的响应片段（优先 `response.snippet.txt`），并列出 `evidence/` 原始文件
- **复现**：可粘贴命令（curl / redis-cli / psql / mysql / ftp / telnet）
- **未验证 / 跳过**单独一节，带原因

`kara list --md` 走同一个渲染器。

### 修复

- `cve` 读不到版本号：netutil 落盘的响应头是**小写键**，`hdr["Server"]` 永远空 → 统一归一化。
- 产物解析注册表放在函数定义之前，`import vc.parsers_sweep` 直接 NameError → 移到文件末尾。
- 证据文件按端点 slug 定位（以前会把同目标其它端点的证据也列进来）。

### 测试

- Python 129 个（新增 brute / cve 产物解析、报告必须含发现方式/判据/证据/复现、证据内联）；
- Go：`go test ./...` 全绿（删掉针对已移除模块与 Python 对照的测试；`internal/parity` 保留壳并显式 skip）。

## 1.8.0 — 2026-11-18

### 变更 · 收敛成单一 CLI（去掉网页层）

产品只有一个界面：命令行。网页那套（`vc/server.py`、`vc/ui/`、`run.sh`）整层移除，
Windows 绿色版的启动器也从「起服务 + 自动开浏览器」改成直接跑 CLI。

命令表压到三个动词，别的一律不进：

```
kara                                   # 状态：引擎、库、存量
kara scan -t <目标> [-m 模式]           # 扫（-m strike = 深度验证）
kara list [-i 序号] [--assets]          # 看（--csv / --md 导出）
kara verify [--ids …] [--deep]         # 复验（--deep 用验证内核真打）
```

- 原先的 `show` / `assets` / `export` / `summary` / `engine` / `strike` / `ingest` 七个命令全部并入上面三个：
  详情与资产进 `list`（`-i` / `--assets`），导出进 `list --csv|--md`，
  状态与引擎自检进**裸命令**（不带子命令就打印），入账在 `scan` / `verify` 之后自动跑。
- 库路径与收件箱默认值搬到 `vc/paths.py`：以前它们住在 server.py 里，删了服务那文件就该搬家。
- 没有服务、没有端口、没有鉴权面；`--engine` 依旧可显式指定，指错就报错。

### 修复

- `asset` 是 `-`（白盒报告进来的条目）时被当成合法目标，`verify --deep` 会拿它去跑引擎然后报错；
  现在 `-` / `unknown` 一律不当目标，直接说明「没有可回访目标」。

### 测试

- 123 个单测：新增「命令表只有三个动词」「裸命令打印状态」「list --assets」「verify --deep 的 dry-run
  与无目标路径」「`kind=any` 目标校验」等用例；删掉网页路由那组测试（随服务层一起退役）。

## 1.7.0 — 2026-11-18

### 变更 · 执行内核内建，不再「移交」

上一版把深度验证做成对外的移交（`vc/strike.py` 调外部 litmus 二进制）。那是过渡方案，
这一版把它**并进 Kara 自己**：验证内核的源码落进 `engine-go/litmus/`（移植自 litmus2，
零第三方依赖），跟指纹/敏感路径/API 一样是同一台引擎的子命令。

- **第 9 个模式 `strike`**：`kara scan -t <目标> -m strike [--ports …] [--intensity …]`
  产物 `out/<target>/strike/{findings.json,report.md,evidence/}`，由 `vc/parsers_sweep.py`
  的新形状 `sweep_strike` 归一化入账——跟其它模式同一条流水线、同一套去重键、同样可复验。
- **`kara strike` 语义改成「用内建内核真打」**：目标仍可从库里挑（`--sev/--ids/--limit`）
  或直接给（`--target`），但不再需要任何外部二进制。`vc/strike.py` 已删除，不留两套逻辑漂移。
- 目标校验新增 `kind=any`：既吃 `http://h:p/path` 也吃裸 `h:p`（验证内核两种都要），
  仍挡注入形状与路径穿越，尾斜杠照旧剥掉。
- 界面/终端不需要跟着变：网页版里它就是一个新模式，终端版就是 `-m strike`。

### 为什么值得合

只读模组给的是「可疑面」，验证内核给的是「能不能打进去、拿到了什么」。分成两个产品时，
中间要手工搬 findings；合进一台引擎后，一次扫描里两种结论落在同一张表里；
同一个去重键让「先扫后验」和「一次全跑」得出一致结果。

### 测试

- 122 个单测（`tests/test_strike_mode.py`：形状识别、0 命中也要认、`kind=any` 目标、
  `--ports/--intensity` 透传给引擎、假引擎跑通「模式 → 产物 → 入账」全段）。
- 实测：`kara scan -m strike` 打本地靶站 → 9 条（严重 3/L2、高危 1/L2…）全部入账；
  `kara strike --sev critical` 复打同一目标 → 9 条全部合并进原条目（去重键生效）。

## 1.6.0 — 2026-11-18

### 新增 · `kara strike`：发现 → 验证 的移交

Kara 的引擎只读，只给「可疑面」；是不是真漏洞、能不能打进去，由执行层 litmus2 判定。
这一版把两段接上：挑命中 → 生成目标清单与线索雏形 → 跑 litmus → 结论归一化回写同一个库。

```bash
kara strike --sev high --limit 10        # 挑 high 前 10 条，交给 litmus 真打一轮
kara strike --ids 5,9,10                 # 指定条目
kara strike --sev critical --dry-run     # 只出清单与雏形，不发一个请求
kara strike --ports 8080 --litmus-arg -no-auth-probe
```

- 目标推导：端点裁到 `scheme://host:port`（把 `/actuator/env` 这种具体路径丢给执行层，
  等于替它预设了结论）；没有端点就退回 `资产:端口`。
- 线索雏形固定 `level=L1 / confidence=suspected`——Kara 不替执行层下结论。
- 执行层的结论带 `[L2/confirmed]` 这类级别/置信写进证据串，L1 的条目交付时一眼看得出还没落地。
- 公网目标自动加 `-allow-public`（litmus 是内网框架，默认只放行私网/回环）。
- **`--target` 直通**：库里有的条目没有回访目标（白盒审计报告、离线产物进来的都这样），
  这种交给 `kara strike --target https://x` 直接给目标；库里的命中只当线索用。
- 产物：`~/.kara/strike/<时间戳>/{targets.txt, seed-findings.json, litmus/}`，报告与证据都在里面。

实测（本地靶站）：Kara 只读扫出 6 条 high → litmus 验证出 9 条，
其中 3 条升级到 critical/L2（.env、heapdump、备份包拿到了真实内容），全部回写本库。

### 边界（写进代码注释，也是产品线纪律）

- Kara 不做写操作、不做爆破、不发 payload；要「打」必须显式 `strike` 移交。
- `strike` 不复制执行层的检查逻辑，只做清单生成与结果归一化——两边各守一段，报告才可审计。

### 测试

- 134 个单测（新增 `tests/test_strike.py` 18 个：目标推导、L1 雏形、结论回写、
  级别保留、`--dry-run` 不发请求、执行层缺失时干净报错）。

## 1.5.0 — 2026-11-18

### 新增 · 终端模式

- **`kara` 命令**（`vc/cli.py`）：不开端口、不起浏览器，扫 → 入账 → 看 → 复验 → 导出全在终端。
  九个入口：`scan / ingest / list / assets / show / verify / export / summary / engine`。
  扫描时实时刷「在跑什么 + i/n + 已用时」，结束后直接给本轮新增命中表（带严重度排序）。
- **url 类目标自动判协议**：`-t 127.0.0.1:8080` 先握手，https 不通就按 http 扫。以前一律补
  `https://`，碰上 http 站会静默 0 命中——看着像「目标很干净」，其实一个包都没发对。

### 变更 · 引擎搬回自己家

- 扫描引擎（Go，二进制名 `sweep`）源码进仓库 `engine-go/`，模块名改成
  `github.com/Kur1sulab/kara/engine-go`，入口 `cmd/sweep`。此前它被资产测绘那条线借走
  （sweep → atlas → 八咫），Kara 只剩一个调不到引擎的空壳：界面在、按钮在、扫不了。
  现在 `engine/sweep` 从本仓库构建，Kara 不再依赖机器上是否装过别的二进制。
- 内核不再带 `serve` 子命令与 Web 控制台——界面那层归 Kara 自己：网页 `vc/server.py`、
  终端 `vc/cli.py`。引擎只负责扫。
- `sweep version` 自报 `sweep v1.0.0 · kara-engine`，`kara engine` 直接显示它。

### 修复

- **带尾斜杠的 URL 被拒收**：从浏览器地址栏复制来的 `http://a.com/x/` 以前报
  「目标不能以 . - / 开头或结尾」，现在只剥尾斜杠，其余校验不动。
- **终端版入账跑两遍**：网页版靠扫描回调入账，终端版结束后又显式入账一次，同一批产物
  第二遍全算「合并」，命中次数凭空 +1、统计会骗人。终端版改为只入账一次。
- **`kara engine` 读不到引擎版本**：无参执行拿到的第一行是帮助标题，不是版本号。现在先问
  `version` 子命令，再退回「含版本号的那一行」。
- **CLI 导出 CSV 少了 BOM**：Windows Excel 双击乱码，现在与网页导出一致走 `utf-8-sig`。

### 测试

- 116 个单测（新增 `tests/test_cli.py` 12 个：尾斜杠、CJK 显示宽度、协议判定、
  假引擎跑通整条 scan 链路、导出 BOM）。

## 1.4.0 — 2026-11-18

### 更名

- **鉴微 / Acumen → 空境 / Kara**（《空之境界》）。「空境」= 边界之内，看得见边界的人才看得见裂缝。
  英文标识统一为 `kara`：目录、启动器 `kara.bat`、CLI 前缀 `[kara]`、绿色版包名 `kara-1.4.0-win64.zip`。
- 旧路径全部留软链（`~/tools/acumen`、`~/tools/sixeyes` → `~/tools/kara`），改名前写下的脚本不用改。
- **库文件迁移链**：新库 `~/.kara/vuln.db`，缺失时按 `~/.sixeyes` → `~/.acumen` 顺序搬一次，
  连 `-wal`/`-shm` 一起搬（只搬 `.db` 会丢掉还没 checkpoint 的命中），搬不动就用老库、不中断启动。
- 侧栏标记换成印章式「空」字标：22px 方框 + 13px 字重 600，20px 下不糊成齿轮。

## 1.3.0 — 2026-11-18

### 新增

- **复验：每条命中都能回答「现在还活着吗」**（`vc/verify.py`）。漏扫的结论是会过期的——
  昨天的 `.env` 今天可能已经关了。勾几条点「复验」，工具用**当初发现它的同一个模式、
  同一个入口**把引擎重跑一遍，结论写回库里：`仍存在 / 已消失 / 无法判定`，
  外加一个 `不可复验`（离线报告、nuclei、nessus 这些没有可回访目标的条目）。
  单条也能点行尾的 ↻ 复验，跑的时候有进度条（第几条 / 当前在跑谁 / 用时）。
- **复现命令跟命中一起存、一起导**（`repro` 字段）。引擎取证目录里本来就写了
  `repro.md`（URL、状态码、判据、复现命令、预期现象），以前只在磁盘上躺着；
  现在随命中入库，点开条目就能看到并复制，CSV / MD 导出也带这一列——
  报告里能直接粘，不用回头翻产物目录。
- **命中详情面板**：点标题或复验徽章，摊开「凭什么算命中」——端点、来源、判据、
  上次复验结论，以及可一键复制的复现命令。按钮只有真功能，没有摆设。
- **`/api/verify` 与 `/api/verify/status`**：复验走 HTTP 派发 + 轮询进度，
  仅回环地址可调用（复验会真起引擎打目标，不给远程留口子）。

### 变更

- **复验结论与人工状态分字段存**（`verify_state` / `verify_at` / `verify_times` / `verify_note`）。
  `状态`（待验证/已确认/误报…）是人判断的，「复验」是机器重跑出来的，混在一个字段里
  就再也分不清哪条是「我确认过」、哪条是「工具刚又打了一枪」。
- **命中表新增「复验」列**，徽章颜色按语义：仍存在=红（还在，得处理）、已消失=绿、
  无法判定=橙、不可复验=灰、未复验=虚线框。
- **列宽从 `nth-child` 改成 class**。中间插一列会把后面所有列宽错位（`来源` 撑到 33%、
  `漏洞名称` 挤成 42px）——这种错位只在截图里看得出来，所以改成按 class 给宽。
- CSV / MD 导出新增「复验 / 复验时间 / 复现命令」；MD 里复现命令单独成段，可直接交报告。

### 修复

- **复验不会把「引擎没连上目标」说成「已消失」**。http 目标被猜成 https 重跑时，引擎
  空手而归但退出码是 0，只看「产物在不在」就会顺理成章地报假结论。现在读引擎自己的
  自述判可达性（`paths` 的 `baseline.kind`、`api` 每条记录的 `status/error`、
  `jsintel` 的 `page_status`），连不上就写「无法判定」——宁可说不准，不给假结论。
- **入口按原样还原**。解析时把引擎写下的 `base`（scheme + host + port）存进命中，
  复验按它重跑，不再靠 `asset + port` 反推；猜出来的入口只作兜底，且默认端口会被去掉。
- 同目标多条命中合并成一次重跑（`baseline` 仍按单项跑），不再为几条命中把整个模式重跑五遍。

### 数据库

- `findings` 新增 `repro / verify_state / verify_at / verify_times / verify_note / base`
  六列与 `idx_f_cve`、`idx_f_vfy` 两个索引，老库自动迁移（幂等）。

## 1.2.0 — 2026-11-18

### 新增

- **引擎原生产物直读**（`vc/parsers_sweep.py`）。以前引擎扫完、产物落进收件箱，
  摄入器却认不出这些 JSON —— 扫出 3 条真命中，库里还是 0 条，「漏扫」等于只是个壳。
  现在 `paths / ports / api_unauth / jsintel / fingerprint / 基线 / 取证 meta` 七种形状
  逐一对上，命中直接进漏洞表、端口指纹进资产卡。
- **敏感串二次判定**。引擎的 JS 情报按 key 名粗匹配，在压缩过的第三方 JS 上一次
  跑出 8 条「硬编码密钥」，实际全是 `var sk={}`、`ak:"endpoint_for_debug"` 这种变量名。
  现在要求「像凭据的值」：厂商前缀（AKIA / sk- / ghp_ / eyJ…）或长度 ≥16 且字母数字混排；
  丢弃条数写进备注，不静默吞掉。
- **解析器代次**（`PARSER_GEN`）参与文件指纹。升级解析逻辑后旧产物自动重解析一次，
  不用让用户记得点「全量重解析」或加 `--force`。

### 变更

- **定位改回「小而精的本地漏扫」**。此前把叙事写成了「看板 / 控制台」，主入口是结果
  表格，绿色版连引擎都没打进去——扫描页在 Windows 上永远显示「没找到扫描引擎」。
  这一版把扫描做成主线：侧栏第一项是「扫描」，库里一条数据都没有时首屏直接落在扫描页，
  用户手动点过任何 tab 之后就不再抢他的选择。
- **绿色版内置扫描引擎**。`engine\sweep.exe` 随包分发（Go 交叉编译产物，7.4MB，
  CGO 关闭，无运行时依赖），解压即能开扫。构建脚本新增 `--engine`，未显式指定时自动
  探测 `build/sweep-win64.exe`；缺引擎直接报错并给出交叉编译命令，不再静默打出空壳包。
- **引擎发现顺序固定**：包内 `engine/sweep` → `PATH` 上的 `sweep` → `~/.local/bin/sweep`。
  机器上装过旧版 sweep 时不会再被先挑中，避免「界面是新的、跑的是旧引擎」。

### 修复

- **窄屏扫描页布局塌陷**。窗口 < 1180px 时表单被压成 46vh 的缝，目标输入框和「开始扫描」
  直接看不见，任务卡叠在模式卡上。窄屏改为整页块流滚动。
- 底部「已选择 N 项 / 共 M 条」只在漏洞页显示，不再跟着出现在扫描页。
- 资产卡与漏洞表的「来源」列显示中文短名（路径 / 端口 / 指纹 / JS / 取证），
  完整值留在 title；端口芯片显示服务名而不是 banner 尾巴（`8899 · HTTP` 而不是 `3.12.16 Date: We…`）。
- 二进制协议的 banner 净化：MySQL 握手包的原始字节不再把资产表弄成乱码。
- 引擎的 `scan-*/progress`、`scan-*/logs` 运行时文件不再进收件箱（以前会以
  「格式无法识别」刷一屏噪音）。
- 资产合并：漏洞侧的 `host:port` 与资产表的 `host` 归到同一张卡；
  端口去重把空 proto 当通配，同一个端口不会因来源不同出现两行。
- 单测 59 → 84：新增引擎真产物 fixtures（敏感串误报、banner 净化、
  基线副本去重、`host:port` 归一、空结果识别）。

## 1.1.0 — 2026-11-18

### 新增

- **CVE 识别链路**。新增 `cve_of()`，从标题、证据、原始报文里识别编号，兼容
  `CVE-2021-44228` / `cve_2021_44228` / `CVE 2021 44228` 以及全角横线、短破折、
  长破折、减号等分隔符；多个编号排序去重后用逗号连接。
- **nuclei 从 `template-id` 取编号**（`CVE-2021-44228.yaml` 的 template-id 就是编号本身）。
- **nessus 从 `<cve>` 子元素取编号**，支持一条 item 多个 CVE。
- **界面 CVE 徽章**：标题前渲染等宽小标签，无编号不占位，多个折叠成 `+N`，
  点击复制。

### 修复

- **繁体表头报告整份丢弃**。`編號 / 發現 / 嚴重度 / 風險描述` 这些词不在识别表里，
  88 行的白盒审计报告一条不出。补齐繁体词后救回 15 条。
- **`cve` 字段被模板名污染**。nuclei 的 template-id 可能是 `exposed-panel` 这种名字，
  以前直接写进 `cve` 字段。现在只收规范编号，非编号文本一律丢弃。
- **端点协议被覆盖**。`rdp://10.0.0.5:3389` 以前被硬拼成 `https://...`，现在带协议的
  端点照原样展示。
- **端口拼两遍**。资产已是 `host:port` 形式时又追加了一次端口，显示成
  `10.0.0.5:3389:3389`。
- **`_port_of()` 从未被调用**，端点里的端口一直没回填到 `port` 字段。

### 工程

- 新增 `tools/check_zero_deps.py`：扫描全部 import，非标准库就失败；同时检查前端
  没有混进 `package.json` / `node_modules` 之类的构建链。核心承诺进 CI。
- 新增 GitHub Actions：单测 × (ubuntu, macos) × (3.9, 3.12, 3.13)，另加零依赖自检与
  JS 语法检查。
- 单测 44 → 58，新增 `tests/test_cve_chain.py` 与 `tests/fixtures/`
  （nuclei jsonl / nessus xml / 繁体 md 三份回归夹具）。

### 说明

全库 126 条 finding 的 CVE 命中数为 0，原因是存量数据本身是 App 白盒审计与内网渗透
报告，讲的是 TLS 校验关闭、TrustManager 空实现这类配置缺陷，本来就不挂 CVE 编号。
链路已就绪，nuclei / nessus 产物进来会自动带编号。

## 1.0.0 — 2026-11-18

首个版本。

- 9 类产物解析：nuclei jsonl / nuclei text / xray / nmap xml / nessus / yakit /
  存活清单 / CSV / Markdown 表格，另加「原始请求响应包」。
- 形状判别：有 host 键且无 severity 标记的判为资产清单，不会把指纹表刷成 info 漏洞。
- 去重键 `sha1(资产|标题|端点|参数)`，命中次数累加、来源取并集、严重度取最高、
  首次发现取最早。
- 5 种状态流转，落 SQLite，支持批量改。
- 导出 CSV（带 BOM，Excel 不乱码）/ Markdown，跟随当前筛选。
- 深浅双主题，过 WCAG AA。
- 零依赖：Python 标准库 + 原生 HTML/CSS/JS，无 pip、无 npm、无构建。
