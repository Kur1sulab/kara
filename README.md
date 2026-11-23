# 空境 · Kara

**内网 / 断网环境的小而精漏扫。** 一条命令跑完：端口 → 爆破 → 指纹 → 子域 → API/路径 →
CVE 匹配 → 深度验证，扫完自动出一份**带证据与复现步骤**的报告。

**运行时零外联**：所有请求只发给自己给的目标，不查备案、不查 FOFA/Hunter、不查证书日志、
不查 WHOIS、不查任何云端接口。这是产品定位，不是可选项。

## 三个主命令 + 四个补充命令，没有第四层

```bash
kara                             # 状态：引擎、库、存量
kara scan -t <目标> [-m 模式]     # 扫（扫完自动生成报告）
kara list [-i 序号] [--assets] [--liveness …]   # 看（--csv / --md 导出）
kara verify [ID …] [--deep]      # 复验：三层流水线（L1 命中复核 → L2 上下文复核 → L3 最小化 PoC）
kara diff --since 2026-11-20     # 对账：新增 / 持续 / 未再出现（复测报告第一段）
kara doctor                      # 交付前自检：引擎 / 子命令 / 库 / POC / 离网守卫
kara poc [--show 名] [--run 名 -t 目标 --yes]   # POC 库浏览与单发
kara replay -u <url> [-m POST -d 'a=1' -H 'K: V']   # 单次精确请求 → 复现 curl
```

```bash
kara scan -t 10.0.0.5 -m portscan
kara scan -t 10.0.0.5 -m brute --ports 6379,3306 --service redis
kara scan -t corp.local -m subdomain --resolver 10.0.0.2:53
kara scan -t http://10.0.0.5:8080 -m api
kara scan -t http://10.0.0.5 -m cve
kara scan -t http://10.0.0.5 -m strike
kara list --sev high                  # 看高危
kara list --liveness unverified       # 拎出从没复验过的命中（alive/dead/unverified/unknown/na）
kara list --pipeline refuted          # 看被三层判成误报的（verified/refuted/uncertain/downgraded/unrun）
kara list -i 12                       # 单条：判据 / 证据 / 三层结论 / 复现命令
kara verify 12 15 19                  # 复验指定命中，逐条打印三层结论与理由
kara verify --liveness unverified      # 只复验从没复验过的
kara verify 12 --feedback --verdict 误报 --note "自研 WAF，403 是拦截页"   # 人工回写
kara verify --feedback-list            # 人工判定台账
kara verify --deep --sev high          # 对已有命中真打一轮（验证内核）
```

`kara` 是仓库根目录的薄壳（`~/.local/bin/kara` 软链过去），等价 `python3 -m vc.cli`。
不给子命令就打印状态——无服务、无端口、无第二套入口。

## 模式（全部断网可用）

| 模式 | 干什么 |
|---|---|
| `all` | 全流程：子域(本地DNS)→验活→指纹→路径→API→JS→端口→基线→CVE→报告 |
| `portscan` | 96 个常用端口 TCP connect + banner 服务识别 |
| `brute` | **弱口令验证**：FTP / MySQL / PostgreSQL / Redis / Telnet / HTTP-Basic 协议握手，命中即停、识别锁定 |
| `fingerprint` | 28 条规则 / 26 种技术（headers + body 双通道） |
| `subdomain` | **本地 DNS 字典爆破**（内置约 4.8k 条；泛解析比对；`--resolver` 指内网 DNS） |
| `api` | 28 个候选端点：Swagger / Actuator / Druid / GraphQL / Nacos / pprof / heapdump…（软 404 基线 + 存活复验 + 取证） |
| `paths` | 19 条敏感路径（`.git` `.env` 备份包…），软 404 基线过滤 |
| `jsintel` | 抓目标页与外链 JS，提取接口与密钥线索（值打码） |
| `baseline` | 暴露面基线 3 项：安全响应头 / 网站文件 / TLS 证书链（只请求目标） |
| `cve` | **离线 CVE 匹配**：产品+版本 → 内置受影响区间规则库（L1：可能受影响） |
| `strike` | **深度验证**：内建内核真打（服务真登 / 未授权 / 注入 / 敏感路径），判定到 L1/L2 |
| `poc` | YAML POC 模板（nuclei 风格子集，`pocs/` 下自带示例） |
| `patchdiff` | 补丁差分 → 变种狩猎（本地 git 仓库，零外联） |

## 扫完自动出的报告

`kara scan` 结束就写一份 Markdown（`~/.kara/reports/<目标>-<模式>-<时间>.md`），每条漏洞都包含：

- **发现方式**：哪个模式、用了什么判据链（如「28 个候选端点 → 软 404 基线 → 存活复验 → 取证」）
- **位置**：端点 / 资产:端口 / 参数 / CVE 号
- **判据**：状态码、字节数、Content-Type、匹配到的关键字、复验结果
- **证据**：直接内联引擎落盘的响应片段；并列出 `evidence/` 下的原始文件路径
- **复现**：可粘贴的命令（curl / redis-cli / psql / mysql / ftp…）
- **状态**：待验证 / 已确认 / 误报，以及 L1 / L2 验证级别
- **原始产物**：这条命中来自哪个 JSON 文件

另有一节「未验证 / 跳过」：跳过的检查一定带原因，**没测的不会被伪装成「没漏洞」**。
不想要报告加 `--no-report`。

## 凭什么算命中

- **去重合并**：键 `sha1(资产|标题|端点|参数)`。同一漏洞被多份产物报到不新增条目，次数 +1、来源取并集、严重度取最高、首次发现取最早。
- **分级判据**：路径可达 ≠ 高危（凭据 / 源码 / 配置 / 备份 / 运维端点才 high）；JS 敏感串二次判定。
- **复验**：按当初发现它的同一个模式重跑，结论分「仍存在 / 已消失 / 无法判定 / 不可复验」——**连不上目标不算已消失**。
  覆盖全部产出漏洞判定的原生模式：paths / api / jsintel / baseline 三检查（含 TLS 证书链）/ strike / brute / cve。
- **三层复验流水线**（`kara verify`）：命中 → 上下文复核 → 最小化 PoC，三层过完才算确认。
  - **L1 命中复核**：原请求重放两次 + 无辜对照（同位置换无害值 / 同目录随机路径）。
    全站 500（payload 与对照同一张错误页）、静态同形（payload 没产生任何差异）、偶发 5xx（第二次变 2xx）
    全部挡在这里；命中落在 WAF 拦截页 → `blocked`，**不下结论**（既不说存在，也不说误报）。
  - **L2 上下文复核**：同位置换无害值（现象照旧 = 不是 payload 造成的）；把 payload 换到另一个参数名/位置
    重放（现象还在 = 通用 sink，照样算命中，但理由里写明）；SQLi 另做布尔对照 `1=1` vs `1=2`
    （两边响应一致 = 布尔差异不成立 → 判误报）。报错型注入不做布尔对照（两侧都 5xx，比值没有判别力）。
  - **L3 最小化 PoC**：剥掉无关参数只留 payload 再打一次，产出能直接粘进报告的 `curl` 串；
    剥完现象消失 = 现象不稳（存疑），不硬凑一个复现串。
  - 层状态：`pass / fail / unstable / blocked / skip / error`。任一层 `fail` → `refuted`；
    适用层全 `pass` → `verified`；其余 → `uncertain`。`blocked` 不是 `fail`——被拦的响应证明不了任何事。
  - `kara list` 的「三层」列：`✓3/3`、`✗1/2`、`—`（没跑）、`⚠降级`、`✗人工`；分母是**适用层数**
    （路径类命中没有可换的参数，L2/L3 不适用，写成 1/3 会被读成「只过一层」）。
- **误报反馈闭环**：`kara verify <ID> --feedback --verdict 误报|真报 [--note …]` 把人工判定写进
  `feedback` 表，按 `(主机, 规则, 参数)` 累积次数；台账用 `kara verify --feedback-list` 看。
  - 扫描入账时：同一 `(主机, 规则, 参数)` 被人工判过误报的，新命中标成 `⚠降级` 并注明
    「历史人工判误报（N 次）」——**不静默丢弃**（那是隐瞒），也不照旧报高危（那是无视人的判断）。
  - 复验时：三层全过但历史判过误报 → 结论降级为 `uncertain` 并把理由写在明面上；
    机器判误报且历史一致 → 理由里标注「与历史人工判误报一致」。
  - 两个字段分开存：`pipe_state` 记机器三层结论，`fb_state` 记人的判断——混在一起就说不清谁说的。
- **存活维度**：`kara list` 每条命中带存活状态（● ALIVE / ○ DEAD / — UNVERIFIED / ? UNKNOWN / ∅ NA），
  顶部一行全库汇总；`--liveness unverified` 拎出从没复验过的。「无法判定 / 不可复验」不混入「未复验」——
  复验过但没结论、没有可回访的目标，都不是「从没复验过」。
- **吃别家产物**：nuclei / xray / nmap / nessus / yakit / CSV / MD 表格 / 原始 HTTP 报文丢进收件箱，自动归一化进同一张表。

## 安装与引擎

引擎按 `engine/sweep` → `PATH` 上的 `sweep` → `~/.local/bin/sweep` 顺序找；
`--engine /path/to/sweep` 指定后只认它，指错会明确报错。

```bash
cd engine-go
go build -ldflags "-X github.com/Kur1sulab/kara/engine-go/cli.Version=v1.2.0" -o ../engine/sweep ./cmd/sweep
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o ../build/sweep-win64.exe ./cmd/sweep   # 绿色版
```

Windows：下 Releases 的 `kara-*-win64.zip`，解压双击 `kara.bat`（命令行，参数直接接在后面）。

## 边界

- 无服务、无端口、无鉴权面：只有一个进程在跑命令。
- **零外联**：CI 里 `tools/check_offline.py` 守着这条（唯一放行是 CLI 对目标握手的 `socket`）。
- 引擎用列表参数启动、不拼 shell；目标先过字符白名单；并发上限 4；停止走进程组 `TERM → KILL`。
- 爆破有额度（默认 20 次/端口，命中即停），识别到「尝试过多/锁定」立即停止。
- 数据在 `~/.kara/vuln.db`（SQLite），删了就是清空重来，不动原始产物。

## 文件

```
kara                 入口薄壳（等价 python3 -m vc.cli）
engine-go/           引擎源码（Go）：cli/ 命令层；brute/ cve/ subdomain/ … 各能力；litmus/ 深度验证内核
engine/sweep         引擎构建产物（gitignore，用上面的命令重建）
pocs/                自带 YAML POC（示例 / Actuator / Nacos / Shiro 特征）
vc/cli.py            CLI：状态 / scan / list / verify
vc/report.py         报告渲染：发现方式 / 判据 / 证据 / 复现 / 未验证项
vc/parsers_sweep.py  引擎原生产物解析（strike/paths/api/ports/jsintel/baseline/fingerprint/brute/cve）
vc/store.py          SQLite：去重合并 / 筛选 / 状态 / 复验结论 / 三层结论 / 误报台账 / 导出
vc/ingest.py         收件箱遍历、内容指纹增量
vc/verify.py         复验：三层流水线入口、结论落库、人工反馈（连不上 ≠ 已消失 ≠ 三层全过）
vc/pipeline.py       三层判定：L1 命中复核 / L2 上下文复核 / L3 最小化 PoC（不联网，prober 注入）
vc/probe.py          探测传输层：把一次精确请求交给引擎的 replay 子命令，读回响应产物
tests/               294 个单测
```

```bash
python3 -m unittest discover -s tests -v
cd engine-go && go test ./...
```
