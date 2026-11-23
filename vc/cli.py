"""空境 Kara —— 单入口命令行（唯一界面）。

三个动词，别的一律不进命令表：

    kara                              # 状态：引擎、库、存量
    kara scan -t <目标> [-m 模式]      # 扫（-m strike 就是深度验证）
    kara list [-i 序号] [--assets]    # 看（列表 / 详情 / 资产 / 导出）
    kara list --liveness unverified   # 拎出从没复验过的命中（alive/dead/unverified/unknown/na）
    kara list --pipeline refuted      # 看被三层判成误报的（verified/refuted/uncertain/downgraded/unrun）
    kara verify [ID …] [--deep]       # 复验：三层流水线（L1 命中复核 → L2 → L3），--deep 用验证内核真打
    kara verify <ID> --feedback --verdict 误报|真报   # 人工回写判定（误报闭环）

约束：
  * 一条命令做一件事：没有子子命令、没有交互向导、没有配置文件。
  * 扫描与复验共用 ScanManager / Verifier，写同一个库（默认 ~/.kara/vuln.db）。
  * 引擎（Go 单文件）只负责跑，产物落收件箱，由 parsers_sweep 归一化入账。
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional

from . import __version__
from . import cli_extra
from . import paths as kpaths
from . import pipeline as pipemod
from . import probe as probe_mod
from . import report as kreport
from . import scans as sc
from . import verify as vfy
from . import waf as wafmod
from .ingest import Ingestor
from .store import Store

TERMINAL_STATUS = ("ok", "partial", "failed", "stopped", "interrupted", "timeout")
SEV_COLOR = {"critical": "35", "high": "31", "medium": "33", "low": "36", "info": "90"}
SEV_ORDER = ("critical", "high", "medium", "low", "info")
# 存活状态配色（黑白灰为主）：颜色只落在单个字符的符号上，状态词与数字一律不着色。
# 三态靠符号 + 文字区分（● ○ — ? ∅），色盲 / NO_COLOR / 非 TTY 不丢任何信息
# （WCAG 1.4.1：颜色不得单独承载信息）。语义沿用严重度色板，不引新色相：
# ●红=漏洞还活着　○绿=确认已消失　—黄=待复验　?青=没结论　∅暗灰=不可复验。
LIVE_COLOR = {"ALIVE": "31", "DEAD": "32", "UNVERIFIED": "33", "UNKNOWN": "36", "NA": "90"}


# ---------------------------------------------------------------- 输出小工具

def _tty() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() and code else text


def _sev(sev: str) -> str:
    return _c(f"{sev:<8}", SEV_COLOR.get(sev, "0"))


def _live(token: str) -> str:
    """存活列：符号 + 文字承载语义，颜色只点单个字符的符号。

    先按列宽垫平再给符号上色（ANSI 序列不计显示宽度，与 _sev 同一手法）。
    """
    sym = vfy.LIVENESS_SYMBOLS[token]
    text = f"{sym} {token}"
    pad = " " * max(0, 12 - _w(text))
    return _c(sym, LIVE_COLOR.get(token, "")) + f" {token}" + pad


def _liveness_line(counts: Dict[str, int]) -> str:
    """汇总行：黑白灰为主——非零桶数字加粗、零桶整体淡化，不靠红黄绿。

    五桶恒显示、加起来等于命中总数；符号与列表列一致。
    """
    parts = []
    for t in vfy.LIVENESS_TOKENS:
        n = counts.get(t, 0)
        seg = f"{vfy.LIVENESS_SYMBOLS[t]} {vfy.LIVENESS_LABELS[t]} "
        parts.append(seg + _c(str(n), "1") if n else _c(seg + "0", "90"))
    return " · ".join(parts)


def _norm_liveness(raw: str) -> str:
    tok = (raw or "").strip().upper()
    if tok and tok not in vfy.LIVENESS_STATES:
        raise ValueError(f"未知存活状态：{raw}（可选 "
                         + " / ".join(t.lower() for t in vfy.LIVENESS_TOKENS) + "）")
    return tok


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _w(s: Any) -> int:
    """显示宽度：东亚宽字符算 2 列（表格别错位）。

    先剥 ANSI 色序再量——转义序列不占显示列；否则 TTY 下带色单元格
    （表头/严重度/存活）会被误判「已够宽」而不垫空格，整行错位。
    """
    s = "" if s is None else str(s)
    s = _ANSI.sub("", s)
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def _pad(s: Any, width: int) -> str:
    s = "" if s is None else str(s)
    return s + " " * max(0, width - _w(s))


def _cut(s: Any, width: int) -> str:
    s = "" if s is None else str(s)
    if _w(s) <= width:
        return s
    out, used = "", 0
    for ch in s:
        step = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + step > width - 1:
            break
        out, used = out + ch, used + step
    return out + "…"


def _hms(sec: float) -> str:
    sec = max(0, int(sec or 0))
    return f"{sec // 60:02d}:{sec % 60:02d}"


def _table(headers: List[str], rows: List[List[Any]], widths: List[int]) -> str:
    lines = ["  ".join(_pad(_c(h, "1"), widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("─" * widths[i] for i in range(len(headers))))
    for r in rows:
        lines.append("  ".join(_pad(v, widths[i]) for i, v in enumerate(r)))
    return "\n".join(lines)


def probe_scheme(hostport: str) -> str:
    """裸主机（可带端口）→ https / http。

    引擎对 url 类目标默认补 https://，碰上 http 站会直接扫空：连接失败 → 0 命中，
    看着像「目标干净」。这里先握手一次再决定，省掉一次白跑。
    """
    head = hostport.split("/")[0]
    host, _, port = head.rpartition(":")
    if not host:
        host, port = head, ""
    host = host.strip("[]")
    if not host:
        return "https"

    def _port(default: int) -> int:
        return int(port) if port.isdigit() else default

    try:
        sock = socket.create_connection((host, _port(443)), timeout=3)
        ctx = ssl._create_unverified_context()
        ctx.wrap_socket(sock, server_hostname=host).close()
        return "https"
    except Exception:
        pass
    try:
        socket.create_connection((host, _port(80)), timeout=3).close()
        return "http"
    except Exception:
        return "https"


# ---------------------------------------------------------------- 装配

class Ctx:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.db = os.path.abspath(os.path.expanduser(args.db or kpaths.default_db_path()))
        self.inboxes = [os.path.abspath(os.path.expanduser(p))
                        for p in (getattr(args, "inbox", None) or kpaths.DEFAULT_INBOXES)]
        for box in self.inboxes:
            try:
                os.makedirs(box, exist_ok=True)
            except OSError:
                pass
        self.store = Store(self.db)
        self.ingestor = Ingestor(self.store, self.inboxes)

    def manager(self, mode_args: Optional[list] = None) -> sc.ScanManager:
        # ingest_cb=None：入账由本进程在确定时机跑一次，避免同一批产物入两遍
        return sc.ScanManager(
            db_path=self.db,
            inbox_root=self.inboxes[0],
            engine=getattr(self.args, "engine", ""),
            timeout=getattr(self.args, "timeout", 900),
            max_parallel=getattr(self.args, "parallel", 2),
            mode_args=mode_args,
            ingest_cb=None,
        )


# ---------------------------------------------------------------- 任务轮询

def _print_job_status(runs: List[Dict[str, Any]], elapsed: float, job_status: str) -> None:
    if not _tty():
        return
    parts = []
    for r in runs[:4]:
        parts.append(f"{_cut(r['target'], 26)} {_pad(r['pct'], 3)}% {_cut(r['step'] or r['status'], 14)}")
    more = "" if len(runs) <= 4 else f" +{len(runs) - 4}"
    line = f"{_c('[kara]', '36')} {_hms(elapsed)}  {job_status:<9} " + " │ ".join(parts) + more
    sys.stdout.write("\r\033[K" + line[:200])
    sys.stdout.flush()


def _run_job_loop(mgr, job_id: int) -> str:
    t0 = time.time()
    cursor = 0
    status = "queued"
    try:
        while True:
            j = mgr.job(job_id, log_from=cursor)
            if not j:
                print(_c("[!] 任务查不到，可能被清库了", "31"), file=sys.stderr)
                return "failed"
            log = j.get("log") or {}
            for line in log.get("lines") or []:
                if _tty():
                    sys.stdout.write("\r\033[K")
                print(f"  {_cut(line, 160)}")
            cursor = log.get("next", cursor)
            status = j.get("status", status)
            _print_job_status(j.get("runs") or [], time.time() - t0, status)
            if status in TERMINAL_STATUS:
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        print()
        print(_c("[kara] 收到中断，正在让引擎收工（进程组 TERM → KILL）…", "33"))
        mgr.stop(job_id)
        while True:
            j = mgr.job(job_id)
            if (j or {}).get("status") in TERMINAL_STATUS:
                status = j["status"]
                break
            time.sleep(0.3)
    if _tty():
        sys.stdout.write("\r\033[K")
    print()
    print(f"{_c('[kara]', '36')} 任务 #{job_id} {status} · 用时 {_hms(time.time() - t0)}")
    return status


def _ingest(ctx: Ctx) -> Dict[str, Any]:
    t0 = time.strftime("%Y-%m-%d %H:%M:%S")   # 这一轮扫描的起始时刻：历史钩子只处理这批碰过的行
    stats = ctx.ingestor.scan() or {}
    print(f"{_c('[kara]', '36')} 入账：新解析 {stats.get('parsed', 0)} 个产物 · "
          f"漏洞 +{stats.get('findings_added', 0)} · 合并 {stats.get('findings_merged', 0)} · "
          f"资产 +{stats.get('assets', 0)} · 解析失败 {stats.get('errors', 0)}")
    # 误报闭环的入账钩子：人判过误报的 (主机, 规则, 参数) 再次命中时降级并注明，
    # 不静默丢弃（那是隐瞒）也不照旧报高危（那是无视人的判断）。
    hist = vfy.apply_history(ctx.store, since=t0)
    if hist.get("marked"):
        print(f"{_c('[kara]', '36')} 历史人工结论生效：{hist['marked']} 条命中被降级待复核"
              f"（{_c('kara list --pipeline downgraded', '36')}）")
    stats = dict(stats)
    stats["history_marked"] = hist.get("marked", 0)
    return stats


def _mode_args(args: argparse.Namespace, mode: str = "strike") -> List[str]:
    """给引擎的透传参数：strike 走验证内核，brute 走爆破。其它模式用不到。"""
    out: List[str] = []
    if mode == "brute":
        if getattr(args, "ports", ""):
            out += ["-p", args.ports]
        if getattr(args, "service", ""):
            out += ["--service", args.service]
        return out
    if getattr(args, "ports", ""):
        out += ["--ports", args.ports]
    if getattr(args, "intensity", ""):
        out += ["--intensity", args.intensity]
    if getattr(args, "allow_public", False):
        out += ["--allow-public"]
    return out


def _level_of(row: Dict[str, Any]) -> str:
    """从证据串里摘出验证内核给的级别标记，如 [L2/confirmed]。"""
    ev = row.get("evidence") or ""
    if "[" in ev and "]" in ev:
        seg = ev[ev.rfind("[") + 1:ev.rfind("]")]
        if "/" in seg or seg.startswith("L"):
            return seg
    return "-"


def _show_scan_waf(mgr: Any, job_id: int) -> None:
    """扫完先报 WAF 三态，再报命中。

    顺序是有讲究的：先看见「这个目标被拦了」，后面那行「0 命中」才不会被误读成
    「目标上什么都没有」。这就是总纲 4.1 要的「指纹前置」在输出层的落点。
    """
    try:
        runs = mgr.job(job_id).get("runs") or []
    except Exception:
        return
    marked = [r for r in runs if (r.get("waf") or {}).get("state")]
    if not marked:
        return
    rows = []
    for r in marked:
        w = r["waf"]
        rows.append([_cut(r.get("target") or "-", 34), w.get("badge") or "-",
                     _cut(w.get("label") or "", 10), _cut(w.get("waf") or "未识别", 22),
                     r.get("findings") or 0])
    print()
    print(_table(["目标", "", "三态", "WAF", "命中"], rows, [34, 2, 10, 22, 4]))
    n_block = sum(1 for r in marked if r["waf"].get("state") == wafmod.BLOCKED)
    if n_block:
        print(_c(f"  ↑ {n_block} 个目标被 WAF 拦：命中的 0 条不代表「不存在」，"
                 f"报告里按「被拦」写，别写成「未发现」", "33"))


def _show_new(ctx: Ctx, before: int) -> int:
    rows = [dict(r) for r in ctx.store.conn.execute(
        "SELECT id,sev,title,asset,endpoint,count,evidence FROM findings WHERE id > ? "
        "ORDER BY sev_rank DESC, id", (before,)).fetchall()]
    if not rows:
        print(f"{_c('[kara]', '36')} 本轮没有新增命中（老命中被重复报到的会并进原条目）")
        return 0
    print()
    print(_table(["ID", "严重度", "标题", "资产", "级别", "次数"],
                 [[r["id"], _sev(r["sev"]), _cut(r["title"], 40), _cut(r["asset"], 26),
                   _cut(_level_of(r), 12), r["count"]] for r in rows],
                 [5, 8, 40, 26, 12, 4]))
    print(f"\n看详情：{_c('kara list -i ' + str(rows[0]['id']), '36')}　"
          f"复验：{_c('kara verify --ids ' + ','.join(str(r['id']) for r in rows[:8]), '36')}")
    return 0


# ---------------------------------------------------------------- 状态（裸命令）

def cmd_status(ctx: Ctx, args: argparse.Namespace) -> int:
    mgr = ctx.manager()
    meta = mgr.meta().get("engine") or {}
    s = ctx.store.summary()
    print(f"{_c('空境 · Kara', '1')} v{__version__}　本地漏扫（单一 CLI）")
    print(f"  引擎　{meta.get('path') or '(未找到)'}"
          + (f"　{meta.get('version') or ''}" if meta.get("ok") else ""))
    if not meta.get("ok"):
        print(_c("  " + (meta.get("hint") or sc.ENGINE_HINT).replace("\n", "\n  "), "33"))
    print(f"  库　　{ctx.db}")
    sev = s["severity"]
    print(f"  存量　漏洞 {s['findings']} 条 / 命中 {s['hits']} 次　资产 {s['assets']}　文件 {s['files']}")
    print("  分级　" + "　".join(f"{k} {sev.get(k, 0)}" for k in SEV_ORDER))
    print("  存活　" + _liveness_line(vfy.liveness_summary(s.get("by_verify") or [])))
    if s.get("by_waf"):
        print("  三态　" + _waf_line(s.get("by_waf")))
    if s.get("last_scan"):
        print(f"  最近　{s['last_scan']}")
    print()
    print("  kara scan -t <目标> [-m 模式]　扫（-m strike = 深度验证，会真发请求）")
    print("  kara list [-i 序号] [--assets] [--liveness …]　看（--csv/--md 导出）")
    print("  kara verify [--ids …] [--liveness …] [--deep]　复验")
    print("  kara diff --since <时间> [--md 文件]　对账：新增 / 持续 / 未再出现（复测第一段）")
    print("  kara doctor　交付前自检：引擎 / 子命令 / 库 / POC / 离网守卫")
    print("  kara poc [--show 名] [--run 名 -t 目标 --yes]　POC 库浏览与单发")
    print("  kara replay -u <url> [-m POST -d …]　单次精确请求 → 复现 curl")
    return 0


# ---------------------------------------------------------------- scan

REPORT_MODES = ("strike", "brute")


def cmd_scan(ctx: Ctx, args: argparse.Namespace) -> int:
    mode = args.mode
    mgr = ctx.manager(mode_args=_mode_args(args, mode) if mode in REPORT_MODES else None)
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2

    raw = list(args.targets)
    if sc.MODES[mode]["kind"] == "url" and args.scheme != "raw":
        fixed = []
        for t in raw:
            if "://" in t:
                fixed.append(t)
                continue
            picked = args.scheme if args.scheme in ("http", "https") else probe_scheme(t)
            fixed.append(f"{picked}://{t}")
            print(f"  {_c('[scheme]', '36')} {t} → {picked}://{t}")
        raw = fixed
    try:
        targets = sc.normalize_targets(mode, raw)
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2

    before = ctx.store.conn.execute("SELECT COALESCE(MAX(id),0) c FROM findings").fetchone()["c"]
    print(f"{_c('空境 · Kara', '1')} v{__version__}　{sc.MODES[mode]['label']}")
    print(f"  模式　{sc.MODES[mode]['hint']}")
    print(f"  目标　{', '.join(targets)}")
    print(f"  引擎　{mgr.engine}")
    print()

    t0 = time.time()
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    res = mgr.start(mode, targets, parallel=args.parallel, timeout=args.timeout)
    _run_job_loop(mgr, res["job_id"])
    _show_scan_waf(mgr, res["job_id"])
    stats = _ingest(ctx)
    _show_new(ctx, before)

    if not getattr(args, "no_report", False):
        _auto_report(ctx, before, mode=mode, targets=targets, engine=mgr.engine,
                     started=started, elapsed=time.time() - t0, stats=stats)
    return 0


def _auto_report(ctx: Ctx, before: int, *, mode: str, targets: List[str],
                 engine: str = "", started: str = "", elapsed: float = 0.0,
                 stats: Optional[Dict[str, Any]] = None) -> str:
    """扫完立刻落一份报告：这次扫了什么、每条凭什么算、怎么复现。"""
    rows = [dict(r) for r in ctx.store.conn.execute(
        "SELECT * FROM findings WHERE id > ? ORDER BY sev_rank DESC, id", (before,)).fetchall()]
    notes = [
        f"模式 `{mode}`：{sc.MODES.get(mode, {}).get('hint', '')}",
        f"目标 {len(targets)} 个：{', '.join(targets)}",
        f"引擎 `{engine or '未指定'}`",
        "全部请求只发往目标本身（断网/内网可用，不访问任何第三方服务）",
    ]
    text = kreport.render(rows, target=", ".join(targets), mode=mode, engine=engine,
                          db=ctx.db, started=started, elapsed=elapsed, stats=stats, notes=notes)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", targets[0] if targets else "scan")[:50]
    path = kreport.write(text, os.path.expanduser("~/.kara/reports"),
                         f"{safe}-{mode}-{time.strftime('%Y%m%d-%H%M%S')}.md")
    print(f"{_c('[kara]', '36')} 报告：{_c(path, '36')}（{len(rows)} 条，含判据/证据/复现）")
    return path


# ---------------------------------------------------------------- list

def _ports_text(ports: Any, cap: int = 8) -> str:
    items = []
    for p in ports or []:
        if isinstance(p, dict):
            num, svc = p.get("port"), p.get("service") or ""
            items.append(f"{num}" + (f"({svc})" if svc else ""))
        else:
            items.append(str(p))
    if not items:
        return "-"
    head = ",".join(items[:cap])
    return head + (f" …+{len(items) - cap}" if len(items) > cap else "")


def _norm_waf(raw: str) -> str:
    """--waf 取值归一。认不出的直接抛：静默忽略会让人把空结果读成「库里没有」。"""
    try:
        return wafmod.norm_state(raw)
    except ValueError:
        raise ValueError(f"未知 WAF 三态：{raw}（可选 blocked / absent / unknown / present）")


def _waf_cell(r: Dict[str, Any]) -> str:
    """列表的 WAF 列：符号 + 厂商名（认不出厂商才退回状态词）。空状态显示 -（没判过）。"""
    state = str(r.get("waf_state") or "")
    if not state:
        return "-"
    names = [x.strip() for x in str(r.get("waf") or "").split(",") if x.strip()]
    return f"{wafmod.badge(state)} {names[0] if names else wafmod.label(state)}"


def _waf_line(by_waf: Any) -> str:
    """三态汇总行：恒显示四桶，被拦那桶非零就加粗——它是唯一会被误读成「不存在」的一桶。"""
    counts = {s: 0 for s in wafmod.STATES}
    for row in by_waf or []:
        if isinstance(row, dict) and row.get("waf_state") in counts:
            counts[row["waf_state"]] = int(row.get("n") or 0)
    parts = []
    for s in (wafmod.BLOCKED, wafmod.UNKNOWN, wafmod.ABSENT, wafmod.PRESENT):
        n = counts[s]
        seg = f"{wafmod.badge(s)} {wafmod.label(s)} "
        parts.append(seg + _c(str(n), "1") if n else _c(seg + "0", "90"))
    return " · ".join(parts)


def cmd_list(ctx: Ctx, args: argparse.Namespace) -> int:
    try:
        liveness = _norm_liveness(getattr(args, "liveness", ""))
        waf = _norm_waf(getattr(args, "waf", ""))
        pipeline = str(getattr(args, "pipeline", "") or "").strip()
        if pipeline:
            # 让错误在筛选前抛出，别等导出完才发现拼错了
            Store._filter(pipeline=pipeline)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    if args.csv or args.md:
        out = os.path.abspath(os.path.expanduser(args.csv or args.md))
        if args.csv:
            # 带 BOM：Windows Excel 双击不乱码
            data = ctx.store.export_csv(sev=args.sev, status=args.status, q=args.q,
                                        liveness=liveness, waf=waf,
                                        pipeline=pipeline).encode("utf-8-sig")
        else:
            rows = ctx.store.findings(sev=args.sev, status=args.status, q=args.q,
                                      limit=10000, liveness=liveness, waf=waf,
                                      pipeline=pipeline)["rows"]
            data = kreport.render(rows, title="空境 Kara 漏洞清单", db=ctx.db,
                                  notes=["按当前筛选条件导出的清单（与自动报告同一渲染器）"]).encode("utf-8")
        with open(out, "wb") as fh:
            fh.write(data)
        print(f"已写 {out}（{len(data)} 字节）")
        return 0

    if args.id is not None:
        return _show_one(ctx, args.id)

    if args.assets:
        data = ctx.store.assets(q=args.q, limit=args.limit)
        rows = data["rows"]
        if not rows:
            print("库里还没有资产。先 kara scan。")
            return 0
        print(_table(["资产", "IP", "端口", "标题 / 最高命中", "指纹", "漏洞"],
                     [[_cut(r.get("host") or "-", 30), _cut(r.get("ip") or "-", 16),
                       _cut(_ports_text(r.get("ports")), 30),
                       _cut(r.get("title") or r.get("hint") or "-", 30),
                       _cut(r.get("fingerprint") or r.get("services") or "-", 22),
                       f"{r.get('n_find') or 0}" + (f" ({r['top_sev']})" if r.get("top_sev") else "")]
                      for r in rows],
                     [30, 16, 30, 30, 22, 12]))
        print(f"\n共 {data['total']} 个资产（显示 {len(rows)}）")
        return 0

    # 汇总先行：产品承诺「每一条命中都回答：现在还活着吗」，存量分布放第一行。
    # 这是全库口径（不随 --sev/--q/--liveness 变），筛选后的条数看底部「共 N 条」。
    summary = ctx.store.summary()
    print("存量　" + _liveness_line(vfy.liveness_summary(ctx.store.verify_stats())))
    # 三层流水线紧跟存活：存活回答「还在不在」，三层回答「这个结论站不站得住」。
    print("三层　" + _pipeline_line(summary.get("by_pipeline"), summary.get("findings") or 0))
    # WAF 三态紧跟存活：被拦的那批必须和「确认不存在」分两栏读，
    # 否则列表上同样一个 0 命中，谁也分不清是没东西还是被挡了。
    print("三态　" + _waf_line(summary.get("by_waf")))
    blocked_n = sum(int(r.get("n") or 0) for r in (summary.get("by_waf") or [])
                    if r.get("waf_state") == wafmod.BLOCKED)
    if blocked_n:
        print(_c(f"　　　↑ 其中 {blocked_n} 条是「被拦」，不计入「已确认不存在」；"
                 f"换出口/降速/加白名单后重测才算数", "33"))
    print()
    data = ctx.store.findings(sev=args.sev, status=args.status, q=args.q,
                              limit=args.limit, liveness=liveness, waf=waf, pipeline=pipeline)
    rows = data["rows"]
    if not rows:
        print("库里没有符合条件的条目。先 kara scan。")
        return 0
    print(_table(["ID", "严重度", "存活", "三层", "WAF", "标题", "资产", "端点", "级别", "次数", "状态"],
                 [[r["id"], _sev(r["sev"]), _live(vfy.liveness_of(r)), _pipe_cell(r),
                   _cut(_waf_cell(r), 14),
                   _cut(r["title"], 32), _cut(r["asset"], 20), _cut(r["endpoint"] or "-", 20),
                   _cut(_level_of(dict(r)), 12), r["count"], _cut(r["status"], 8)] for r in rows],
                 [5, 8, 12, 6, 14, 32, 20, 20, 12, 4, 8]))
    tail = (f"\n共 {data['total']} 条（显示 {len(rows)}）　详情 {_c('kara list -i <ID>', '36')}"
            f"　导出 {_c('kara list --csv out.csv', '36')}")
    if liveness == "UNVERIFIED":
        tail += f"\n复验这批：{_c('kara verify --liveness unverified', '36')}"
    if not waf:
        tail += f"\n只看被拦：{_c('kara list --waf blocked', '36')}"
    if not pipeline:
        tail += f"\n只看三层全过：{_c('kara list --pipeline verified', '36')}"
    print(tail)
    return 0


def _pipe_cell(r: Any) -> str:
    """list 的「三层」列：✓3/3、✗1/2、—（没跑）、⚠降级、✗人工（人已判误报）。"""
    def get(k: str) -> str:
        try:
            return str(r[k] or "")
        except (KeyError, IndexError, TypeError):
            return ""

    fb = get("fb_state")
    if fb == pipemod.REFUTED:
        return "✗人工"
    if fb == pipemod.VERIFIED:
        return "✓人工"
    return pipemod.badge(vfy.pipeline_of(r))


def _pipeline_line(by_pipe: Optional[List[Dict[str, Any]]], total: int) -> str:
    """抬头一行：三层全过 / 存疑 / 误报 / 降级 / 未跑（各桶之和 == 命中总数）。"""
    n = {str(r.get("pipe_state") or ""): int(r.get("n") or 0) for r in (by_pipe or [])}
    done = sum(v for k, v in n.items() if k)
    buckets = (("✓ 全过", n.get("verified", 0), "32"), ("? 存疑", n.get("uncertain", 0), "33"),
               ("✗ 误报", n.get("refuted", 0), "31"), ("⚠ 降级", n.get("downgraded", 0), "33"),
               ("— 未跑", max(0, int(total) - done), "90"))
    out = []
    for label, num, color in buckets:
        txt = f"{label} {num}"
        out.append(_c(txt, color) if num else _c(txt, "90"))
    return " · ".join(out)


def _show_one(ctx: Ctx, row_id: int) -> int:
    rows = ctx.store.findings_by_ids([row_id])
    if not rows:
        print(f"[!] 序号 {row_id} 不存在", file=sys.stderr)
        return 2
    r = dict(rows[0])
    print(f"{_c(str(r.get('title') or ''), '1')}")
    print(f"  严重度　{_sev(r.get('sev') or 'info')}　级别 {_level_of(r)}")
    print(f"  资产　　{r.get('asset') or '-'}　端口 {r.get('port') or '-'}　IP {r.get('ip') or '-'}")
    print(f"  端点　　{r.get('endpoint') or '-'}")
    print(f"  来源　　{r.get('sources') or '-'}　次数 {r.get('count')}　状态 {r.get('status')}")
    live = vfy.liveness_of(r)
    sym = vfy.LIVENESS_SYMBOLS[live]
    print(f"  复验　　{_c(sym, LIVE_COLOR[live])} {live} · "
          f"{r.get('verify_state') or '未复验'} {r.get('verify_note') or ''}")
    print(f"  时间　　{r.get('first_seen')} → {r.get('last_seen')}")
    if r.get("evidence"):
        print(f"  判据　　{_cut(r['evidence'], 400)}")
    if r.get("waf_state"):
        # 三态单独一行：这一条到底是「扫到过」还是「只被拦过」，看这一行
        who = f"（{r['waf']}）" if r.get("waf") else ""
        print(f"  WAF　　 {wafmod.label(r['waf_state'])}{who}　"
              + ("被拦 ≠ 不存在：换出口/降速后重测再下结论"
                 if r["waf_state"] == wafmod.BLOCKED else ""))
    if vfy.has_layers(r):
        # 三层结论是这条命中的「凭什么算命中」，和复验状态分两段读
        res = vfy.pipeline_of(r)
        print("  三层　　" + f"{pipemod.VERDICT_SYMBOLS.get(res['verdict'], '?')} "
              f"{pipemod.VERDICT_LABELS.get(res['verdict'], res['verdict'])}"
              f"　{_cut(res['reason'], 120)}")
        for n in pipemod.LAYERS:
            item = res["layers"].get(n) or {}
            if not item:
                continue
            print(f"　　{n} {pipemod.LAYER_TITLES[n]}\u3000"
                  f"{pipemod.STATE_SYMBOLS.get(item.get('state'), '?')} "
                  f"{pipemod.STATE_LABELS.get(item.get('state'), item.get('state'))}\u3000"
                  f"{_cut(item.get('reason') or '', 90)}")
        if res.get("minimal_curl"):
            print(f"  最小复现\u3000{_c(res['minimal_curl'], '36')}")
    if r.get("fb_state"):
        human = "误报" if pipemod.norm_human(r["fb_state"]) == pipemod.REFUTED else "真报"
        print(f"  人工　　{human}（{r.get('fb_at') or ''}）——历史判定会参与后续复验")
    if r.get("repro"):
        print(f"  复现　　{_c(str(r['repro']), '36')}")
    print(f"  产物　　{r.get('files') or '-'}")
    return 0


# ---------------------------------------------------------------- verify

def _target_of(row: Dict[str, Any]) -> str:
    """一条命中 → 可回访的目标（端点裁到 scheme://host:port，退回「资产:端口」）。"""
    ep = (row.get("endpoint") or "").strip()
    if ep.startswith(("http://", "https://")):
        u = urllib.parse.urlsplit(ep)
        if u.hostname:
            return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
    # strike 服务级命中的端点是裸 host:port：原样带端口回访（strike 吃 kind=any）
    hp = vfy.bare_hostport(ep)
    if hp:
        return hp
    asset = str(row.get("asset") or "").strip()
    if asset and asset not in ("-", "unknown"):
        port = row.get("port")
        return f"{asset}:{port}" if port and ":" not in asset else asset
    return ""


def _verify_rows(ctx: Ctx, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """挑要复验的命中：位置参数 / --ids 优先，其次按筛选条件。"""
    raw = " ".join(str(x) for x in (getattr(args, "ids_pos", None) or []))
    if getattr(args, "ids", ""):
        raw = f"{raw} {args.ids}"
    ids = [int(x) for x in raw.replace(",", " ").split() if x.strip().lstrip("-").isdigit()]
    if ids:
        got = {int(r["id"]): dict(r) for r in ctx.store.findings_by_ids(ids)}
        return [got[i] for i in ids if i in got]     # 按用户给的顺序，别让库的顺序打乱输出
    liveness = _norm_liveness(getattr(args, "liveness", ""))
    pipeline = str(getattr(args, "pipeline", "") or "")
    return [dict(r) for r in ctx.store.findings(sev=args.sev, status=args.status,
                                                limit=args.limit, liveness=liveness,
                                                pipeline=pipeline)["rows"]]


def cmd_verify(ctx: Ctx, args: argparse.Namespace) -> int:
    if getattr(args, "feedback_list", False):
        return _cmd_feedback_list(ctx, args)
    try:
        rows = _verify_rows(ctx, args)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    if getattr(args, "feedback", False):
        return _cmd_feedback(ctx, rows, args)
    if not rows:
        print("没有要复验的条目。")
        return 0
    if args.deep:
        return _verify_deep(ctx, rows, args)

    rest = rows
    if not getattr(args, "legacy", False):
        mgr = ctx.manager()
        if not mgr.engine:
            print(_c("[i] 没找到引擎：三层流水线发不出请求，回落到整模式重跑复验\n" + sc.ENGINE_HINT, "33"),
                  file=sys.stderr)
        else:
            with probe_mod.EngineProber(mgr.engine, timeout=getattr(args, "probe_timeout", 10)) as pr:
                if pr.available():
                    rest = _verify_layers(ctx, rows, args, pr)
                else:
                    print(_c("[i] 引擎没有 replay 子命令（版本旧）：本次回落到整模式重跑复验。\n"
                             "    三层流水线要「换参数名再打一枪」，老引擎给不了这个控制。", "33"),
                          file=sys.stderr)
    if rest:
        return _verify_legacy(ctx, rest, args)
    return 0


def _verify_layers(ctx: Ctx, rows: List[Dict[str, Any]], args: argparse.Namespace,
                   prober) -> List[Dict[str, Any]]:
    """三层流水线：逐条跑、逐条打印、逐条落库。返回没能走流水线的行（交给老路径）。"""
    todo = [r for r in rows if pipemod.applicable(r)]
    rest = [r for r in rows if not pipemod.applicable(r)]
    if not todo:
        return rows

    print(f"三层复验 {len(todo)} 条　L1 命中复核 → L2 上下文复核 → L3 最小化 PoC")

    def on_row(row: Dict[str, Any], res: Dict[str, Any]) -> None:
        print()
        print(f"{_c('#' + str(row.get('id')), '1')} {_cut(row.get('title') or '', 52)}　"
              f"{_sev(row.get('sev') or 'info')}　{_cut(str(row.get('sources') or ''), 20)}")
        ep = str(row.get("endpoint") or "")
        entry = ep if ep.startswith("http") else f"{pipemod.base_of(row)}{ep}"
        print(f"  入口　{entry}")
        print(pipemod.format_layers(res))

    results = vfy.run_layers(ctx.store, todo, prober=prober, on_row=on_row)
    print()
    counts = _verdict_counts([r["result"] for r in results])
    order = (pipemod.VERIFIED, pipemod.REFUTED, pipemod.UNCERTAIN, pipemod.DOWNGRADED)
    labels = dict(pipemod.VERDICT_LABELS, **{pipemod.DOWNGRADED: "降级（历史人工判误报）"})
    syms = dict(pipemod.VERDICT_SYMBOLS, **{pipemod.DOWNGRADED: "⚠"})
    print(f"{_c('[kara]', '36')} 三层完成　"
          + "　".join(f"{syms[v]} {labels[v]} {counts[v]}" for v in order if counts.get(v)))
    print(f"  明细 {_c('kara list --pipeline refuted', '36')}　"
          f"只回看结论 {_c('kara list -i <ID>', '36')}　"
          f"人工回写 {_c('kara verify <ID> --feedback --verdict 误报', '36')}")
    return rest


def _verdict_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {v: 0 for v in pipemod.VERDICTS}
    out[pipemod.DOWNGRADED] = 0
    for r in results:
        r = r or {}
        key = pipemod.DOWNGRADED if r.get("history_downgraded") else str(r.get("verdict") or "")
        if key in out:
            out[key] += 1
    return out


def _cmd_feedback(ctx: Ctx, rows: List[Dict[str, Any]], args: argparse.Namespace) -> int:
    """人工回写：误报 / 真报。写进 feedback 表，按 (host, rule, param) 累积。"""
    if not rows:
        print("[!] --feedback 要指定一条命中的序号，例如：kara verify 12 --feedback --verdict 误报",
              file=sys.stderr)
        return 2
    if len(rows) > 20:
        print(f"[!] 一次最多回写 20 条（给了 {len(rows)} 条）：人工判定要人真的看过", file=sys.stderr)
        return 2
    code = 0
    for row in rows:
        res = vfy.feedback(ctx.store, row, args.verdict, args.note or "")
        if not res.get("ok"):
            print(f"[!] {res.get('error')}", file=sys.stderr)
            return 2
        human = "误报" if res["verdict"] == pipemod.REFUTED else "真报"
        print(f"已记下人工判定：#{row.get('id')} {_cut(row.get('title') or '', 40)} → {human}"
              f"　（{res['host']} / {res['param'] or '无参数'} 已累计 {res['times']} 次）")
        if res["verdict"] == pipemod.REFUTED:
            print("  这条历史会参与判定：同一规则再次命中时降级为「存疑」并标注「历史人工判误报」，"
                  "不会静默丢弃")
        else:
            print("  下次复验若三层没全过，会提示「历史人工已确认」以免被误判成消失")
    print(f"\n查看人工判定台账：{_c('kara verify --feedback-list', '36')}")
    return code


def _cmd_feedback_list(ctx: Ctx, args: argparse.Namespace) -> int:
    rows = ctx.store.feedback_rows(limit=getattr(args, "limit", 200) or 200)
    if not rows:
        print("还没有人工判定记录。回写一条：kara verify <ID> --feedback --verdict 误报")
        return 0
    print(_table(["主机", "规则", "参数", "判定", "次数", "最近", "备注"],
                 [[_cut(r.get("host") or "-", 24), _cut(r.get("rule") or "-", 30),
                   _cut(r.get("param") or "-", 14),
                   "误报" if pipemod.norm_human(r.get("verdict")) == pipemod.REFUTED else "真报",
                   r.get("times") or 1, _cut(r.get("at") or "", 19), _cut(r.get("note") or "", 30)]
                  for r in rows],
                 [24, 30, 14, 6, 4, 19, 30]))
    print(f"\n共 {len(rows)} 条人工判定。这些结论会在扫描入账与复验时参与判定。")
    return 0


def _verify_legacy(ctx: Ctx, rows: List[Dict[str, Any]], args: argparse.Namespace) -> int:
    """老路径：按当初发现它的模式整组重跑，看同标题命中还在不在。

    没有请求上下文可换的类别（弱口令、配置检查）走这条：它们的「假命中」形态
    不是全站 500 / WAF 拦截页，而是「这次根本没测成」，重跑判可达性才是对的。
    """
    mgr = ctx.manager()
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2
    v = vfy.Verifier(ctx.store, engine=mgr.engine, timeout=args.timeout,
                     log=lambda lvl, msg: print(f"  [{lvl}] {msg}"))
    ids = [r["id"] for r in rows]
    print(f"复验 {len(ids)} 条：按当初发现它的同一个模式、同一个入口重跑…")
    v.start(ids)
    try:
        while True:
            st = v.status()
            if not st.get("running"):
                break
            if _tty():
                sys.stdout.write("\r\033[K" + f"{_c('[kara]', '36')} {st['done']}/{st['total']} "
                                                f"{_hms(st.get('elapsed') or 0)} "
                                                f"{_cut(st.get('current') or '', 60)}")
                sys.stdout.flush()
            time.sleep(0.4)
    except KeyboardInterrupt:
        print("\n[kara] 中断（跑完的那部分已写回库）")
        return 130
    if _tty():
        sys.stdout.write("\r\033[K")
    st = v.status()
    summary = st.get("summary") or {}
    print(f"{_c('[kara]', '36')} 复验完成　" + "　".join(f"{k} {n}" for k, n in summary.items() if n))
    for item in (st.get("last") or [])[:20]:
        print(f"  #{item.get('id')} {item.get('state')} {_cut(item.get('title') or '', 40)} "
              f"{_cut(item.get('note') or '', 64)}")
    return 0


def _verify_deep(ctx: Ctx, rows: List[Dict[str, Any]], args: argparse.Namespace) -> int:
    """--deep：用验证内核真打一遍（L1 → L2 的那一步），而不是重放只读探测。"""
    targets: List[str] = []
    for t in getattr(args, "target", None) or []:
        t = t.strip()
        if t and t.lower() not in {x.lower() for x in targets}:
            targets.append(t)
    for r in rows:
        t = _target_of(r)
        if t and t.lower() not in {x.lower() for x in targets}:
            targets.append(t)
    if not targets:
        print("这些条目没有可回访的目标（白盒报告、离线产物都这样），深度验证需要端点或资产。")
        return 0
    try:
        targets = sc.normalize_targets("strike", targets)
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2

    # dry-run 只列清单、不碰引擎：CI 里没有引擎二进制也该能过
    if args.dry_run:
        print(f"{_c('空境 · Kara', '1')} v{__version__}　深度验证（dry-run）")
        print(f"  目标 {len(targets)} 个")
        for i, t in enumerate(targets, 1):
            print(f"  {i:>2}. {t}")
        print("\n--dry-run：没有发起任何请求。去掉它就跑。")
        return 0

    mgr = ctx.manager(mode_args=_mode_args(args))
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2

    before = ctx.store.conn.execute("SELECT COALESCE(MAX(id),0) c FROM findings").fetchone()["c"]
    print(f"{_c('空境 · Kara', '1')} v{__version__}　深度验证")
    print(f"  来源　{len(rows)} 条命中 → 目标 {len(targets)} 个：{', '.join(targets)}")
    print(_c("  这一档会真的发请求（真登/未授权/注入探测），确认目标在授权范围内。", "33"))
    print()
    res = mgr.start("strike", targets, parallel=args.parallel, timeout=args.timeout)
    _run_job_loop(mgr, res["job_id"])
    _ingest(ctx)
    _show_new(ctx, before)
    return 0


# ---------------------------------------------------------------- 入口

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kara",
        description="空境 Kara —— 本地漏扫（scan / list / verify；补充 diff / doctor / poc / replay）",
        epilog="不给子命令就打印状态。")
    ap.add_argument("--db", default="", help=f"库路径（默认 {kpaths.default_db_path()}）")
    ap.add_argument("--inbox", action="append", default=None, help="收件箱目录，可重复")
    ap.add_argument("--engine", default="", help="引擎路径（默认自动查找）")
    ap.add_argument("--timeout", type=int, default=900, help="单目标超时秒数（默认 900）")
    ap.add_argument("--parallel", type=int, default=2, help="并发目标数（上限 4）")
    ap.add_argument("-v", "--version", action="version", version=f"kara {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="扫描（-m strike 为深度验证）")
    p.add_argument("-t", "--targets", nargs="+", required=True, help="目标（域名 / IP / URL）")
    p.add_argument("-m", "--mode", default="all", choices=list(sc.MODES), help="扫描模式")
    p.add_argument("--scheme", default="auto", choices=["auto", "http", "https", "raw"],
                   help="url 类模式的协议：auto 先握手判定（默认）")
    p.add_argument("--ports", default="", help="strike：top100/full/80,443；brute：22,3306,6379")
    p.add_argument("--service", default="", help="仅 brute：ftp/mysql/postgres/redis/telnet/http-basic")
    p.add_argument("--no-report", action="store_true", help="扫完不自动生成 Markdown 报告")
    p.add_argument("--intensity", default="", choices=["", "low", "normal", "high"],
                   help="仅 strike：强度档位")
    p.add_argument("--allow-public", action="store_true", help="仅 strike：允许公网目标")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("list", help="看：列表 / 详情 / 资产 / 导出")
    p.add_argument("-i", "--id", type=int, default=None, help="看某一条的详情")
    p.add_argument("--assets", action="store_true", help="看资产（主机/端口/指纹）")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="", help="待验证 / 已确认 / 误报 / 已修复 / 已忽略")
    p.add_argument("--liveness", default="", metavar="STATE",
                   help="存活状态：alive / dead / unverified / unknown / na")
    p.add_argument("--waf", default="", metavar="STATE",
                   help="WAF 三态：blocked（被拦）/ absent（真不存在）/ unknown（不确定）/ present")
    p.add_argument("--pipeline", default="", metavar="STATE",
                   help="三层结论：verified（全过）/ refuted / uncertain / downgraded / unrun")
    p.add_argument("--q", default="", help="关键词")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--csv", default="", help="导出 CSV 到该文件")
    p.add_argument("--md", default="", help="导出 Markdown 到该文件")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser(
        "verify", help="复验：三层流水线（L1 命中复核 → L2 上下文复核 → L3 最小化 PoC）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="复验：把「扫出来的结果」变成「能复现的结论」。默认走三层流水线。",
        epilog="""三层判定（任一层不通过就不算确认）
  L1 命中复核     原请求重放两次 + 无害对照：全站 500 / 静态同形 / 偶发 5xx / WAF 拦截页
                  全部挡在这里。被拦 = blocked（不下结论），不是 fail。
  L2 上下文复核   同位置换无害值、payload 换参数名/位置重放；SQLi 另做布尔对照
                  （1=1 vs 1=2，响应一致 = 布尔差异不成立 → 判误报）。
  L3 最小化 PoC   剥掉无关参数只留 payload 再打一次，产出能直接粘进报告的最小复现串；
                  剥完现象消失 = 现象不稳（存疑）。

结论：verified（三层全过）/ refuted（有层不通过）/ uncertain（证据不足）。
人工闭环：kara verify <ID> --feedback --verdict 误报|真报　（台账：--feedback-list）
历史人工判过误报的 (主机, 规则, 参数) 再次命中时降级为「存疑」并注明，不会静默丢弃。
弱口令 / 配置检查没有请求上下文可换，仍走整模式重跑（--legacy 可强制）。""")
    p.add_argument("ids_pos", nargs="*", metavar="ID", help="命中序号，如 12 15 19（也可用 --ids 12,15）")
    p.add_argument("--ids", default="", help="如 12,15,19；不给就按筛选批量")
    p.add_argument("--feedback", action="store_true",
                   help="人工回写判定（配 --verdict 误报/真报），写进反馈闭环")
    p.add_argument("--feedback-list", action="store_true", help="看人工判定台账")
    p.add_argument("--verdict", default="",
                   help="仅 --feedback：误报 / 真报（也收 false-positive / true-positive）")
    p.add_argument("--note", default="", help="仅 --feedback：备注（写进台账）")
    p.add_argument("--target", action="append", default=[], help="仅 --deep：直接指定目标")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="")
    p.add_argument("--liveness", default="", metavar="STATE",
                   help="按存活状态挑命中：alive / dead / unverified / unknown / na（--ids 优先）")
    p.add_argument("--pipeline", default="", metavar="STATE",
                   help="按三层结论挑命中：verified / refuted / uncertain / downgraded / unrun")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--legacy", action="store_true",
                   help="跳过三层流水线，按老办法整模式重跑（引擎没有 replay 时的兜底）")
    p.add_argument("--probe-timeout", type=int, default=10, help="单次探测超时秒数（默认 10）")
    p.add_argument("--deep", action="store_true", help="深度验证（会真发请求）")
    p.add_argument("--dry-run", action="store_true", help="仅 --deep：只列目标，不发请求")
    p.add_argument("--ports", default="", help="仅 --deep：top100 / full / 80,443")
    p.add_argument("--intensity", default="", choices=["", "low", "normal", "high"])
    p.add_argument("--allow-public", action="store_true")
    p.set_defaults(func=cmd_verify)

    cli_extra.add_subparsers(sub)

    ap.set_defaults(func=cmd_status)
    return ap


def _force_utf8_stdout() -> None:
    """把输出钉到 UTF-8。

    Windows 控制台默认 cp936/cp1252：中文路径、引擎版本串里的 · 之类字符
    会直接 UnicodeEncodeError，表现为「双击 bat 闪一下就没了」。
    这里自己钉，不依赖用户去设 PYTHONIOENCODING。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdout()
    args = build_parser().parse_args(argv)
    ctx = Ctx(args)
    try:
        return args.func(ctx, args) or 0
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
