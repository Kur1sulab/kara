"""kara 的补充子命令：diff / doctor / poc / replay / identifier。

为什么单独一个模块：cli.py 已经一千多行，这几条各自是独立动作，塞进主命令只会
把阅读路径拉得更长。这里只依赖标准库与本包既有模块（paths / scans），不引第三方。

几条命令的定位
    diff        两次时间窗对账：新增 / 持续 / 未再出现（复测报告第一段就要这个）
    doctor      交付前自检：引擎 / 子命令 / 库 / POC / 报告目录 / 离网守卫
    poc         POC 库浏览（--list / --show）；--run 会真发请求，必须显式 --yes
    replay      单次精确请求 → 拿回「能直接粘进报告的 curl 复现串」
    identifier  结构化标识符检测：校验位算得通才报（逻辑在 Go 内核，这里只转发）
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from . import paths as kpaths
from . import scans as sc

POC_DIR = os.path.join(sc.PKG_ROOT, "pocs")
REPORT_DIR = os.path.expanduser("~/.kara/reports")
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


# ---------------------------------------------------------------- 小工具

def _tty() -> bool:
    return sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text


def _cut(s: Any, width: int) -> str:
    text = "" if s is None else str(s)
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _pad(s: Any, width: int) -> str:
    text = _cut(s, width)
    fill = width - len(text)
    return text + " " * max(0, fill)


def _table(headers: List[str], rows: List[List[Any]], widths: List[int]) -> str:
    out = [" ".join(_pad(h, w) for h, w in zip(headers, widths)).rstrip()]
    out.append(" ".join("-" * w for w in widths))
    for row in rows:
        out.append(" ".join(_pad(c, w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(out)


def _sev_label(sev: Optional[str]) -> str:
    key = (sev or "").lower()
    return SEV_CN.get(key, sev or "-")


def _now_tag() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------- diff

def _norm_since(raw: str) -> str:
    """把 --since 归一成可比较的字符串。

    库里 first_seen / last_seen 存的是 `YYYY-MM-DD HH:MM:SS`；只给日期时按当天
    00:00:00 算，给到分钟就补齐秒，方便直接字符串比较（ISO 形态天然可比）。
    """
    text = (raw or "").strip()
    if not text:
        return ""
    text = text.replace("/", "-").replace("T", " ")
    if len(text) == 7:                       # 2026-11
        return text + "-01 00:00:00"
    if len(text) == 10:                      # 2026-11-20
        return text + " 00:00:00"
    if len(text) == 13:                      # 2026-11-20 09
        return text + ":00:00"
    if len(text) == 16:                      # 2026-11-20 09:30
        return text + ":00"
    return text


def _norm_ts(raw: Any) -> str:
    text = "" if raw is None else str(raw).strip().replace("/", "-").replace("T", " ")
    if len(text) == 10:
        return text + " 00:00:00"
    return text


def _classify(rows: List[Dict[str, Any]], since: str) -> Dict[str, List[Dict[str, Any]]]:
    """按时间窗把命中分三堆：新增 / 持续 / 未再出现。

    「未再出现」只是**没再扫到**，不等于修好了——报告里必须写成待复验，
    真结论要 `kara verify <ID>` 打一遍再说。
    """
    out: Dict[str, List[Dict[str, Any]]] = {"new": [], "ongoing": [], "gone": []}
    if not since:
        out["ongoing"] = list(rows)
        return out
    for row in rows:
        first = _norm_ts(row.get("first_seen"))
        last = _norm_ts(row.get("last_seen"))
        if not first and not last:
            out["ongoing"].append(row)
        elif first and first >= since:
            out["new"].append(row)
        elif last and last >= since:
            out["ongoing"].append(row)
        else:
            out["gone"].append(row)
    return out


def _diff_rows(rows: List[Dict[str, Any]]) -> List[List[Any]]:
    return [
        [r.get("id"), _sev_label(r.get("sev")), _cut(r.get("asset") or r.get("ip"), 22),
         _cut(r.get("title"), 34), _cut(r.get("endpoint"), 40)]
        for r in rows
    ]


def _write_diff_csv(path: str, buckets: Dict[str, List[Dict[str, Any]]]) -> None:
    fields = ["bucket", "id", "sev", "asset", "port", "title", "endpoint", "status",
              "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(fields)
        for name in ("new", "ongoing", "gone"):
            for r in buckets[name]:
                wr.writerow([name, r.get("id"), r.get("sev"), r.get("asset"), r.get("port"),
                             r.get("title"), r.get("endpoint"), r.get("status"),
                             r.get("first_seen"), r.get("last_seen")])


def _write_diff_md(path: str, buckets: Dict[str, List[Dict[str, Any]]], since: str,
                   asset: str) -> None:
    lines = ["# 对账报告（diff）", ""]
    lines.append(f"- 时间分界：{since or '（未指定）'}")
    if asset:
        lines.append(f"- 资产过滤：{asset}")
    lines.append(f"- 新增 {len(buckets['new'])} / 持续 {len(buckets['ongoing'])} / "
                 f"未再出现 {len(buckets['gone'])}")
    lines.append("")
    for key, title, note in (
        ("new", "一、新增（本次时间窗内首次出现）", ""),
        ("ongoing", "二、持续（窗口前已存在，窗口内仍出现）", ""),
        ("gone", "三、未再出现（窗口内未扫到）",
         "> 注意：未再出现 ≠ 已修复。修复结论必须 `kara verify <ID>` 打一遍。"),
    ):
        rows = buckets[key]
        lines += [f"## {title}", ""]
        if note:
            lines += [note, ""]
        if not rows:
            lines += ["（无）", ""]
            continue
        lines.append("| ID | 等级 | 资产 | 标题 | 位置 | 首次 | 最近 |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in rows:
            lines.append("| {id} | {sev} | {asset} | {title} | {ep} | {f} | {l} |".format(
                id=r.get("id"), sev=_sev_label(r.get("sev")),
                asset=(r.get("asset") or r.get("ip") or ""),
                title=(r.get("title") or "").replace("|", "\\|"),
                ep=(r.get("endpoint") or "").replace("|", "\\|"),
                f=r.get("first_seen") or "", l=r.get("last_seen") or ""))
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def cmd_diff(ctx: Any, args: argparse.Namespace) -> int:
    since = _norm_since(getattr(args, "since", "") or "")
    data = ctx.store.findings(sev=getattr(args, "sev", "") or "",
                              asset=getattr(args, "asset", "") or "",
                              limit=max(1, getattr(args, "limit", 500)))
    rows = data.get("rows", [])
    buckets = _classify(rows, since)
    asset = getattr(args, "asset", "") or ""

    if getattr(args, "csv", ""):
        _write_diff_csv(os.path.expanduser(args.csv), buckets)
        print(f"CSV 已写出：{os.path.abspath(os.path.expanduser(args.csv))}")
    if getattr(args, "md", ""):
        _write_diff_md(os.path.expanduser(args.md), buckets, since or "（未指定）", asset)
        print(f"Markdown 已写出：{os.path.abspath(os.path.expanduser(args.md))}")

    header = f"对账分界 {since or '（未指定，全部算持续）'}"
    if asset:
        header += f"　资产 {asset}"
    print(_c(header, "36"))
    print(f"  新增 {_c(str(len(buckets['new'])), '31')}　"
          f"持续 {len(buckets['ongoing'])}　"
          f"未再出现 {_c(str(len(buckets['gone'])), '33')}　"
          f"（库内 {data.get('total', len(rows))} 条，本次看 {len(rows)} 条）")
    widths = [6, 6, 22, 34, 40]
    headers = ["ID", "等级", "资产", "标题", "位置"]
    for key, title in (("new", "一、新增"), ("ongoing", "二、持续"), ("gone", "三、未再出现")):
        rows_k = buckets[key]
        print()
        print(_c(f"{title}（{len(rows_k)}）", "36"))
        if not rows_k:
            print("  （无）")
            continue
        print(_table(headers, _diff_rows(rows_k[: max(1, getattr(args, 'show', 20))]), widths))
        if len(rows_k) > getattr(args, "show", 20):
            print(f"  … 其余 {len(rows_k) - getattr(args, 'show', 20)} 条用 --md / --csv 导出看")
    if buckets["gone"]:
        print()
        print(_c("提示：未再出现 ≠ 已修复 —— 要结论请 kara verify <ID> 打一遍。", "33"))
    return 0


# ---------------------------------------------------------------- doctor

def _engine_subcommands(engine: str) -> Tuple[str, List[str]]:
    """问引擎要版本与可用子命令（只跑 `version` 与无参帮助，不发请求）。"""
    ver = ""
    subs: List[str] = []
    if not engine:
        return ver, subs
    for argv in ([engine, "version"], [engine]):
        try:
            cp = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=8)
        except Exception:
            continue
        text = (cp.stdout or "") + (cp.stderr or "")
        for line in text.splitlines():
            if not ver and "sweep" in line:
                ver = line.strip()[:120]
            hit = line.strip().split()
            if len(hit) >= 2 and hit[0] == "sweep" and hit[1][0].isalpha():
                if hit[1] not in subs:
                    subs.append(hit[1])
    return ver, subs


def collect_checks(engine: str, db_path: str, poc_dir: str = POC_DIR,
                   report_dir: str = REPORT_DIR, pkg_root: str = sc.PKG_ROOT) -> List[Dict[str, str]]:
    """自检项。纯函数式：给什么查什么，方便单测直接喂假路径。"""
    checks: List[Dict[str, str]] = []

    def add(level: str, label: str, detail: str = "") -> None:
        checks.append({"level": level, "label": label, "detail": detail})

    # 1) Python 版本
    ver = "%d.%d.%d" % sys.version_info[:3]
    if sys.version_info >= (3, 9):
        add("ok", "Python", ver)
    else:
        add("fail", "Python", f"{ver}（要求 ≥3.9）")

    # 2) 引擎
    if engine and os.path.isfile(engine) and os.access(engine, os.X_OK):
        ev, subs = _engine_subcommands(engine)
        add("ok", "引擎", f"{engine}　{ev or '（版本串读不出）'}")
        need = ["paths", "api", "cve", "fingerprint", "jsintel", "baseline",
                "replay", "poc", "strike", "identifier"]
        missing = [s for s in need if subs and s not in subs]
        if not subs:
            add("warn", "引擎子命令", "帮助文本里没解析出子命令表（版本差异？），跳过比对")
        elif missing:
            add("warn", "引擎子命令", "缺：" + ", ".join(missing))
        else:
            add("ok", "引擎子命令", f"{len(need)}/{len(need)} 齐全（{'/'.join(need)}）")
    else:
        add("fail", "引擎", f"找不到可执行引擎（{engine or '未指定'}）—— 扫描/复验全都跑不了")

    # 3) 库
    if os.path.isfile(db_path):
        try:
            size = os.path.getsize(db_path)
            writable = os.access(db_path, os.W_OK) and os.access(os.path.dirname(db_path) or ".", os.W_OK)
            add("ok" if writable else "fail", "库",
                f"{db_path}　{size / 1024:.0f} KB" + ("" if writable else "　只读"))
        except OSError as exc:
            add("warn", "库", f"{db_path}　读取失败：{exc}")
    else:
        add("warn", "库", f"{db_path} 还不存在（首次 scan 会自动建）")

    # 4) POC 库
    try:
        pocs = sorted(n for n in os.listdir(poc_dir) if n.endswith((".yaml", ".yml")))
        add("ok" if pocs else "warn", "POC", f"{len(pocs)} 个（{poc_dir}）")
    except OSError:
        add("warn", "POC", f"目录不存在：{poc_dir}")

    # 5) 报告目录
    try:
        os.makedirs(report_dir, exist_ok=True)
        add("ok", "报告目录", report_dir if os.access(report_dir, os.W_OK) else
            f"{report_dir}（不可写）")
    except OSError as exc:
        add("fail", "报告目录", f"{report_dir}：{exc}")

    # 6) 离网守卫 / 零依赖守卫
    for name, label in (("check_offline.py", "离网守卫"), ("check_zero_deps.py", "零依赖守卫")):
        path = os.path.join(pkg_root, "tools", name)
        if not os.path.isfile(path):
            add("warn", label, f"缺少 {path}")
            continue
        try:
            cp = subprocess.run([sys.executable, path], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=60, cwd=pkg_root)
            tail = [ln for ln in ((cp.stdout or "") + (cp.stderr or "")).splitlines() if ln.strip()]
            add("ok" if cp.returncode == 0 else "fail", label,
                (tail[-1].strip()[:120] if tail else f"exit {cp.returncode}"))
        except Exception as exc:                     # 超时/解释器异常都只降级不崩
            add("warn", label, f"跑不起来：{exc}")

    return checks


_LEVEL_MARK = {"ok": ("✓", "32"), "warn": ("⚠", "33"), "fail": ("✗", "31")}


def cmd_doctor(ctx: Any, args: argparse.Namespace) -> int:
    engine = sc.find_engine(getattr(args, "engine", "") or "")
    db_path = ctx.db
    checks = collect_checks(engine, db_path)

    print(_c("空境 Kara · 交付前自检（doctor）", "36"))
    print()
    bad = 0
    for item in checks:
        mark, color = _LEVEL_MARK.get(item["level"], ("·", "0"))
        if item["level"] == "fail":
            bad += 1
        print(f"  {_c(mark, color)} {_pad(item['label'], 10)} {item['detail']}")
    print()
    if bad:
        print(_c(f"结论：{bad} 项不合格，先修再交付。", "31"))
        return 1
    print(_c("结论：全部通过，可以交付。", "32"))
    return 0


# ---------------------------------------------------------------- poc

def parse_poc_meta(text: str) -> Dict[str, str]:
    """从 POC 文本里抽几个关键字段（不引 YAML 依赖，只认平铺 key: value）。

    支持两种写法：
        id: nacos-auth-bypass            # 顶层
        info:
          name: Nacos 默认口令            # 缩进一层
    """
    meta: Dict[str, str] = {}
    in_info = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip().lower()
        val = val.strip().strip("'\"")
        if indent == 0:
            in_info = key in ("info", "metadata")
            if in_info:
                continue
            if key in ("id", "name", "severity", "tags", "author", "description"):
                meta.setdefault(key, val)
        elif in_info and key in ("name", "severity", "tags", "author", "description"):
            if key == "tags" and val.startswith("["):
                val = val.strip("[]").replace("'", "").replace('"', "")
            meta.setdefault(key, val)
    return meta


def _poc_files(poc_dir: str = POC_DIR) -> List[str]:
    try:
        names = sorted(n for n in os.listdir(poc_dir) if n.endswith((".yaml", ".yml")))
    except OSError:
        return []
    return [os.path.join(poc_dir, n) for n in names]


def _poc_path(name: str, poc_dir: str = POC_DIR) -> str:
    cand = name if name.lower().endswith((".yaml", ".yml")) else name + ".yaml"
    path = cand if os.path.isabs(cand) else os.path.join(poc_dir, os.path.basename(cand))
    return path if os.path.isfile(path) else ""


def cmd_poc(ctx: Any, args: argparse.Namespace) -> int:
    if args.show:
        path = _poc_path(args.show)
        if not path:
            print(_c(f"[!] 找不到 POC：{args.show}（--list 看有哪些）", "31"), file=sys.stderr)
            return 2
        text = open(path, encoding="utf-8", errors="replace").read()
        meta = parse_poc_meta(text)
        print(_c(f"POC {os.path.basename(path)}", "36"))
        for key in ("id", "name", "severity", "tags", "author", "description"):
            if meta.get(key):
                print(f"  {_pad(key, 12)} {meta[key]}")
        print()
        print(text.rstrip())
        return 0

    if args.run:
        if not args.target:
            print(_c("[!] --run 需要 -t <目标>", "31"), file=sys.stderr)
            return 2
        if not args.yes:
            print(_c("[!] --run 会真发请求。确认授权后加 --yes 再跑。", "33"), file=sys.stderr)
            return 2
        engine = sc.find_engine(getattr(args, "engine", "") or "")
        if not engine:
            print(_c("[!] 找不到引擎", "31"), file=sys.stderr)
            return 2
        path = _poc_path(args.run)
        if not path:
            print(_c(f"[!] 找不到 POC：{args.run}", "31"), file=sys.stderr)
            return 2
        argv = [engine, "poc", "-t", args.target, "-p", path]
        print(_c("$ " + " ".join(argv), "36"))
        try:
            cp = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=max(10, args.timeout))
        except subprocess.TimeoutExpired:
            print(_c("[!] 超时", "31"), file=sys.stderr)
            return 2
        sys.stdout.write(cp.stdout or "")
        if cp.returncode != 0:
            sys.stderr.write(cp.stderr or "")
        return cp.returncode

    # 默认列出
    files = _poc_files()
    if not files:
        print("POC 目录为空（或不存在）。")
        return 0
    rows = []
    for path in files:
        meta = parse_poc_meta(open(path, encoding="utf-8", errors="replace").read())
        rows.append([os.path.basename(path), meta.get("id", ""), _cut(meta.get("name", ""), 34),
                     _sev_label(meta.get("severity", "")), _cut(meta.get("tags", ""), 24)])
    print(_c(f"POC 库：{len(files)} 个（{POC_DIR}）", "36"))
    print(_table(["文件", "ID", "名称", "等级", "标签"], rows, [30, 24, 34, 6, 24]))
    print()
    print("看细节：kara poc --show <文件>　打一发：kara poc --run <文件> -t <目标> --yes")
    return 0


# ---------------------------------------------------------------- replay

def replay_argv(engine: str, url: str, method: str = "GET", data: str = "",
                headers: Optional[List[str]] = None, no_redirect: bool = False,
                out_dir: str = "", timeout: int = 10) -> List[str]:
    """拼 `sweep replay` 的参数表（列表参数，绝不拼 shell）。"""
    argv = [engine, "replay", "-u", url, "-m", (method or "GET").upper(),
            "--timeout", str(max(1, int(timeout)))]
    if data:
        argv += ["--data", data]
    for head in headers or []:
        argv += ["--header", head]
    if no_redirect:
        argv.append("--no-redirect")
    if out_dir:
        argv += ["-o", out_dir]
    return argv


def _curl_of(url: str, method: str, data: str, headers: List[str]) -> str:
    parts = ["curl -i -sS"]
    if (method or "GET").upper() != "GET":
        parts.append(f"-X {(method or 'GET').upper()}")
    for head in headers:
        parts.append(f"-H '{head}'")
    if data:
        parts.append(f"--data '{data}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def cmd_replay(ctx: Any, args: argparse.Namespace) -> int:
    engine = sc.find_engine(getattr(args, "engine", "") or "")
    if not engine:
        print(_c("[!] 找不到引擎", "31"), file=sys.stderr)
        return 2
    out_dir = os.path.abspath(os.path.expanduser(args.out or os.path.join(
        REPORT_DIR, "replay-" + _now_tag())))
    os.makedirs(out_dir, exist_ok=True)
    argv = replay_argv(engine, args.url, args.method, args.data or "", args.header or [],
                       args.no_redirect, out_dir, args.timeout)
    print(_c("$ " + " ".join(argv), "36"))
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=max(10, args.timeout + 15))
    except subprocess.TimeoutExpired:
        print(_c("[!] 超时", "31"), file=sys.stderr)
        return 2
    sys.stdout.write(cp.stdout or "")
    if cp.returncode != 0 and cp.stderr:
        sys.stderr.write(cp.stderr)

    payload = ""
    for rel in ("replay.json", os.path.join(os.path.basename(url_path(args.url)), "replay.json")):
        cand = os.path.join(out_dir, rel)
        if os.path.isfile(cand):
            payload = cand
            break
    if payload:
        print()
        print(_c(f"产物 {payload}", "36"))
        try:
            data = json.load(open(payload, encoding="utf-8", errors="replace"))
        except Exception:
            data = None
        if isinstance(data, dict):
            err = data.get("error") or ""
            status = data.get("status") or 0
            size = data.get("size", data.get("len", ""))
            hdrs = data.get("headers") or {}
            ctype = ""
            if isinstance(hdrs, dict):
                for hk, hv in hdrs.items():
                    if str(hk).lower() == "content-type":
                        ctype = hv
                        break
            ms = data.get("ms", "")
            digest = data.get("digest", "")
            final = data.get("final_url") or ""
            if err:
                print(_c(f"  请求失败：{err}", "31"))
            else:
                print(f"  状态 {status}　长度 {size}　类型 {ctype or '-'}　耗时 {ms}ms")
            if final and final != args.url:
                print(f"  终点 {final}")
            if digest:
                print(f"  摘要 {digest}")
            if args.raw:
                print(json.dumps(data, ensure_ascii=False, indent=2)[:4000])
    print()
    print(_c("复现命令（直接粘报告）", "36"))
    print("  " + _curl_of(args.url, args.method, args.data or "", args.header or []))
    return cp.returncode


def url_path(url: str) -> str:
    """取 URL 的路径段（只用来找引擎产物子目录，不做语义解析）。"""
    rest = url.split("://", 1)[-1]
    idx = rest.find("/")
    return rest[idx:].strip("/") if idx >= 0 else ""


# ---------------------------------------------------------------- identifier

def cmd_identifier(ctx: Any, args: argparse.Namespace) -> int:
    """结构化标识符检测（身份证 / 银行卡 / 手机号 / 信用代码 / 车牌）。

    判定逻辑只写一份，在引擎的 identifier 包里。Python 侧再实现一遍 GB 11643 /
    Luhn / GB 32100，迟早会和引擎漂移，报告里就会出现「CLI 说有、引擎说没有」。
    这里只负责找到引擎、原样转发参数、把退出码带回来。
    """
    engine = sc.find_engine(getattr(args, "engine", "") or "")
    if not engine:
        print("[!] 找不到引擎 sweep：identifier 的校验位逻辑在 Go 内核里。", file=sys.stderr)
        print("    构建：cd engine-go && go build -o ../engine/sweep ./cmd/sweep", file=sys.stderr)
        return 2
    argv = [engine, "identifier", args.file]
    if args.json:
        argv.append("--json")
    if args.candidates:
        argv.append("--candidates")
    try:
        # 不捕获 stdout：表格/JSON 由引擎直接写到终端，管道里也能原样接走。
        return subprocess.run(argv).returncode
    except OSError as exc:
        print(f"[!] 引擎启动失败: {exc}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------- 注册

def add_subparsers(sub: Any) -> None:
    p = sub.add_parser("diff", help="对账：新增 / 持续 / 未再出现（复测第一段）")
    p.add_argument("--since", default="", metavar="TIME",
                   help="分界时间，如 2026-11-20 / '2026-11-20 09:30'（不给则全部算持续）")
    p.add_argument("--asset", default="", help="只看某个资产")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--limit", type=int, default=500, help="最多看多少条（默认 500）")
    p.add_argument("--show", type=int, default=20, help="每堆屏显多少行（默认 20）")
    p.add_argument("--csv", default="", help="导出 CSV")
    p.add_argument("--md", default="", help="导出 Markdown（直接贴复测报告）")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("doctor", help="交付前自检：引擎/子命令/库/POC/守卫")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("poc", help="POC 库：--list（默认）/ --show / --run（真发请求）")
    p.add_argument("--list", action="store_true", help="列出 POC（默认动作）")
    p.add_argument("--show", default="", metavar="NAME", help="看某个 POC 全文与元信息")
    p.add_argument("--run", default="", metavar="NAME", help="跑某个 POC（需 -t 与 --yes）")
    p.add_argument("-t", "--target", default="", help="--run 的目标（域名 / IP / URL）")
    p.add_argument("--yes", action="store_true", help="--run 的确认开关（会真发请求）")
    p.add_argument("--timeout", type=int, default=120, help="--run 超时秒数（默认 120）")
    p.set_defaults(func=cmd_poc)

    p = sub.add_parser("replay", help="单次精确请求 → 拿回复现 curl")
    p.add_argument("-u", "--url", required=True, help="完整 URL")
    p.add_argument("-m", "--method", default="GET", help="请求方法（默认 GET）")
    p.add_argument("-d", "--data", default="", help="请求体，如 'a=1&b=2'")
    p.add_argument("-H", "--header", action="append", default=[], help="请求头，可重复：-H 'K: V'")
    p.add_argument("--no-redirect", action="store_true", help="不跟随跳转")
    p.add_argument("--timeout", type=int, default=10, help="单次超时秒数（默认 10）")
    p.add_argument("-o", "--out", default="", help="产物目录（默认 ~/.kara/reports/replay-<时间>）")
    p.add_argument("--raw", action="store_true", help="打印 replay.json 全文（截断 4000 字）")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("identifier", help="结构化标识符：身份证/银行卡/手机号/信用代码（校验位通过才报）")
    p.add_argument("file", nargs="?", default="-", metavar="FILE",
                   help="待检文件；- 或省略则读 stdin")
    p.add_argument("--json", action="store_true", help="JSON 输出（供脚本/流水线消费）")
    p.add_argument("--candidates", action="store_true",
                   help="连未通过校验的候选一起列（默认不输出，precision 口径不变）")
    p.set_defaults(func=cmd_identifier)
