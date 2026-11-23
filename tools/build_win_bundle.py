#!/usr/bin/env python3
"""把源码组装成 Windows 绿色版 zip（双击即跑，不需要装 Python）。

设计约束
--------
本脚本零出站：运行时绝不联网。官方 embeddable 运行时由调用方准备好后
用 --python-zip 传进来（CI 里 curl 取，本地手工取一次）。
这样 check_offline.py 不必为构建脚本开白名单例外。

为什么要改 ._pth（关键坑）
--------------------------
embeddable 版带的 python312._pth 内容只有两行有效路径：

    python312.zip
    .

而 ._pth 里的相对路径**以 python.exe 所在目录为基准**——也就是 python\，
不是解压根目录。更狠的是：._pth 一旦存在，Python 会进入 isolated 模式，
**完全忽略 PYTHONPATH 和 PYTHONHOME**，往环境变量里塞路径没有任何用。

不改的话，双击之后立刻 ModuleNotFoundError: No module named 'vc'。
所以必须往 ._pth 追加一行 ".."，把解压根纳入 sys.path。

编码
----
启动器和说明文件都用 GBK + CRLF 写入：cmd 默认码页 936，UTF-8 的 bat
在中文 Windows 上会显示成乱码；而 Python 侧同步用 PYTHONIOENCODING=gbk，
保证 print 里的中文在控制台读得懂。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 版本号唯一真源 = vc/__init__.py 的 __version__。这里不另写一份，
# 否则改版本要动两处、迟早漂移（__init__ 里升了、产物名还是旧的）。
sys.path.insert(0, str(ROOT))
from vc import __version__ as VERSION  # noqa: E402

BUNDLE = f"kara-{VERSION}-win64"

BAT = r"""@echo off
rem 控制台默认 GBK，中文会花屏；Python 侧已钉 UTF-8，这里把 cmd 也切过来
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem 控制台走 GBK，和代码里的中文输出对齐
set "PYTHONIOENCODING=gbk"
set "PYTHONDONTWRITEBYTECODE=1"

if not exist "python\python.exe" goto :nopython

rem 包内引擎：找到就显式指给后端，免得机器上另有一个旧 sweep 被优先选中
if exist "engine\sweep.exe" set "VC_RECON_BIN=%CD%\engine\sweep.exe"

echo.
echo   空境 Kara  v{ver}
echo   ---------------------------------------------
echo   本地漏扫 · 自带引擎 · 单一 CLI · 不联网
echo.
echo   这是命令行界面：在下面这行后面直接接参数即可，例如
echo     kara.bat scan -t https://example.com
echo     kara.bat list --sev high
echo   不带参数运行 = 打印状态。
echo.

"python\python.exe" -m vc.cli %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" goto :crashed
echo.
echo   [kara] 已停止。
timeout /t 3 >nul 2>&1
goto :eof

:crashed
echo.
echo   [异常退出] 退出码 %RC%
echo.
pause
goto :eof

:nopython
echo.
echo   [错误] 找不到 python\python.exe —— 这个包不完整。
echo   请确认整个压缩包完整解压后再双击本文件。
echo.
pause
"""

README = r"""空境 Kara v{ver} —— Windows 绿色版
================================================

小而精的本地漏扫。解压即用：不需要安装 Python，不需要 pip，不需要联网，
扫描引擎 engine\sweep.exe 已经在包里。

用法
----
1. 把整个压缩包解压到一个有写权限的目录
   （桌面、D 盘、U 盘都行；务必完整解压，别在压缩包里直接双击）

2. 双击 kara.bat

3. 浏览器自动打开 http://127.0.0.1:7788/
   没自动开就手动输入这个地址

4. 在「扫描」页一行一个填目标（IP / 域名 / URL），选模式，点「开始扫描」

5. 扫完的命中自动进「漏洞」页；要交报告就点右上角「导出 MD / CSV」

6. 用完关掉黑色窗口即停止

目录说明
--------
kara.bat              启动器，双击这个
START-HERE.txt          就是你正在读的这份说明
engine\sweep.exe        扫描引擎（全流程 / 端口 / 指纹 / API / JS / 路径 / 子域 / 基线）
python\                 内置 Python 3.12.8 运行时（约 25MB），不用管
vc\                     程序本体
tests\smoke_bundle.py   自检脚本，怀疑环境有问题时跑它
README.md               完整功能说明
CHANGELOG.md            版本更新记录

安全说明
--------
· 只监听 127.0.0.1，同网段其它机器访问不到
· 不发起任何外部网络请求，没有遥测、没有上报
· 数据全部存本机：%USERPROFILE%\.kara\vuln.db
· 收件箱默认扫 %USERPROFILE%\pentest-inbox 等目录

常见问题
--------
Q: 双击后窗口一闪就没
A: 八成是压缩包没解压完整，重新完整解压。

Q: 提示端口被占用
A: 已有实例在跑，直接用浏览器开 127.0.0.1:7788。

Q: 杀软提示风险
A: Python 官方绿色版运行时的固有误报，程序本身没有网络行为。

Q: 想换端口
A: kara.bat --port 7799

Q: 想确认包是好的
A: 在解压目录执行：
   python\python.exe tests\smoke_bundle.py
"""


def _force_utf8_stdout() -> None:
    """把 stdout/stderr 钉到 UTF-8。

    为什么必须做：Windows 控制台默认码页是 cp936，但 CI runner / 英文版
    Windows / 重定向到管道时是 cp1252 或 cp437，print 一个中文就
    UnicodeEncodeError 崩掉——而且崩在日志第一行，看起来像"程序根本没跑"。
    依赖外部设 PYTHONIOENCODING 不可靠（用户不会设），所以脚本自己钉。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def eprint(*a: object) -> None:
    print(*a)


def _check_pe(path: Path) -> str:
    """粗检 PE 头：Windows 可执行且是 amd64。返回问题描述，没问题返回空串。

    为什么查：绿色版没有引擎就只是个看结果的壳。构建脚本拿到错文件
    （arm64 版、Linux ELF、截断下载）时如果不吭声，交付出去的症状是
    「扫描页一直显示没找到引擎」，用户根本不知道该怪谁。
    """
    try:
        head = path.read_bytes()[:0x200]
    except OSError as exc:
        return f"读不到 {path.name}：{exc}"
    if len(head) < 0x40 or head[:2] != b"MZ":
        return f"{path.name} 不是 Windows PE（缺 MZ 头）"
    off = int.from_bytes(head[0x3C:0x40], "little")
    if off + 6 > len(head):
        return f"{path.name} PE 头越界"
    if head[off:off + 4] != b"PE\0\0":
        return f"{path.name} 缺 PE 签名"
    machine = int.from_bytes(head[off + 4:off + 6], "little")
    if machine != 0x8664:
        return f"{path.name} 不是 amd64（machine=0x{machine:04x}）"
    return ""


def assemble(python_zip: Path, build_dir: Path, engine_exe: Path) -> Path:
    if not python_zip.is_file():
        raise SystemExit(f"[X] 找不到运行时压缩包：{python_zip}")
    if not engine_exe.is_file():
        raise SystemExit(f"[X] 找不到扫描引擎：{engine_exe}（漏扫不带引擎等于空壳）")
    bad = _check_pe(engine_exe)
    if bad:
        raise SystemExit(f"[X] 引擎不可用：{bad}")

    with zipfile.ZipFile(python_zip) as z:
        names = z.namelist()
        for must in ("python.exe", "_sqlite3.pyd", "sqlite3.dll", "python312.dll"):
            if must not in names:
                raise SystemExit(f"[X] 运行时包里没有 {must}，这不是官方的 embeddable 包")

    stage = build_dir / BUNDLE
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    eprint(f"[1/7] 解压官方运行时 -> {stage.name}/python/")
    with zipfile.ZipFile(python_zip) as z:
        z.extractall(stage / "python")
    eprint(f"      {len(list((stage / 'python').iterdir()))} 个文件")

    eprint("[2/7] 修正 python312._pth（补 ..，否则 import vc 失败）")
    pth = stage / "python" / "python312._pth"
    if not pth.is_file():
        raise SystemExit("[X] 运行时包里没有 python312._pth，结构异常")
    body = pth.read_text(encoding="utf-8")
    if "\n..\n" not in body and not body.rstrip().endswith(".."):
        lines = [ln for ln in body.splitlines()]
        # 插在 "." 之后、注释之前
        out, done = [], False
        for ln in lines:
            out.append(ln)
            if ln.strip() == "." and not done:
                out.append("..")
                done = True
        if not done:
            out = ["python312.zip", ".", ".."] + out
        body = "\n".join(out)
    pth.write_bytes(body.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    eprint(f"      路径表: {[l for l in pth.read_text().splitlines() if l.strip() and not l.startswith('#')]}")

    eprint(f"[3/7] 拷入产品代码")
    shutil.copytree(ROOT / "vc", stage / "vc",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (stage / "tests").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "tests" / "smoke_bundle.py", stage / "tests" / "smoke_bundle.py")
    for f in ("LICENSE", "README.md", "CHANGELOG.md"):
        src = ROOT / f
        if src.is_file():
            shutil.copy2(src, stage / f)
    eprint(f"      vc/ 下 {len(list((stage / 'vc').glob('*.py')))} 个 .py")

    eprint("[4/7] 塞入扫描引擎（自带引擎才算漏扫，不然只是个看结果的壳）")
    eng_dir = stage / "engine"
    eng_dir.mkdir(exist_ok=True)
    shutil.copy2(engine_exe, eng_dir / "sweep.exe")
    eprint(f"      engine/sweep.exe  {engine_exe.stat().st_size:,} 字节")

    eprint("[5/7] 生成启动器（GBK + CRLF）")
    (stage / "kara.bat").write_bytes(
        BAT.replace("{ver}", VERSION).replace("\n", "\r\n").encode("gbk"))
    (stage / "START-HERE.txt").write_bytes(
        README.replace("{ver}", VERSION).replace("\n", "\r\n").encode("gbk"))
    eprint("      kara.bat / START-HERE.txt")

    eprint("[6/7] 打包")
    out_zip = build_dir / f"{BUNDLE}.zip"
    if out_zip.exists():
        out_zip.unlink()
    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, dirs, files in os.walk(stage):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fn in sorted(files):
                if fn.endswith(".pyc"):
                    continue
                fp = Path(root) / fn
                # 压缩包内套一层同名目录：用户解压时得到一个完整的 kara-x.y.z-win64/，
                # 而不是把一堆文件撒进他当前的下载文件夹。
                z.write(fp, Path(BUNDLE) / fp.relative_to(stage))
                count += 1

    eprint("[7/7] 自检（回读压缩包）")
    problems = []
    with zipfile.ZipFile(out_zip) as z:
        got = set(z.namelist())
        def _p(rel: str) -> str:
            return f"{BUNDLE}/{rel}"

        for must in ("kara.bat", "python/python.exe", "python/python312._pth",
                     "python/_sqlite3.pyd", "vc/cli.py", "vc/cli_extra.py", "vc/parsers_sweep.py", "vc/paths.py",
                     "tests/smoke_bundle.py", "START-HERE.txt", "engine/sweep.exe"):
            if _p(must) not in got:
                problems.append(f"缺 {must}")
        if _p("engine/sweep.exe") in got:
            eng_bytes = z.read(_p("engine/sweep.exe"))
            if not eng_bytes.startswith(b"MZ"):
                problems.append("engine/sweep.exe 不是 PE")
            # 7MB 的引擎被压成小几十 KB 基本意味着拷了个空壳/占位文件
            elif len(eng_bytes) < 4 * 1024 * 1024:
                problems.append(f"engine/sweep.exe 只有 {len(eng_bytes):,} 字节，太小")
        pth_txt = z.read(_p("python/python312._pth")).decode("utf-8")
        entries = [l.strip() for l in pth_txt.splitlines()
                   if l.strip() and not l.startswith("#")]
        if ".." not in entries:
            problems.append("._pth 里没有 ..（import vc 会失败）")
        bat = z.read(_p("kara.bat"))
        if bat.count(b"\r\n") == 0 or bat.count(b"\n") != bat.count(b"\r\n"):
            problems.append("kara.bat 换行不是纯 CRLF")
        try:
            bat.decode("gbk")
        except UnicodeDecodeError:
            problems.append("kara.bat 不是 GBK 可解码")
    if problems:
        for pb in problems:
            eprint(f"      [X] {pb}")
        raise SystemExit(1)
    eprint(f"      OK  {count} 个条目，全部必需文件就位")

    return out_zip


def _default_engine() -> Path | None:
    """找构建机上的 Windows 引擎：先看显式缓存目录，再看仓库 build/dist。

    引擎是 Go 交叉编译产物，不该进 git；放 build/ 下由 .gitignore 兜住，
    构建脚本只负责「有就用、没有就明确报错」。
    """
    for c in (os.environ.get("KARA_ENGINE", ""),
              ROOT / "build" / "sweep-win64.exe",
              ROOT / "dist" / "sweep-win64.exe"):
        if not c:
            continue
        p = Path(c).expanduser().resolve()
        if p.is_file():
            return p
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="组装 Windows 绿色版（零出站）")
    ap.add_argument("--python-zip", required=True,
                    help="官方 python-3.12.x-embed-amd64.zip 的本地路径")
    ap.add_argument("--engine", default="",
                    help="扫描引擎 sweep.exe（交叉编译产物）；不给就探 build/sweep-win64.exe")
    ap.add_argument("--out", default="dist", help="输出目录（默认 dist）")
    args = ap.parse_args()
    _force_utf8_stdout()

    py_zip = Path(args.python_zip).expanduser().resolve()
    engine = Path(args.engine).expanduser().resolve() if args.engine else _default_engine()
    if engine is None:
        raise SystemExit(
            "[X] 没找到 Windows 引擎。先交叉编译一次：\n"
            "  cd " + str(ROOT / "engine-go") + " && "
            "GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath "
            "-ldflags '-s -w' -o " + str(ROOT / "build" / "sweep-win64.exe") + " ./cmd/sweep")
    out_dir = (ROOT / args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    eprint(f"空境 Kara v{VERSION} · Windows 绿色版构建")
    eprint(f"运行时 : {py_zip}")
    eprint(f"引擎   : {engine}")
    eprint(f"输出   : {out_dir}")
    eprint("-" * 58)

    z = assemble(py_zip, out_dir, engine)
    size = z.stat().st_size

    eprint("-" * 58)
    eprint(f"完成: {z}")
    eprint(f"      {size:,} 字节 ({size / 1048576:.1f} MB)")
    eprint("")
    eprint("下一步（必须在真 Windows 上做，结构对不等于能跑）：")
    eprint(f"      解压 {z.name} 后执行 python\\python.exe tests\\smoke_bundle.py")
    eprint("      再双击 kara.bat，确认「扫描」页底部显示 engine\\sweep.exe 已就绪")
    return 0


if __name__ == "__main__":
    sys.exit(main())
