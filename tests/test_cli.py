"""单一 CLI 的单测：状态页、目标归一化补丁、显示宽度、协议判定、scan/list/verify 三条命令。

不联网：HTTP 判定用 stdlib 起一个回环 server 当靶子；扫描链路用 tests.test_scans
里那段假引擎（会写 nuclei 形状产物），验证「跑引擎 → 入账 → 列表」真的走通。
"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import cli                       # noqa: E402
from vc.scans import normalize_targets   # noqa: E402
from vc.store import Store               # noqa: E402

from tests.test_scans import make_engine  # noqa: E402


def run(*argv):
    """跑一次 CLI，返回 (退出码, stdout, stderr)。"""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCommandSurface(unittest.TestCase):
    """命令表：三个主命令 + 四个补充命令 —— 别把这层堆成子命令树。"""

    def test_command_surface(self):
        ap = cli.build_parser()
        sub = [a for a in ap._actions if a.__class__.__name__ == "_SubParsersAction"][0]
        self.assertIsNotNone(sub.choices)
        self.assertEqual(sorted(sub.choices),
                         ["diff", "doctor", "list", "poc", "replay", "scan", "verify"])

    def test_three_core_verbs_present(self):
        ap = cli.build_parser()
        sub = [a for a in ap._actions if a.__class__.__name__ == "_SubParsersAction"][0]
        self.assertIsNotNone(sub.choices)
        for verb in ("scan", "list", "verify"):
            self.assertIn(verb, sub.choices)

    def test_bare_runs_status(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = run("--db", os.path.join(d, "v.db"))
            self.assertEqual(code, 0)
            self.assertIn("空境", out)
            self.assertIn("kara scan", out)


class TestTargetPatch(unittest.TestCase):
    """浏览器复制的 URL 带尾斜杠 —— 以前直接被拒收，现在按合法目标处理。"""

    def test_trailing_slash_accepted(self):
        self.assertEqual(normalize_targets("fingerprint", ["http://a.com/x/"]), ["http://a.com/x"])
        self.assertEqual(normalize_targets("fingerprint", ["a.com/"]), ["https://a.com"])

    def test_bare_host_unchanged(self):
        self.assertEqual(normalize_targets("fingerprint", ["a.com"]), ["https://a.com"])

    def test_root_slash_kept_sane(self):
        self.assertEqual(normalize_targets("api", ["http://a.com/"]), ["http://a.com"])

    def test_any_kind_keeps_scheme(self):
        """深度验证两种写法都吃：带协议原样，裸 host:port 也原样。"""
        self.assertEqual(normalize_targets("strike", ["http://a.com:8080/x/"]), ["http://a.com:8080/x"])
        self.assertEqual(normalize_targets("strike", ["10.0.0.5:8080"]), ["10.0.0.5:8080"])

    def test_still_rejects_dangerous(self):
        for bad in ["a.com; id", "http://a.com/../x", "-rf"]:
            with self.assertRaises(Exception):
                normalize_targets("fingerprint", [bad])


class TestDisplay(unittest.TestCase):
    def test_cjk_width(self):
        self.assertEqual(cli._w("中文"), 4)
        self.assertEqual(cli._w("ab"), 2)
        for budget in (3, 5, 7, 9):
            self.assertLessEqual(cli._w(cli._cut("敏感路径可访问：/.git/config", budget)), budget)
        self.assertTrue(cli._cut("abcdef", 4).endswith("…"))

    def test_pad(self):
        self.assertEqual(cli._w(cli._pad("中文", 10)), 10)
        self.assertEqual(cli._w(cli._pad("ab", 6)), 6)

    def test_ports_text(self):
        ports = [{"port": 80, "service": "http"}, {"port": 443, "service": ""}, 8080]
        self.assertEqual(cli._ports_text(ports), "80(http),443,8080")
        self.assertEqual(cli._ports_text([]), "-")
        many = [{"port": i} for i in range(1, 13)]
        self.assertTrue(cli._ports_text(many, cap=3).endswith("…+9"))

    def test_level_of(self):
        self.assertEqual(cli._level_of({"evidence": "HTTP 200 · [L2/confirmed]"}), "L2/confirmed")
        self.assertEqual(cli._level_of({"evidence": "HTTP 200"}), "-")


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):                      # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):             # 静音
        pass


class TestProbeScheme(unittest.TestCase):
    def test_http_server_detected(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.assertEqual(cli.probe_scheme(f"127.0.0.1:{srv.server_address[1]}"), "http")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_dead_port_falls_back_to_https(self):
        self.assertEqual(cli.probe_scheme("127.0.0.1:9"), "https")


class TestScanList(unittest.TestCase):
    def test_scan_then_list(self):
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            db, inbox = os.path.join(d, "v.db"), os.path.join(d, "inbox")
            base = ["--db", db, "--inbox", inbox, "--engine", engine, "--timeout", "60"]

            code, out, _ = run(*base, "scan", "-t", "example.com", "-m", "api", "--scheme", "https")
            self.assertEqual(code, 0, out)
            store = Store(db)
            rows = store.findings(limit=50)["rows"]
            self.assertEqual(len(rows), 1, out)
            self.assertEqual(rows[0]["sev"], "high")
            self.assertIn("XSS", rows[0]["title"])

            # list：列表
            code, out, _ = run("--db", db, "list")
            self.assertEqual(code, 0)
            self.assertIn("XSS", out)

            # list -i：详情，带复现命令
            code, out, _ = run("--db", db, "list", "-i", str(rows[0]["id"]))
            self.assertEqual(code, 0)
            self.assertIn("端点", out)
            self.assertIn("XSS", out)

    def test_bad_target_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            code, _, err = run("--db", os.path.join(d, "v.db"),
                               "--inbox", os.path.join(d, "inbox"), "--engine", engine,
                               "scan", "-t", "a.com; id", "-m", "api")
            self.assertEqual(code, 2)
            self.assertIn("不合法", err)

    def test_export_csv_with_bom(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "v.db")
            Store(db).add_findings([{
                "asset": "a.com", "title": "测试命中", "sev": "high", "endpoint": "http://a.com/x",
                "param": "q", "port": "", "ip": "", "cve": "", "evidence": "200 · 12B",
                "repro": "curl -i http://a.com/x", "sources": "sweep-paths",
            }], "t.json")
            out = os.path.join(d, "r.csv")
            code, _, _ = run("--db", db, "list", "--csv", out)
            self.assertEqual(code, 0)
            with open(out, "rb") as fh:
                raw = fh.read()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "CSV 必须带 BOM，Excel 才不乱码")
            self.assertIn("测试命中", raw.decode("utf-8-sig"))

    def test_list_assets(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "v.db")
            store = Store(db)
            store.add_findings([{
                "asset": "a.com", "title": "命中", "sev": "high", "endpoint": "http://a.com/x",
                "port": 443, "ip": "1.2.3.4", "source": "sweep-paths", "evidence": "200", "repro": "",
            }], "t.json")
            code, out, _ = run("--db", db, "list", "--assets")
            self.assertEqual(code, 0)
            self.assertIn("a.com", out)

    def test_verify_deep_dry_run(self):
        """--deep --dry-run 只列目标，不调引擎、不发请求。"""
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "v.db")
            Store(db).add_findings([{
                "asset": "a.com", "title": "命中", "sev": "high",
                "endpoint": "http://a.com:8080/x", "port": 8080, "ip": "1.2.3.4",
                "source": "sweep-paths", "evidence": "200", "repro": "",
            }], "t.json")
            code, out, _ = run("--db", db, "verify", "--deep", "--dry-run")
            self.assertEqual(code, 0, out)
            self.assertIn("http://a.com:8080", out)
            self.assertIn("dry-run", out.lower())

    def test_ascii_console_does_not_crash(self):
        """GBK/ASCII 控制台上不许崩 —— Windows 双击 bat 一闪而过就是这个原因。"""
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, PYTHONIOENCODING="ascii", PYTHONUTF8="0")
            env.pop("PYTHONPATH", None)
            p = subprocess.run([sys.executable, "-m", "vc.cli", "--db", os.path.join(d, "v.db")],
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = (p.stdout or b"").decode("utf-8", "replace")
            self.assertEqual(p.returncode, 0, out)
            self.assertNotIn("UnicodeEncodeError", out)
            self.assertIn("Kara", out)

    def test_verify_without_targets(self):
        """白盒报告类条目没有可回访目标 —— 要说清楚，而不是装作跑过了。"""
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "v.db")
            Store(db).add_findings([{
                "asset": "-", "title": "白盒发现", "sev": "critical", "endpoint": "",
                "port": "", "ip": "", "source": "md", "evidence": "代码审计", "repro": "",
            }], "t.json")
            code, out, _ = run("--db", db, "verify", "--deep")
            self.assertEqual(code, 0)
            self.assertIn("没有可回访的目标", out)


if __name__ == "__main__":
    unittest.main()
