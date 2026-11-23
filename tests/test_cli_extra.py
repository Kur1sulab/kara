"""cli_extra（diff / doctor / poc / replay）的单测。

不联网：replay 只验参数拼装（真发请求的链路由 verify 的既有测试覆盖），
doctor 的守卫检查用真实仓库脚本跑一次（它本身只扫文件、不建连）。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import cli                       # noqa: E402
from vc import cli_extra as ex           # noqa: E402


def _row(rid, sev="high", first="2026-11-01 10:00:00", last="2026-11-20 10:00:00",
         asset="10.0.0.5", title="t", endpoint="/x"):
    return {"id": rid, "sev": sev, "asset": asset, "ip": asset, "title": title,
            "endpoint": endpoint, "first_seen": first, "last_seen": last,
            "port": 80, "status": "待验证"}


class TestDiff(unittest.TestCase):
    def test_norm_since_shapes(self):
        self.assertEqual(ex._norm_since("2026-11-20"), "2026-11-20 00:00:00")
        self.assertEqual(ex._norm_since("2026-11/20"), "2026-11-20 00:00:00")
        self.assertEqual(ex._norm_since("2026-11-20 09:30"), "2026-11-20 09:30:00")
        self.assertEqual(ex._norm_since("2026-11-20T09:30:00"), "2026-11-20 09:30:00")
        self.assertEqual(ex._norm_since(""), "")

    def test_classify_three_buckets(self):
        rows = [
            _row(1, first="2026-11-21 00:00:00", last="2026-11-21 00:00:00"),   # 新增
            _row(2, first="2026-11-01 00:00:00", last="2026-11-22 00:00:00"),   # 持续
            _row(3, first="2026-11-01 00:00:00", last="2026-11-02 00:00:00"),   # 未再出现
        ]
        out = ex._classify(rows, "2026-11-20 00:00:00")
        self.assertEqual([r["id"] for r in out["new"]], [1])
        self.assertEqual([r["id"] for r in out["ongoing"]], [2])
        self.assertEqual([r["id"] for r in out["gone"]], [3])

    def test_classify_without_since_all_ongoing(self):
        rows = [_row(1), _row(2)]
        out = ex._classify(rows, "")
        self.assertEqual(len(out["ongoing"]), 2)
        self.assertEqual(out["new"], [])

    def test_classify_missing_timestamps_count_as_ongoing(self):
        rows = [_row(9, first="", last="")]
        out = ex._classify(rows, "2026-11-20 00:00:00")
        self.assertEqual([r["id"] for r in out["ongoing"]], [9])

    def test_export_md_csv(self):
        buckets = {"new": [_row(1)], "ongoing": [_row(2)], "gone": [_row(3)]}
        with tempfile.TemporaryDirectory() as tmp:
            md = os.path.join(tmp, "d.md")
            csv_path = os.path.join(tmp, "d.csv")
            ex._write_diff_md(md, buckets, "2026-11-20 00:00:00", "10.0.0.5")
            ex._write_diff_csv(csv_path, buckets)
            text = open(md, encoding="utf-8").read()
            self.assertIn("新增 1 / 持续 1 / 未再出现 1", text)
            self.assertIn("未再出现 ≠ 已修复", text)
            rows = open(csv_path, encoding="utf-8").read().splitlines()
            self.assertEqual(len(rows), 4)          # 表头 + 3 条
            self.assertTrue(rows[0].startswith("bucket,id,sev"))


class TestPoc(unittest.TestCase):
    SAMPLE = """id: demo-poc
info:
  name: 示例 POC
  severity: high
  tags: [nacos, auth]
  author: kuri
http:
  - method: GET
    path: /nacos/
"""

    def test_parse_poc_meta(self):
        meta = ex.parse_poc_meta(self.SAMPLE)
        self.assertEqual(meta["id"], "demo-poc")
        self.assertEqual(meta["name"], "示例 POC")
        self.assertEqual(meta["severity"], "high")
        self.assertEqual(meta["tags"], "nacos, auth")

    def test_poc_files_and_path(self):
        files = ex._poc_files()
        self.assertTrue(files, "pocs/ 目录应有 POC")
        self.assertTrue(all(f.endswith((".yaml", ".yml")) for f in files))
        name = os.path.basename(files[0])
        self.assertTrue(ex._poc_path(name))
        self.assertTrue(ex._poc_path(name[:-5]))        # 不带后缀也能找到
        self.assertEqual(ex._poc_path("no-such-poc"), "")

    def test_poc_run_requires_yes(self):
        args = cli.build_parser().parse_args(["poc", "--run", "nacos-auth-bypass", "-t", "10.0.0.1"])
        ctx = type("C", (), {})()
        self.assertEqual(ex.cmd_poc(ctx, args), 2)      # 没 --yes 直接拒

    def test_poc_run_requires_target(self):
        args = cli.build_parser().parse_args(["poc", "--run", "nacos-auth-bypass", "--yes"])
        ctx = type("C", (), {})()
        self.assertEqual(ex.cmd_poc(ctx, args), 2)


class TestReplay(unittest.TestCase):
    def test_replay_argv(self):
        argv = ex.replay_argv("/e/sweep", "http://h/x?a=1", "post", "a=1",
                              ["K: V", "A: B"], True, "/tmp/o", 7)
        self.assertEqual(argv[:5], ["/e/sweep", "replay", "-u", "http://h/x?a=1", "-m"])
        self.assertIn("POST", argv)
        self.assertEqual(argv[argv.index("--timeout") + 1], "7")
        self.assertEqual(argv[argv.index("--data") + 1], "a=1")
        self.assertEqual(argv.count("--header"), 2)
        self.assertIn("--no-redirect", argv)
        self.assertEqual(argv[argv.index("-o") + 1], "/tmp/o")

    def test_replay_argv_minimal(self):
        argv = ex.replay_argv("/e/sweep", "http://h/")
        self.assertNotIn("--data", argv)
        self.assertNotIn("--header", argv)
        self.assertNotIn("-o", argv)

    def test_curl_of(self):
        line = ex._curl_of("http://h/x", "POST", "a=1", ["K: V"])
        self.assertIn("-X POST", line)
        self.assertIn("-H 'K: V'", line)
        self.assertIn("--data 'a=1'", line)
        self.assertTrue(line.rstrip().endswith("'http://h/x'"))


class TestDoctor(unittest.TestCase):
    def test_missing_engine_is_fail(self):
        checks = ex.collect_checks("", os.path.expanduser("~/.kara/vuln.db"))
        levels = {c["label"]: c["level"] for c in checks}
        self.assertEqual(levels["引擎"], "fail")

    def test_all_checks_have_shape(self):
        checks = ex.collect_checks("/nonexistent/sweep", "/tmp/none.db")
        self.assertGreaterEqual(len(checks), 6)
        for item in checks:
            self.assertIn(item["level"], ("ok", "warn", "fail"))
            self.assertTrue(item["label"])
            self.assertIsInstance(item["detail"], str)

    def test_doctor_exit_code(self):
        args = cli.build_parser().parse_args(["--engine", "/nonexistent/sweep", "doctor"])
        ctx = type("C", (), {"db": "/tmp/none.db"})()
        self.assertEqual(ex.cmd_doctor(ctx, args), 1)


class TestRegistration(unittest.TestCase):
    def test_new_subcommands_registered(self):
        ap = cli.build_parser()
        for cmd in ("diff", "doctor", "poc", "replay"):
            args = ap.parse_args([cmd, "-h"]) if False else ap.parse_args(
                {"diff": ["diff"], "doctor": ["doctor"], "poc": ["poc"],
                 "replay": ["replay", "-u", "http://h/"]}[cmd])
            self.assertTrue(callable(getattr(args, "func", None)), cmd)

    def test_status_still_default(self):
        args = cli.build_parser().parse_args([])
        self.assertTrue(callable(getattr(args, "func", None)))


if __name__ == "__main__":
    unittest.main()
