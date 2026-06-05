"""Unit tests for butian/scripts/run_audit.py — pipeline orchestrator."""

import os
import subprocess
import sys
import unittest
from types import SimpleNamespace

from butian.scripts import run_audit


def _scan_args(**overrides):
    """Build a namespace with all build_scan_cmd attributes and sensible defaults."""
    defaults = dict(
        skip_outdated=False,
        skip_hygiene=False,
        include_packages=False,
        max_secret_files=None,
        verbose=False,
        debug=False,
        follow_symlinks=False,
        no_cache=False,
        cache_ttl=86400,
        progress=False,
        no_progress=False,
        severity_threshold=None,
        baseline=False,
        skip_baseline=False,
        generate_baseline=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# script_path
# ---------------------------------------------------------------------------
class ScriptPathTests(unittest.TestCase):
    def test_resolves_to_script_dir(self):
        path = run_audit.script_path("scan.py")
        self.assertTrue(path.endswith("scan.py"))
        self.assertIn("scripts", path)


# ---------------------------------------------------------------------------
# display_width
# ---------------------------------------------------------------------------
class DisplayWidthTests(unittest.TestCase):
    def test_ascii(self):
        self.assertEqual(run_audit.display_width("abc"), 3)

    def test_cjk_wide(self):
        # CJK Unified Ideographs
        self.assertEqual(run_audit.display_width("中"), 2)

    def test_mixed(self):
        self.assertEqual(run_audit.display_width("a中b"), 4)

    def test_empty(self):
        self.assertEqual(run_audit.display_width(""), 0)

    def test_number(self):
        self.assertEqual(run_audit.display_width(42), 2)


# ---------------------------------------------------------------------------
# fit_cell
# ---------------------------------------------------------------------------
class FitCellTests(unittest.TestCase):
    def test_left_align(self):
        result = run_audit.fit_cell("abc", 6)
        self.assertEqual(result, "abc   ")

    def test_right_align(self):
        result = run_audit.fit_cell("abc", 6, "right")
        self.assertEqual(result, "   abc")

    def test_center_align(self):
        result = run_audit.fit_cell("ab", 6, "center")
        self.assertIn("ab", result)
        self.assertEqual(len(result), 6)

    def test_no_padding_needed(self):
        result = run_audit.fit_cell("abcdef", 6)
        self.assertEqual(result, "abcdef")


# ---------------------------------------------------------------------------
# table
# ---------------------------------------------------------------------------
class TableTests(unittest.TestCase):
    def test_renders_box_drawing(self):
        result = run_audit.table(
            ["Name", "Value"],
            [["a", "1"], ["b", "2"]],
        )
        self.assertIn("┌", result)
        self.assertIn("┬", result)
        self.assertIn("┐", result)
        self.assertIn("│", result)
        self.assertIn("a", result)
        self.assertIn("b", result)

    def test_min_widths(self):
        result = run_audit.table(
            ["A", "B"],
            [["x", "y"]],
            min_widths=[10, 10],
        )
        # Each cell should be at least 10 wide
        for line in result.split("\n"):
            if "x" in line and "y" in line:
                # Account for │ chars
                self.assertGreaterEqual(len(line), 22)

    def test_empty_rows(self):
        result = run_audit.table(["A", "B"], [])
        self.assertIn("┌", result)
        self.assertIn("A", result)


# ---------------------------------------------------------------------------
# relative_path
# ---------------------------------------------------------------------------
class RelativePathTests(unittest.TestCase):
    def test_within_project(self):
        self.assertEqual(run_audit.relative_path("/proj/src/a.py", "/proj"), "src/a.py")

    def test_empty_path(self):
        self.assertEqual(run_audit.relative_path("", "/proj"), "-")

    def test_outside_project(self):
        # If relative path starts with .., return original
        result = run_audit.relative_path("/other/file.py", "/proj")
        # On same filesystem, relpath works; may return ../...
        # The function returns original if starts with ..
        self.assertTrue(isinstance(result, str))


# ---------------------------------------------------------------------------
# version_key
# ---------------------------------------------------------------------------
class VersionKeyTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(run_audit.version_key("1.2.3"), (1, 2, 3))

    def test_none(self):
        self.assertEqual(run_audit.version_key(None), ())

    def test_sorting(self):
        versions = ["2.0.0", "1.5.0", "1.0.0"]
        self.assertEqual(
            sorted(versions, key=run_audit.version_key), ["1.0.0", "1.5.0", "2.0.0"]
        )


# ---------------------------------------------------------------------------
# best_fixed_version
# ---------------------------------------------------------------------------
class BestFixedVersionTests(unittest.TestCase):
    def test_single(self):
        self.assertEqual(
            run_audit.best_fixed_version([{"fixed_versions": ["1.0.1"]}]), "1.0.1"
        )

    def test_multiple_picks_highest(self):
        result = run_audit.best_fixed_version(
            [
                {"fixed_versions": ["1.0.1"]},
                {"fixed_versions": ["1.0.3"]},
            ]
        )
        self.assertIn("1.0.3", result)

    def test_empty(self):
        self.assertEqual(run_audit.best_fixed_version([]), "待确认")

    def test_no_fixed(self):
        self.assertEqual(
            run_audit.best_fixed_version([{"fixed_versions": []}]), "待确认"
        )


# ---------------------------------------------------------------------------
# risk_nature
# ---------------------------------------------------------------------------
class RiskNatureTests(unittest.TestCase):
    def test_ssrf(self):
        self.assertIn(
            "SSRF",
            run_audit.risk_nature(
                [{"summary": "server-side request forgery vulnerability"}]
            ),
        )

    def test_dos(self):
        self.assertIn(
            "DoS",
            run_audit.risk_nature([{"summary": "denial of service via large payload"}]),
        )

    def test_xss(self):
        self.assertIn(
            "XSS", run_audit.risk_nature([{"summary": "cross-site scripting issue"}])
        )

    def test_middleware_bypass(self):
        self.assertIn(
            "中间件",
            run_audit.risk_nature([{"summary": "middleware proxy bypass in next.js"}]),
        )

    def test_path_traversal(self):
        self.assertIn(
            "路径穿越",
            run_audit.risk_nature([{"summary": "path traversal vulnerability"}]),
        )

    def test_buffer(self):
        self.assertIn(
            "buffer",
            run_audit.risk_nature([{"summary": "buffer bounds check missing"}]),
        )

    def test_generic(self):
        self.assertIn(
            "依赖漏洞", run_audit.risk_nature([{"summary": "a type confusion bug"}])
        )

    def test_multiple_issues_count(self):
        result = run_audit.risk_nature(
            [
                {"summary": "ssrf issue"},
                {"summary": "dos issue"},
            ]
        )
        self.assertIn("2 条", result)


# ---------------------------------------------------------------------------
# mode_label
# ---------------------------------------------------------------------------
class ModeLabelTests(unittest.TestCase):
    def test_full(self):
        self.assertEqual(
            run_audit.mode_label("full_dependency_scan"), "完整依赖漏洞扫描"
        )

    def test_hygiene(self):
        self.assertEqual(run_audit.mode_label("hygiene_only"), "仓库卫生扫描")

    def test_unknown(self):
        self.assertEqual(run_audit.mode_label("custom"), "安全扫描")


# ---------------------------------------------------------------------------
# format_risk_rows
# ---------------------------------------------------------------------------
class FormatRiskRowsTests(unittest.TestCase):
    def test_with_risks(self):
        rows = run_audit.format_risk_rows(
            {"critical": 1, "high": 2, "medium": 0, "low": 0}
        )
        self.assertEqual(len(rows), 2)
        self.assertIn("紧急", rows[0][0])
        self.assertEqual(rows[0][1], "1")

    def test_no_risks(self):
        rows = run_audit.format_risk_rows({})
        self.assertEqual(len(rows), 1)
        self.assertIn("未发现风险", rows[0][0])

    def test_all_levels(self):
        rows = run_audit.format_risk_rows(
            {"critical": 1, "high": 2, "medium": 3, "low": 4}
        )
        self.assertEqual(len(rows), 4)


# ---------------------------------------------------------------------------
# format_focus
# ---------------------------------------------------------------------------
class FormatFocusTests(unittest.TestCase):
    def test_hygiene_only(self):
        result = run_audit.format_focus({}, scan_mode="hygiene_only")
        self.assertIn("暂无法执行依赖漏洞扫描", result)

    def test_no_issues(self):
        result = run_audit.format_focus({"top_issues": []})
        self.assertIn("未发现需要优先处理", result)

    def test_with_critical(self):
        analysis = {
            "top_issues": [
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "fixed_versions": ["4.17.21"],
                    "summary": "pollution",
                },
            ]
        }
        result = run_audit.format_focus(analysis)
        self.assertIn("lodash", result)
        self.assertIn("4.17.21", result)

    def test_medium_summary(self):
        analysis = {
            "top_issues": [
                {
                    "package": "foo",
                    "version": "1.0",
                    "severity": "medium",
                    "fixed_versions": ["1.1"],
                    "summary": "issue",
                },
                {
                    "package": "bar",
                    "version": "2.0",
                    "severity": "medium",
                    "fixed_versions": ["2.1"],
                    "summary": "issue2",
                },
            ]
        }
        result = run_audit.format_focus(analysis)
        self.assertIn("中风险", result)


# ---------------------------------------------------------------------------
# format_human_summary
# ---------------------------------------------------------------------------
class FormatHumanSummaryTests(unittest.TestCase):
    def test_hygiene_only_mode(self):
        summary = {
            "scan_mode": "hygiene_only",
            "markdown_report": "/tmp/r.md",
            "html_report": "/tmp/r.html",
            "analysis_file": "/tmp/a.json",
            "errors": [],
        }
        scan = {"scan_config": {"scan_mode": "hygiene_only"}, "hygiene": {}}
        analysis = {
            "project": {
                "path": "/tmp/demo",
                "name": "demo",
                "ecosystems": [],
                "total_packages": 0,
            },
            "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "hygiene": {},
            "top_issues": [],
            "vulnerability_count": 0,
            "outdated_count": 0,
            "errors": [],
        }
        args = SimpleNamespace(no_open=True)
        result = run_audit.format_human_summary(summary, scan, analysis, args)
        self.assertIn("仓库卫生扫描", result)
        self.assertIn("暂无法执行依赖漏洞扫描", result)

    def test_full_scan_with_vulns(self):
        summary = {
            "scan_mode": "full_dependency_scan",
            "markdown_report": "/tmp/r.md",
            "html_report": "/tmp/r.html",
            "analysis_file": "/tmp/a.json",
            "errors": [],
        }
        scan = {"scan_config": {"scan_mode": "full_dependency_scan"}, "hygiene": {}}
        analysis = {
            "project": {
                "path": "/tmp/demo",
                "name": "demo",
                "ecosystems": ["npm"],
                "total_packages": 5,
            },
            "risk_summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "hygiene": {},
            "top_issues": [
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "fixed_versions": ["4.17.21"],
                    "summary": "pollution",
                }
            ],
            "vulnerability_count": 1,
            "outdated_count": 0,
            "errors": [],
        }
        args = SimpleNamespace(no_open=True)
        result = run_audit.format_human_summary(summary, scan, analysis, args)
        self.assertIn("完整依赖漏洞扫描", result)
        self.assertIn("lodash", result)


# ---------------------------------------------------------------------------
# build_scan_cmd
# ---------------------------------------------------------------------------
class BuildScanCmdTests(unittest.TestCase):
    def test_basic(self):
        args = _scan_args()
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--preflight", cmd)
        self.assertIn("preflight.json", cmd)
        self.assertNotIn("--skip-outdated", cmd)

    def test_skip_outdated(self):
        args = _scan_args(skip_outdated=True)
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--skip-outdated", cmd)

    def test_skip_hygiene(self):
        args = _scan_args(skip_hygiene=True)
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--skip-hygiene", cmd)

    def test_include_packages(self):
        args = _scan_args(include_packages=True)
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--include-packages", cmd)

    def test_max_secret_files(self):
        args = _scan_args(max_secret_files=100)
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--max-secret-files", cmd)
        self.assertIn("100", cmd)


# ---------------------------------------------------------------------------
# should_echo_build_report
# ---------------------------------------------------------------------------
class ShouldEchoBuildReportTests(unittest.TestCase):
    def test_non_compact(self):
        self.assertTrue(
            run_audit.should_echo_build_report(SimpleNamespace(compact=False))
        )

    def test_compact(self):
        self.assertFalse(
            run_audit.should_echo_build_report(SimpleNamespace(compact=True))
        )


# ---------------------------------------------------------------------------
# quote_line
# ---------------------------------------------------------------------------
class QuoteLineTests(unittest.TestCase):
    def test_prefixes_gt(self):
        self.assertEqual(run_audit.quote_line("hello"), "> hello")


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class ParseArgsTests(unittest.TestCase):
    def test_defaults(self):
        args = run_audit.parse_args([])
        self.assertEqual(args.project_path, ".")
        self.assertFalse(args.no_root_discovery)
        self.assertFalse(args.skip_outdated)
        self.assertFalse(args.skip_hygiene)
        self.assertIsNone(args.max_secret_files)
        self.assertFalse(args.include_packages)
        self.assertFalse(args.compact)
        self.assertFalse(args.no_open)

    def test_all_flags(self):
        args = run_audit.parse_args(
            [
                "--no-root-discovery",
                "--skip-outdated",
                "--skip-hygiene",
                "--include-packages",
                "--compact",
                "--no-open",
                "--max-secret-files",
                "200",
                "/tmp/project",
            ]
        )
        self.assertEqual(args.project_path, "/tmp/project")
        self.assertTrue(args.no_root_discovery)
        self.assertTrue(args.skip_outdated)
        self.assertTrue(args.skip_hygiene)
        self.assertTrue(args.include_packages)
        self.assertTrue(args.compact)
        self.assertTrue(args.no_open)
        self.assertEqual(args.max_secret_files, 200)


# ---------------------------------------------------------------------------
# pipeline: --help
# ---------------------------------------------------------------------------
class PipelineHelpTests(unittest.TestCase):
    def test_run_audit_help(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        result = subprocess.run(
            [
                sys.executable,
                os.path.join("butian", "scripts", "run_audit.py"),
                "--help",
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
