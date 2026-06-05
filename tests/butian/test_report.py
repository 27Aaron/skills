"""Unit tests for butian/scripts/report.py — Markdown report rendering."""

import os
import subprocess
import sys
import tempfile
import unittest

from butian.scripts import report


# ---------------------------------------------------------------------------
# text / cell
# ---------------------------------------------------------------------------
class TextTests(unittest.TestCase):
    def test_none_to_empty(self):
        self.assertEqual(report.text(None), "")

    def test_strips(self):
        self.assertEqual(report.text("  hello  "), "hello")

    def test_preserves_inner(self):
        self.assertEqual(report.text("a b c"), "a b c")


class CellTests(unittest.TestCase):
    def test_pipe_escaped(self):
        self.assertEqual(report.cell("a|b"), "a\\|b")

    def test_newline_replaced(self):
        self.assertEqual(report.cell("a\nb"), "a b")

    def test_none_to_empty(self):
        self.assertEqual(report.cell(None), "")


# ---------------------------------------------------------------------------
# to_list
# ---------------------------------------------------------------------------
class ToListTests(unittest.TestCase):
    def test_none(self):
        self.assertEqual(report.to_list(None), [])

    def test_empty_list(self):
        self.assertEqual(report.to_list([]), [])

    def test_list_with_falsy(self):
        self.assertEqual(report.to_list(["a", "", None, "b"]), ["a", "b"])

    def test_single_string(self):
        self.assertEqual(report.to_list("hello"), ["hello"])

    def test_single_int(self):
        self.assertEqual(report.to_list(42), [42])


# ---------------------------------------------------------------------------
# clean_version
# ---------------------------------------------------------------------------
class CleanVersionTests(unittest.TestCase):
    def test_strips_v(self):
        self.assertEqual(report.clean_version("v1.2.3"), "1.2.3")

    def test_no_v(self):
        self.assertEqual(report.clean_version("1.2.3"), "1.2.3")

    def test_none(self):
        self.assertEqual(report.clean_version(None), "")


# ---------------------------------------------------------------------------
# outdated_update_target / is_outdated_item
# ---------------------------------------------------------------------------
class OutdatedUpdateTargetTests(unittest.TestCase):
    def test_wanted_first(self):
        self.assertEqual(
            report.outdated_update_target({"wanted": "1.1", "latest": "2.0"}), "1.1"
        )

    def test_update_second(self):
        self.assertEqual(
            report.outdated_update_target({"update": "1.1", "latest": "2.0"}), "1.1"
        )

    def test_latest_fallback(self):
        self.assertEqual(report.outdated_update_target({"latest": "2.0"}), "2.0")

    def test_empty(self):
        self.assertEqual(report.outdated_update_target({}), None)


class IsOutdatedItemTests(unittest.TestCase):
    def test_outdated(self):
        self.assertTrue(report.is_outdated_item({"current": "1.0", "wanted": "1.1"}))

    def test_current(self):
        self.assertFalse(report.is_outdated_item({"current": "1.0", "wanted": "1.0"}))

    def test_v_prefix(self):
        self.assertTrue(report.is_outdated_item({"current": "v1.0", "latest": "v2.0"}))

    def test_no_target(self):
        self.assertFalse(
            report.is_outdated_item({"current": "1.0", "wanted": "", "latest": ""})
        )


# ---------------------------------------------------------------------------
# date_from_analysis
# ---------------------------------------------------------------------------
class DateFromAnalysisTests(unittest.TestCase):
    def test_extracts_date(self):
        self.assertEqual(
            report.date_from_analysis({"generated_at": "2026-06-05 09:05:50"}),
            "2026-06-05",
        )

    def test_missing(self):
        self.assertEqual(report.date_from_analysis({}), "unknown-date")


# ---------------------------------------------------------------------------
# severity_label
# ---------------------------------------------------------------------------
class SeverityLabelTests(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(report.severity_label("critical"), "紧急")

    def test_high(self):
        self.assertEqual(report.severity_label("high"), "高风险")

    def test_medium(self):
        self.assertEqual(report.severity_label("medium"), "中风险")

    def test_low(self):
        self.assertEqual(report.severity_label("low"), "低风险")

    def test_info(self):
        self.assertEqual(report.severity_label("info"), "待确认")

    def test_unknown(self):
        self.assertEqual(report.severity_label("unknown"), "待确认")

    def test_none(self):
        self.assertEqual(report.severity_label(None), "待确认")

    def test_case_insensitive(self):
        self.assertEqual(report.severity_label("HIGH"), "高风险")


# ---------------------------------------------------------------------------
# is_hygiene_only
# ---------------------------------------------------------------------------
class IsHygieneOnlyTests(unittest.TestCase):
    def test_hygiene_mode(self):
        self.assertTrue(
            report.is_hygiene_only({"scan_config": {"scan_mode": "hygiene_only"}})
        )

    def test_full_scan(self):
        self.assertFalse(
            report.is_hygiene_only(
                {"scan_config": {"scan_mode": "full_dependency_scan"}}
            )
        )

    def test_missing_config(self):
        self.assertFalse(report.is_hygiene_only({}))


# ---------------------------------------------------------------------------
# security_ids
# ---------------------------------------------------------------------------
class SecurityIdsTests(unittest.TestCase):
    def test_advisory_id(self):
        self.assertEqual(
            report.security_ids({"advisory_id": "GHSA-aaaa-bbbb-cccc"}),
            ["GHSA-aaaa-bbbb-cccc"],
        )

    def test_aliases_list(self):
        self.assertEqual(
            report.security_ids({"aliases": ["GHSA-xxxx-xxxx-xxxx", "CVE-2024-0001"]}),
            ["GHSA-xxxx-xxxx-xxxx"],
        )

    def test_comma_separated(self):
        self.assertEqual(
            report.security_ids(
                {"advisory_ids": "GHSA-aaaa-bbbb-cccc, GHSA-dddd-eeee-ffff"}
            ),
            ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"],
        )

    def test_deduplicates(self):
        ids = report.security_ids(
            {
                "advisory_id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
            }
        )
        self.assertEqual(ids, ["GHSA-aaaa-bbbb-cccc"])

    def test_no_ids(self):
        self.assertEqual(report.security_ids({}), [])


# ---------------------------------------------------------------------------
# render_summary
# ---------------------------------------------------------------------------
class RenderSummaryTests(unittest.TestCase):
    def test_full_summary(self):
        analysis = {
            "summary": {
                "tldr": "发现高风险漏洞",
                "detail": "详细信息",
                "priority": ["优先处理紧急项"],
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_summary(analysis)
        self.assertIn("发现高风险漏洞", result)
        self.assertIn("详细信息", result)
        self.assertIn("优先处理紧急项", result)
        self.assertIn("能力边界", result)

    def test_hygiene_only(self):
        analysis = {
            "summary": {"tldr": "卫生扫描"},
            "scan_config": {"scan_mode": "hygiene_only"},
        }
        result = report.render_summary(analysis)
        self.assertIn("暂无法执行依赖漏洞扫描", result)

    def test_missing_summary(self):
        result = report.render_summary({})
        self.assertIn("没有生成摘要", result)


# ---------------------------------------------------------------------------
# render_vulnerabilities
# ---------------------------------------------------------------------------
class RenderVulnerabilitiesTests(unittest.TestCase):
    def test_with_issues(self):
        analysis = {
            "top_issues": [
                {
                    "severity": "high",
                    "package": "lodash",
                    "version": "4.17.20",
                    "fixed_versions": ["4.17.21"],
                    "summary": "Prototype pollution",
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                }
            ],
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_vulnerabilities(analysis)
        self.assertIn("lodash", result)
        self.assertIn("4.17.21", result)
        self.assertIn("高风险", result)
        self.assertIn("GHSA-aaaa-bbbb-cccc", result)

    def test_no_issues_full_scan(self):
        result = report.render_vulnerabilities(
            {"scan_config": {"scan_mode": "full_dependency_scan"}}
        )
        self.assertIn("未命中", result)

    def test_no_issues_hygiene_only(self):
        result = report.render_vulnerabilities(
            {"scan_config": {"scan_mode": "hygiene_only"}}
        )
        self.assertIn("暂无法执行依赖漏洞扫描", result)


# ---------------------------------------------------------------------------
# render_hygiene
# ---------------------------------------------------------------------------
class RenderHygieneTests(unittest.TestCase):
    def test_all_clean(self):
        result = report.render_hygiene({"hygiene": {}})
        self.assertIn("没有发现硬编码密钥", result)

    def test_with_secrets(self):
        analysis = {
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": "src/config.ts",
                        "line": 12,
                        "type": "generic_api_key",
                        "confidence": "high",
                        "preview": "api_key=***",
                    }
                ],
            }
        }
        result = report.render_hygiene(analysis)
        self.assertIn("src/config.ts:12", result)
        self.assertIn("api_key", result)

    def test_with_sensitive_tracked(self):
        analysis = {
            "hygiene": {
                "sensitive_tracked": [
                    {"file": ".env", "type": "env_file", "size": 128},
                ],
            }
        }
        result = report.render_hygiene(analysis)
        self.assertIn(".env", result)
        self.assertIn("env_file", result)

    def test_with_gitignore_missing(self):
        analysis = {
            "hygiene": {"gitignore_missing": [".env", "*.pem"]},
        }
        result = report.render_hygiene(analysis)
        self.assertIn(".env", result)
        self.assertIn("*.pem", result)

    def test_with_gitignore_state(self):
        analysis = {
            "hygiene": {},
            "butian_workspace": {
                "gitignore": {"preexisting": True, "added_butian_entry": True},
            },
        }
        result = report.render_hygiene(analysis)
        self.assertIn("是", result)


# ---------------------------------------------------------------------------
# render_outdated
# ---------------------------------------------------------------------------
class RenderOutdatedTests(unittest.TestCase):
    def test_with_outdated(self):
        analysis = {
            "outdated": [
                {
                    "package": "react",
                    "current": "18.2.0",
                    "latest": "19.1.0",
                    "ecosystem": "npm",
                },
            ],
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_outdated(analysis)
        self.assertIn("react", result)
        self.assertIn("18.2.0", result)
        self.assertIn("19.1.0", result)

    def test_no_outdated(self):
        result = report.render_outdated(
            {"scan_config": {"scan_mode": "full_dependency_scan"}}
        )
        self.assertIn("没有检测到", result)

    def test_hygiene_only(self):
        result = report.render_outdated({"scan_config": {"scan_mode": "hygiene_only"}})
        self.assertIn("暂无法执行", result)


# ---------------------------------------------------------------------------
# render_manual_items
# ---------------------------------------------------------------------------
class RenderManualItemsTests(unittest.TestCase):
    def test_with_items(self):
        analysis = {
            "red": [
                {
                    "name": "密钥已入 git 历史",
                    "severity": "critical",
                    "path": ".env.production",
                    "why_keep": "需确认",
                    "risk": "凭证泄露",
                    "indirect_release": "轮换后清理",
                }
            ],
            "yellow": [],
        }
        result = report.render_manual_items(analysis)
        self.assertIn("密钥已入 git 历史", result)
        self.assertIn("紧急", result)
        self.assertIn("需确认", result)

    def test_empty(self):
        result = report.render_manual_items({"red": [], "yellow": []})
        self.assertIn("没有需要额外人工确认", result)


# ---------------------------------------------------------------------------
# render_errors
# ---------------------------------------------------------------------------
class RenderErrorsTests(unittest.TestCase):
    def test_with_errors(self):
        analysis = {
            "errors": [{"step": "vulnerability_check", "message": "NVD timeout"}]
        }
        result = report.render_errors(analysis)
        self.assertIn("vulnerability_check", result)
        self.assertIn("NVD timeout", result)

    def test_no_errors(self):
        result = report.render_errors({})
        self.assertIn("没有记录到扫描错误", result)


# ---------------------------------------------------------------------------
# render_next_steps
# ---------------------------------------------------------------------------
class RenderNextStepsTests(unittest.TestCase):
    def test_with_priority(self):
        analysis = {"summary": {"priority": ["先升 lodash", "再补 gitignore"]}}
        result = report.render_next_steps(analysis)
        self.assertIn("先升 lodash", result)

    def test_no_priority(self):
        result = report.render_next_steps({})
        self.assertIn("阅读报告后再决定", result)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class ParseArgsTests(unittest.TestCase):
    def test_required_only(self):
        args = report.parse_args(["analysis.json"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertIsNone(args.output_markdown)

    def test_with_output(self):
        args = report.parse_args(["analysis.json", "report.md"])
        self.assertEqual(args.output_markdown, "report.md")


# ---------------------------------------------------------------------------
# default_output_path
# ---------------------------------------------------------------------------
class DefaultOutputPathTests(unittest.TestCase):
    def test_generates_path_under_docs(self):
        analysis = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"path": "/tmp/test-project"},
        }
        with tempfile.TemporaryDirectory(prefix="butian-report-") as root:
            analysis["project"]["path"] = root
            path = report.default_output_path(analysis)
            self.assertTrue(path.endswith("security-report-2026-06-05_090550.md"))
            self.assertIn("docs/butian", path)


# ---------------------------------------------------------------------------
# pipeline: --help
# ---------------------------------------------------------------------------
class PipelineHelpTests(unittest.TestCase):
    def test_report_help(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        result = subprocess.run(
            [sys.executable, os.path.join("butian", "scripts", "report.py"), "--help"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
