"""Unit tests for butian/scripts/run_audit.py - pipeline orchestrator."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from butian.scripts import run_audit


def _scan_args(**overrides):
    """Build a namespace with all build_scan_cmd attributes and sensible defaults."""
    defaults = dict(
        skip_outdated=False,
        allow_project_exec=False,
        skip_hygiene=False,
        include_packages=False,
        max_secret_files=None,
        verbose=False,
        debug=False,
        follow_symlinks=False,
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

    def test_filters_lower_versions_and_matches_current_major(self):
        result = run_audit.best_fixed_version(
            [
                {
                    "version": "2.2.0",
                    "fixed_versions": ["1.11.23", "2.2.28", "3.2.25"],
                }
            ]
        )

        self.assertEqual(result, "2.2.28")


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
        self.assertEqual(run_audit.mode_label("hygiene_only"), "仓库安检")

    def test_unknown(self):
        self.assertEqual(run_audit.mode_label("custom"), "安全扫描")

    def test_server_only(self):
        self.assertEqual(run_audit.mode_label("server_only"), "服务器运行环境扫描")


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
        self.assertIn("🟢 低风险", rows[3][0])


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

    def test_no_issues_with_vulnerability_source_error_warns_incomplete(self):
        result = run_audit.format_focus(
            {
                "top_issues": [],
                "errors": [
                    {
                        "step": "vulnerability_check",
                        "message": "OSV 批次 1 返回 HTTP 403",
                    }
                ],
            }
        )

        self.assertIn("官方漏洞源检查存在失败", result)
        self.assertIn("不能当作完整的安全结论", result)
        self.assertNotIn("未发现需要优先处理的依赖漏洞。", result)

    def test_risk_summary_without_issue_details_warns_incomplete(self):
        result = run_audit.format_focus(
            {
                "top_issues": [],
                "server_issues": [],
                "risk_summary": {"high": 1},
            }
        )

        self.assertIn("风险计数", result)
        self.assertIn("缺少可展示的明细", result)
        self.assertNotIn("未发现需要优先处理", result)

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
        self.assertIn("已确认风险项", result)


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
        args = SimpleNamespace(no_open=True, final_report=False)
        result = run_audit.format_human_summary(summary, scan, analysis, args)
        self.assertIn("仓库安检", result)
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
        args = SimpleNamespace(no_open=True, final_report=False)
        result = run_audit.format_human_summary(summary, scan, analysis, args)
        self.assertIn("完整依赖漏洞扫描", result)
        self.assertIn("已确认风险项", result)
        self.assertIn("lodash", result)
        self.assertIn("风险项修复验证", result)

    def test_server_only_mode_counts_server_issues(self):
        summary = {
            "scan_mode": "server_only",
            "markdown_report": "/tmp/r.md",
            "html_report": None,
            "analysis_file": "/tmp/a.json",
            "errors": [],
        }
        scan = {"scan_config": {"scan_mode": "server_only"}, "hygiene": {}}
        analysis = {
            "project": {
                "path": "/tmp/demo",
                "name": "demo",
                "ecosystems": [],
                "total_packages": 0,
            },
            "risk_summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "hygiene": {},
            "top_issues": [],
            "server_issues": [
                {
                    "scope": "server",
                    "package": "nginx",
                    "version": "1.24.0",
                    "severity": "high",
                    "summary": "nginx confirmed",
                }
            ],
            "server_issue_count": 1,
            "vulnerability_count": 0,
            "outdated_count": 0,
            "errors": [],
        }
        args = SimpleNamespace(no_open=True, final_report=False)

        result = run_audit.format_human_summary(summary, scan, analysis, args)

        self.assertIn("已确认风险项：1 个", result)
        self.assertIn("nginx", result)
        self.assertIn("HTML 报告：服务器扫描不生成 HTML", result)
        self.assertIn("server-inventory.json", result)
        self.assertIn("server-assets.json", result)
        self.assertIn("server-vulns.json", result)
        self.assertIn("server-analysis.json", result)
        self.assertNotIn("总依赖", result)
        self.assertNotIn("仓库安检", result)
        self.assertNotIn("未发现需要优先处理的依赖漏洞", result)

    def test_final_report_label_has_space_before_markdown(self):
        summary = {
            "scan_mode": "hygiene_only",
            "markdown_report": "/tmp/r.md",
            "html_report": "/tmp/r.html",
            "analysis_file": "/tmp/a.json",
            "errors": [],
        }
        scan = {"scan_config": {"scan_mode": "hygiene_only"}, "hygiene": {}}
        analysis = {
            "project": {"path": "/tmp/demo", "name": "demo", "ecosystems": []},
            "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "hygiene": {},
            "top_issues": [],
            "vulnerability_count": 0,
            "outdated_count": 0,
            "errors": [],
        }
        args = SimpleNamespace(no_open=True, final_report=True)

        result = run_audit.format_human_summary(summary, scan, analysis, args)

        self.assertIn("最终 Markdown 审计报告", result)
        self.assertNotIn("最终Markdown", result)


class PipelinePathTests(unittest.TestCase):
    def test_main_writes_html_report_to_scan_run_dir(self):
        original_argv = sys.argv
        original_run_json = run_audit.run_json
        original_run_text = run_audit.run_text
        original_setup_logging = run_audit.setup_logging
        with tempfile.TemporaryDirectory(prefix="butian-run-audit-") as root:
            project = os.path.join(root, "project")
            run_dir = os.path.join(project, ".butian", "20260608-1200")
            assets_dir = os.path.join(run_dir, "assets")
            os.makedirs(assets_dir)
            preflight_path = os.path.join(assets_dir, "preflight.json")
            scan_path = os.path.join(assets_dir, "scan.json")
            captured = {"commands": []}

            def fake_run_json(cmd):
                if cmd[1].endswith("detect.py"):
                    return {
                        "output_file": preflight_path,
                        "recommended_scan_mode": "full_dependency_scan",
                        "butian_workspace": {
                            "run_dir": run_dir,
                            "assets_dir": assets_dir,
                            "content_dir": os.path.join(run_dir, "content"),
                        },
                    }
                return {
                    "output_file": scan_path,
                    "project": {
                        "path": project,
                        "ecosystems": ["npm"],
                        "total_packages": 0,
                    },
                    "scan_config": {"scan_mode": "full_dependency_scan"},
                    "hygiene": {},
                    "outdated": [],
                    "errors": [],
                    "vulnerabilities": [],
                    "butian_workspace": {
                        "run_dir": run_dir,
                        "assets_dir": assets_dir,
                        "content_dir": os.path.join(run_dir, "content"),
                    },
                }

            def fake_run_text(cmd, echo=True):
                captured["commands"].append(cmd)
                script = os.path.basename(cmd[1])
                if script == "analyze.py":
                    analysis_path = cmd[3]
                    with open(analysis_path, "w", encoding="utf-8") as handle:
                        json.dump(
                            {
                                "generated_at": "2026-06-05 09:05:50",
                                "project": {
                                    "path": project,
                                    "ecosystems": ["npm"],
                                    "total_packages": 0,
                                },
                                "risk_summary": {},
                                "top_issues": [],
                                "hygiene": {},
                                "outdated": [],
                                "errors": [],
                                "butian_workspace": {
                                    "run_dir": run_dir,
                                    "assets_dir": assets_dir,
                                    "content_dir": os.path.join(run_dir, "content"),
                                },
                            },
                            handle,
                        )
                return ""

            try:
                sys.argv = ["run_audit.py", "--no-open", project]
                run_audit.run_json = fake_run_json
                run_audit.run_text = fake_run_text
                run_audit.setup_logging = lambda *args, **kwargs: None

                run_audit.main()
            finally:
                sys.argv = original_argv
                run_audit.run_json = original_run_json
                run_audit.run_text = original_run_text
                run_audit.setup_logging = original_setup_logging

            visualize_cmd = [
                cmd
                for cmd in captured["commands"]
                if os.path.basename(cmd[1]) == "visualize.py"
            ][0]
            self.assertEqual(
                visualize_cmd[3],
                os.path.join(run_dir, "content", "security-report.html"),
            )


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

    def test_allow_project_exec(self):
        args = _scan_args(allow_project_exec=True)
        cmd = run_audit.build_scan_cmd(args, "preflight.json")
        self.assertIn("--allow-project-exec", cmd)

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


class BuildVisualizeCmdTests(unittest.TestCase):
    def test_final_report_forces_open(self):
        args = SimpleNamespace(no_open=False, final_report=True)
        cmd = run_audit.build_visualize_cmd(args, "analysis.json", "report.html")
        self.assertIn("--force-open", cmd)
        self.assertNotIn("--no-open", cmd)

    def test_no_open_still_passed_for_final_report(self):
        args = SimpleNamespace(no_open=True, final_report=True)
        cmd = run_audit.build_visualize_cmd(args, "analysis.json", "report.html")
        self.assertIn("--force-open", cmd)
        self.assertIn("--no-open", cmd)

    def test_normal_scan_does_not_force_open(self):
        args = SimpleNamespace(no_open=False, final_report=False)
        cmd = run_audit.build_visualize_cmd(args, "analysis.json", "report.html")
        self.assertNotIn("--force-open", cmd)


class ServerArgsTests(unittest.TestCase):
    def test_parse_server_args(self):
        args = run_audit.parse_args(
            [
                "--server",
                "root@203.0.113.10",
                "--server-only",
                "--ssh-port",
                "2222",
                "--identity",
                "/tmp/id_ed25519",
                "--include-docker-metadata",
            ]
        )

        self.assertEqual(args.server, "root@203.0.113.10")
        self.assertTrue(args.server_only)
        self.assertEqual(args.ssh_port, 2222)
        self.assertEqual(args.identity, "/tmp/id_ed25519")
        self.assertTrue(args.include_docker_metadata)

    def test_parse_server_args_can_still_use_ssh_config(self):
        args = run_audit.parse_args(
            ["--server", "prod-web", "--ssh-config", "/tmp/ssh_config"]
        )

        self.assertEqual(args.server, "prod-web")
        self.assertEqual(args.ssh_config, "/tmp/ssh_config")

    def test_parse_server_inventory_arg(self):
        args = run_audit.parse_args(
            ["--server-inventory", "/tmp/server-inventory.json"]
        )
        self.assertEqual(args.server_inventory, "/tmp/server-inventory.json")

    def test_server_only_requires_server_or_inventory(self):
        with self.assertRaises(SystemExit):
            run_audit.parse_args(["--server-only"])

        ssh_args = run_audit.parse_args(
            ["--server-only", "--server", "root@203.0.113.10"]
        )
        self.assertTrue(ssh_args.server_only)
        self.assertEqual(ssh_args.server, "root@203.0.113.10")

        inventory_args = run_audit.parse_args(
            ["--server-only", "--server-inventory", "/tmp/server.json"]
        )
        self.assertTrue(inventory_args.server_only)
        self.assertEqual(inventory_args.server_inventory, "/tmp/server.json")


class ServerPipelineHelperTests(unittest.TestCase):
    def test_build_server_scan_payload_from_inventory(self):
        inventory = {
            "target": "root@example.test",
            "outputs": {"os_release": {"stdout": "ID=ubuntu\nVERSION_ID=24.04\n"}},
            "errors": [],
        }
        calls = []
        fake_assets = {"distro": {"id": "ubuntu"}, "packages": []}
        fake_matches = {"confirmed": []}
        fake_analysis = {
            "summary": {"package_count": 0, "confirmed_count": 0},
            "confirmed_issues": [],
            "maintenance_items": [],
            "errors": [],
        }
        modules = {
            "butian.scripts.server_inventory": SimpleNamespace(
                build_server_assets=lambda data: (
                    calls.append(("assets", data)) or fake_assets
                )
            ),
            "butian.scripts.server_match": SimpleNamespace(
                match_server_vulnerabilities=lambda assets, project_path: (
                    calls.append(("match", assets, project_path)) or fake_matches
                )
            ),
            "butian.scripts.server_analyze": SimpleNamespace(
                build_server_analysis=lambda assets, matches: (
                    calls.append(("analysis", assets, matches)) or fake_analysis
                )
            ),
        }

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(sys.modules, modules):
                payload = run_audit.build_server_scan_payload(
                    inventory, project_path=tmp
                )

        self.assertIn("assets", payload)
        self.assertIn("analysis", payload)
        self.assertIn("server", payload)
        self.assertEqual(payload["server"]["assets"]["distro"]["id"], "ubuntu")
        self.assertEqual(payload["server"]["analysis"], fake_analysis)
        self.assertEqual(
            calls,
            [
                ("assets", inventory),
                ("match", fake_assets, tmp),
                ("analysis", fake_assets, fake_matches),
            ],
        )


class ServerIdentityRedactionTests(unittest.TestCase):
    def test_strip_server_identity_redacts_explicit_secret_from_free_text(self):
        payload = {
            "errors": [
                {
                    "step": "ssh",
                    "message": "Identity file /tmp/id_prod not accessible",
                }
            ],
            "outputs": {"probe": {"stderr": "using /tmp/id_prod"}},
        }

        result = run_audit.strip_server_identity(
            payload, extra_secrets={"/tmp/id_prod"}
        )

        rendered = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("/tmp/id_prod", rendered)
        self.assertIn("[redacted-identity]", rendered)

    def test_strip_server_identity_handles_case_insensitive_identity_keys(self):
        payload = {
            "IdentityFile": "/tmp/id_prod",
            "errors": [{"message": "using /tmp/id_prod"}],
        }

        result = run_audit.strip_server_identity(payload)

        rendered = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("IdentityFile", rendered)
        self.assertNotIn("/tmp/id_prod", rendered)
        self.assertIn("[redacted-identity]", rendered)


class ServerOnlyPipelineTests(unittest.TestCase):
    def test_main_server_only_writes_scan_and_artifacts_without_identity(self):
        original_argv = sys.argv
        original_run_json = run_audit.run_json
        original_run_text = run_audit.run_text
        original_setup_logging = run_audit.setup_logging
        with tempfile.TemporaryDirectory(prefix="butian-server-only-") as root:
            project = os.path.join(root, "project")
            run_dir = os.path.join(project, ".butian", "20260609-2100")
            assets_dir = os.path.join(run_dir, "assets")
            content_dir = os.path.join(run_dir, "content")
            os.makedirs(assets_dir)
            preflight_path = os.path.join(assets_dir, "preflight.json")
            scan_path = os.path.join(assets_dir, "scan.json")
            analysis_path = os.path.join(assets_dir, "analysis.json")
            server_inventory = {
                "target": "root@example.test",
                "identity": "/tmp/id_server_only",
                "ssh": {"identity_file": "/tmp/id_server_only"},
                "outputs": {"os_release": {"stdout": "ID=ubuntu\nVERSION_ID=24.04\n"}},
                "errors": [
                    {
                        "step": "ssh",
                        "message": "ssh failed while using /tmp/id_server_only",
                    }
                ],
            }
            sanitized_server_inventory = {
                "target": "root@example.test",
                "ssh": {},
                "outputs": {"os_release": {"stdout": "ID=ubuntu\nVERSION_ID=24.04\n"}},
                "errors": [
                    {
                        "step": "ssh",
                        "message": "ssh failed while using [redacted-identity]",
                    }
                ],
            }
            server_assets = {"distro": {"id": "ubuntu"}, "packages": []}
            server_matched = {"confirmed_issues": [], "errors": []}
            server_analysis = {
                "summary": {"package_count": 0, "confirmed_count": 1},
                "confirmed_issues": [
                    {
                        "scope": "server",
                        "package": "nginx",
                        "version": "1.24.0",
                        "severity": "high",
                        "confidence": "confirmed",
                        "summary": "nginx confirmed",
                    }
                ],
                "maintenance_items": [],
                "errors": [{"step": "server_match", "message": "partial source"}],
            }
            collect_calls = []
            captured = {"commands": []}

            modules = {
                "butian.scripts.server_collect": SimpleNamespace(
                    collect_server_inventory=lambda target, port, identity, ssh_config, include_docker_metadata: (
                        collect_calls.append(
                            {
                                "target": target,
                                "port": port,
                                "identity": identity,
                                "ssh_config": ssh_config,
                                "include_docker_metadata": include_docker_metadata,
                            }
                        )
                        or server_inventory
                    ),
                    read_inventory_file=lambda path: server_inventory,
                ),
                "butian.scripts.server_inventory": SimpleNamespace(
                    build_server_assets=lambda inventory: server_assets
                ),
                "butian.scripts.server_match": SimpleNamespace(
                    match_server_vulnerabilities=lambda assets, project_path: (
                        server_matched
                    )
                ),
                "butian.scripts.server_analyze": SimpleNamespace(
                    build_server_analysis=lambda assets, matched: server_analysis
                ),
            }

            def fake_run_json(cmd):
                script = os.path.basename(cmd[1])
                if script != "detect.py":
                    raise AssertionError("server-only must skip dependency scan")
                return {
                    "generated_at": "2026-06-09 21:00:00",
                    "output_file": preflight_path,
                    "recommended_scan_mode": "full_dependency_scan",
                    "project": {
                        "path": project,
                        "name": "demo",
                        "ecosystems": [],
                        "total_packages": 0,
                    },
                    "butian_workspace": {
                        "run_dir": run_dir,
                        "assets_dir": assets_dir,
                        "content_dir": content_dir,
                    },
                }

            def fake_run_text(cmd, echo=True):
                captured["commands"].append(cmd)
                script = os.path.basename(cmd[1])
                if script == "analyze.py":
                    self.assertEqual(cmd[2], scan_path)
                    self.assertEqual(cmd[3], analysis_path)
                    with open(analysis_path, "w", encoding="utf-8") as handle:
                        json.dump(
                            {
                                "generated_at": "2026-06-09 21:00:00",
                                "project": {"path": project, "name": "demo"},
                                "risk_summary": {"high": 1},
                                "top_issues": [],
                                "hygiene": {},
                                "outdated": [],
                                "errors": server_analysis["errors"],
                                "butian_workspace": {
                                    "run_dir": run_dir,
                                    "assets_dir": assets_dir,
                                    "content_dir": content_dir,
                                },
                            },
                            handle,
                        )
                return ""

            try:
                sys.argv = [
                    "run_audit.py",
                    "--server",
                    "root@203.0.113.10",
                    "--server-only",
                    "--ssh-port",
                    "2222",
                    "--identity",
                    "/tmp/id_server_only",
                    "--include-docker-metadata",
                    "--no-open",
                    project,
                ]
                run_audit.run_json = fake_run_json
                run_audit.run_text = fake_run_text
                run_audit.setup_logging = lambda *args, **kwargs: None
                with mock.patch.dict(sys.modules, modules):
                    self.assertEqual(run_audit.main(), 0)
            finally:
                sys.argv = original_argv
                run_audit.run_json = original_run_json
                run_audit.run_text = original_run_text
                run_audit.setup_logging = original_setup_logging

            self.assertEqual(
                collect_calls,
                [
                    {
                        "target": "root@203.0.113.10",
                        "port": 2222,
                        "identity": "/tmp/id_server_only",
                        "ssh_config": "",
                        "include_docker_metadata": True,
                    }
                ],
            )
            with open(scan_path, "r", encoding="utf-8") as handle:
                scan = json.load(handle)
            with open(
                os.path.join(assets_dir, "server-inventory.json"),
                "r",
                encoding="utf-8",
            ) as handle:
                inventory_json = json.load(handle)
            with open(
                os.path.join(assets_dir, "server-assets.json"),
                "r",
                encoding="utf-8",
            ) as handle:
                assets_json = json.load(handle)
            with open(
                os.path.join(assets_dir, "server-analysis.json"),
                "r",
                encoding="utf-8",
            ) as handle:
                server_analysis_json = json.load(handle)
            with open(
                os.path.join(assets_dir, "server-vulns.json"),
                "r",
                encoding="utf-8",
            ) as handle:
                server_vulns_json = json.load(handle)

            self.assertEqual(scan["scan_config"]["scan_mode"], "server_only")
            self.assertEqual(scan["vulnerabilities"], [])
            self.assertEqual(scan["server"], server_analysis)
            self.assertIn(server_analysis["errors"][0], scan["errors"])
            self.assertEqual(inventory_json, sanitized_server_inventory)
            self.assertEqual(assets_json, server_assets)
            self.assertEqual(server_analysis_json, server_analysis)
            self.assertEqual(server_vulns_json, server_matched)
            command_names = [os.path.basename(cmd[1]) for cmd in captured["commands"]]
            self.assertIn("report.py", command_names)
            self.assertNotIn("visualize.py", command_names)
            self.assertFalse(
                os.path.exists(os.path.join(content_dir, "security-report.html"))
            )
            self.assertNotIn(
                "/tmp/id_server_only", json.dumps(scan, ensure_ascii=False)
            )
            self.assertNotIn(
                "/tmp/id_server_only",
                json.dumps(inventory_json, ensure_ascii=False),
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
        self.assertFalse(args.no_open)

    def test_all_flags(self):
        args = run_audit.parse_args(
            [
                "--no-root-discovery",
                "--skip-outdated",
                "--skip-hygiene",
                "--include-packages",
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
