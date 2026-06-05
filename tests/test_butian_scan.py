import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from butian.scripts import run_audit, scan


class ButianScanTests(unittest.TestCase):
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

    def test_scan_secrets_includes_env_variants(self):
        with tempfile.TemporaryDirectory(prefix="butian-env-") as root:
            with open(
                os.path.join(root, ".env.local"), "w", encoding="utf-8"
            ) as handle:
                key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
                handle.write(f'OPENAI_API_KEY="{key}"\n')

            findings = scan.scan_secrets(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], ".env.local")
            self.assertEqual(findings[0]["type"], "openai_key")

    def test_openai_key_is_high_confidence_with_short_preview(self):
        with tempfile.TemporaryDirectory(prefix="butian-openai-key-") as root:
            with open(
                os.path.join(root, ".env.local"), "w", encoding="utf-8"
            ) as handle:
                key = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
                handle.write(f'OPENAI_API_KEY="{key}"\n')

            [finding] = scan.scan_secrets(root)

            self.assertEqual(finding["type"], "openai_key")
            self.assertEqual(finding["confidence"], "high")
            self.assertEqual(finding["preview"], "sk-proj...7890")

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
                            "node_modules/foo/node_modules/bar": {
                                "version": "2.0.0"
                            },
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
        with tempfile.TemporaryDirectory(
            prefix="butian-preflight-project-"
        ) as root, tempfile.TemporaryDirectory(
            prefix="butian-preflight-output-"
        ) as out_dir:
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
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                capture_output=True,
                text=True,
                check=True,
            )
            preflight = json.loads(result.stdout)

            self.assertEqual(preflight["output_file"], output)
            self.assertTrue(os.path.isdir(os.path.join(root, ".butian")))
            with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8") as handle:
                self.assertIn(".butian/", handle.read())
            self.assertTrue(
                os.path.abspath(preflight["butian_workspace"]["run_dir"]).startswith(
                    os.path.join(os.path.abspath(root), ".butian")
                )
            )

    def test_human_summary_warns_when_hygiene_only_skips_dependency_scan(self):
        summary = {
            "scan_mode": "hygiene_only",
            "markdown_report": "/tmp/demo/docs/security-report-2026-06-05.md",
            "html_report": "/tmp/demo/.butian/run/content/security-report.html",
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
            summary, scan_output, analysis, SimpleNamespace(no_open=True)
        )

        self.assertIn("暂不支持依赖漏洞扫描", text)
        self.assertNotIn("未发现需要优先处理的依赖漏洞", text)

    def test_build_report_output_is_visible_in_human_mode(self):
        self.assertTrue(run_audit.should_echo_build_report(SimpleNamespace(compact=False)))
        self.assertFalse(run_audit.should_echo_build_report(SimpleNamespace(compact=True)))

    def test_pipeline_scripts_expose_help(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "butian", "SKILL.md"), encoding="utf-8") as handle:
            skill_doc = handle.read()

        self.assertIn("check local dependency security and repository hygiene", skill_doc)
        self.assertIn("不修改源码、依赖、数据库、日志或任意项目文件", skill_doc)
        self.assertIn("会创建/更新 `.butian/` 本地报告工作区", skill_doc)
        self.assertIn("会确保 `.gitignore` 忽略 `.butian/`", skill_doc)
        self.assertNotIn("全程只读，绝不擅自动手", skill_doc)
        self.assertNotIn("没有任何会触发本地操作的按钮", skill_doc)


if __name__ == "__main__":
    unittest.main()
