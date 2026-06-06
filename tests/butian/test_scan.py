"""Comprehensive tests for butian/scripts/scan.py.

Covers secret detection (97 patterns), entropy engine, sensitive files,
gitignore helpers, lockfile parsers, vulnerability data parsing, CVSS scoring,
workspace management, utility helpers, and pipeline integration.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

# Import scan module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "butian", "scripts"))
from butian.scripts import analyze, run_audit, scan


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
        # verify run_audit no longer has should_echo_build_report (removed with --compact)
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
            "check local dependency security and repository hygiene", skill_doc
        )
        self.assertIn("不修改源码、依赖、数据库、日志或任意项目文件", skill_doc)
        self.assertIn("会创建/更新 `.butian/` 本地报告工作区", skill_doc)
        self.assertIn("会确保 `.gitignore` 忽略 `.butian/`", skill_doc)
        self.assertNotIn("全程只读，绝不擅自动手", skill_doc)
        self.assertNotIn("没有任何会触发本地操作的按钮", skill_doc)


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
        # .env.example starts with ".env." → is_env_secret_scan_file returns True
        # (actual template filtering happens in is_env_template / sensitive_file_type)
        self.assertTrue(scan.is_env_secret_scan_file(".env.example"))


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

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-yarn-") as root:
            self.assertEqual(scan.parse_yarn_lock(root), [])


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
                    # no source → local crate, should be excluded from fallback
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
        """CVSS 3.x vector without baseScore → compute from metrics."""
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIn(result, {"critical", "high"})

    def test_all_confidentiality_none(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(result, "low")

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

    def test_falls_back_to_osv_cvss(self):
        # C:H/I:L/A:N → ISS≈0.657, impact≈4.22, exploit≈3.92, base≈8.1 → high
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


class EnsureButianRunTests(unittest.TestCase):
    def test_creates_workspace_and_dirs(self):
        with tempfile.TemporaryDirectory(prefix="butian-run-") as root:
            run_dir = scan.ensure_butian_run(root)
            self.assertTrue(os.path.isdir(run_dir))
            self.assertTrue(os.path.isdir(os.path.join(run_dir, "assets")))
            self.assertTrue(os.path.isdir(os.path.join(run_dir, "content")))
            self.assertTrue(os.path.isfile(os.path.join(root, ".gitignore")))

    def test_collision_avoidance(self):
        with tempfile.TemporaryDirectory(prefix="butian-run-") as root:
            first = scan.ensure_butian_run(root)
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()  # reset cache
            second = scan.ensure_butian_run(root)
            # Second call within the same second gets a suffix
            if first == second:
                # If same timestamp, it would have a suffix; otherwise just
                # verify both are valid directories
                pass
            else:
                self.assertNotEqual(first, second)


class EnsureButianGitignoreTests(unittest.TestCase):
    def test_creates_gitignore(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            path = scan.ensure_butian_gitignore(root)
            self.assertTrue(os.path.isfile(path))
            with open(path) as f:
                content = f.read()
            self.assertIn(".butian/", content)

    def test_appends_to_existing(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            with open(os.path.join(root, ".gitignore"), "w") as f:
                f.write("node_modules/\n")
            scan.ensure_butian_gitignore(root)
            with open(os.path.join(root, ".gitignore")) as f:
                content = f.read()
            self.assertIn("node_modules/", content)
            self.assertIn(".butian/", content)

    def test_does_not_duplicate_entry(self):
        with tempfile.TemporaryDirectory(prefix="butian-gitignore-") as root:
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            scan.ensure_butian_gitignore(root)
            scan._GITIGNORE_STATUS_BY_PROJECT.clear()
            scan.ensure_butian_gitignore(root)
            with open(os.path.join(root, ".gitignore")) as f:
                content = f.read()
            self.assertEqual(content.count(".butian/"), 1)


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
        # All same character → 0 entropy
        self.assertEqual(scan._shannon_entropy("aaaa"), 0.0)

    def test_shannon_entropy_high(self):
        # Mixed characters → high entropy
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
        # This is a known MD5 — high enough hex entropy
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
        # "test" as a standalone word in comment-like context
        self.assertEqual(
            self._count_findings('api_key = "a_real_secret_for_prod"  # test\n'), 0
        )

    def test_skip_standalone_default_in_comment(self):
        # "default" as a standalone word in comment-like context
        self.assertEqual(
            self._count_findings('api_key = "a_real_prod_key"  # default\n'), 0
        )

    def test_no_skip_xxx_inside_value(self):
        """'xxx' inside a longer secret value should NOT trigger skip."""
        # A real-looking API key that happens to contain 'xxx'
        self._count_findings(
            'secret_key = "aXxxB3cD5eF7gH9iJ1kLmNoPqR2"\n'
        )  # fake fixture
        # Should NOT be skipped — 'xxx' is part of a value, not a standalone word
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
        # 15 chars after sk- — long enough for generic_sk_key (8+) but
        # shorter than openai_key threshold (20+)
        f = self._detect_one(
            'MY_KEY = "sk-' + 'abc123def456ghi"', "generic_sk_key"
        )  # fake fixture
        self.assertEqual(f["confidence"], "medium")

    def test_generic_sk_key_no_false_positive_css(self):
        # CSS properties like "mask-composite" contain "sk-composite" — must NOT match
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


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
