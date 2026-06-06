"""Unit tests for butian/scripts/fix.py"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import fix as fix_mod


# ---------------------------------------------------------------------------
# extract_fixable_items
# ---------------------------------------------------------------------------
class ExtractFixableItemsTests(unittest.TestCase):
    def test_extracts_upgrade_items_from_current_green_schema(self):
        analysis = {
            "green": [
                {
                    "type": "dependency_upgrade",
                    "package": "lodash",
                    "severity": "high",
                    "summary": "升级 lodash",
                    "fix_config": {
                        "type": "upgrade",
                        "ecosystem": "npm",
                        "package": "lodash",
                        "current_versions": ["4.17.20"],
                        "target_version": "4.17.21",
                        "fixed_versions": ["4.17.21"],
                        "advisory_ids": ["GHSA-abc"],
                    },
                },
                {
                    "type": "dependency_upgrade",
                    "package": "norel",
                    "severity": "medium",
                    "summary": "无生态",
                    "fix_config": {
                        "type": "upgrade",
                        "ecosystem": None,
                        "package": "norel",
                        "current_versions": ["1.0"],
                        "target_version": "1.1",
                        "fixed_versions": ["1.1"],
                        "advisory_ids": [],
                    },
                },
            ]
        }
        items = fix_mod.extract_fixable_items(analysis)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["package"], "lodash")
        self.assertEqual(items[0]["target_version"], "4.17.21")
        self.assertEqual(items[1]["package"], "norel")

    def test_extracts_upgrade_items_from_legacy_green_items_schema(self):
        analysis = {
            "green_items": [
                {
                    "type": "dependency_upgrade",
                    "package": "lodash",
                    "severity": "high",
                    "summary": "升级 lodash",
                    "fix_config": {
                        "type": "upgrade",
                        "ecosystem": "npm",
                        "package": "lodash",
                        "current_versions": ["4.17.20"],
                        "target_version": "4.17.21",
                        "fixed_versions": ["4.17.21"],
                        "advisory_ids": ["GHSA-abc"],
                    },
                }
            ]
        }
        items = fix_mod.extract_fixable_items(analysis)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["package"], "lodash")
        self.assertEqual(items[0]["target_version"], "4.17.21")

    def test_skips_items_without_target_version(self):
        analysis = {
            "green_items": [
                {
                    "type": "dependency_upgrade",
                    "package": "bad",
                    "fix_config": {
                        "type": "upgrade",
                        "ecosystem": "npm",
                        "package": "bad",
                        "target_version": None,
                    },
                }
            ]
        }
        items = fix_mod.extract_fixable_items(analysis)
        self.assertEqual(len(items), 0)

    def test_skips_non_upgrade_items(self):
        analysis = {
            "green_items": [
                {
                    "type": "gitignore",
                    "name": "添加 .env",
                    "fix_config": {"type": "gitignore", "patterns": [".env"]},
                }
            ]
        }
        items = fix_mod.extract_fixable_items(analysis)
        self.assertEqual(len(items), 0)

    def test_empty_analysis(self):
        items = fix_mod.extract_fixable_items({})
        self.assertEqual(items, [])
        items2 = fix_mod.extract_fixable_items({"green_items": []})
        self.assertEqual(items2, [])


# ---------------------------------------------------------------------------
# build_upgrade_commands
# ---------------------------------------------------------------------------
class BuildUpgradeCommandsTests(unittest.TestCase):
    _FIX_ITEMS = [
        {
            "package": "lodash",
            "ecosystem": "npm",
            "current_version": "4.17.20",
            "target_version": "4.17.21",
            "fixed_versions": ["4.17.21"],
            "advisory_ids": ["GHSA-abc"],
            "severity": "high",
            "summary": "",
        },
        {
            "package": "requests",
            "ecosystem": "pypi",
            "current_version": "2.25.0",
            "target_version": "2.31.0",
            "fixed_versions": ["2.31.0"],
            "advisory_ids": ["CVE-2023"],
            "severity": "critical",
            "summary": "",
        },
    ]

    def test_minimal_npm(self):
        cmds = fix_mod.build_upgrade_commands(self._FIX_ITEMS, "minimal")
        pkgs = {pkg for pkg, _ in cmds}
        self.assertIn("lodash", pkgs)
        self.assertIn("requests", pkgs)
        # lodash should use npm install lodash@4.17.21
        lodash_cmd = [c for p, c in cmds if p == "lodash"][0]
        self.assertEqual(lodash_cmd[-1], "lodash@4.17.21")

    def test_latest_npm(self):
        cmds = fix_mod.build_upgrade_commands(self._FIX_ITEMS, "latest")
        lodash_cmd = [c for p, c in cmds if p == "lodash"][0]
        self.assertEqual(lodash_cmd[-1], "lodash@latest")

    def test_latest_pypi(self):
        cmds = fix_mod.build_upgrade_commands(self._FIX_ITEMS, "latest")
        requests_cmd = [c for p, c in cmds if p == "requests"][0]
        self.assertIn("--upgrade", requests_cmd)

    def test_ecosystem_filter(self):
        cmds = fix_mod.build_upgrade_commands(
            self._FIX_ITEMS, "minimal", ecosystem="npm"
        )
        pkgs = {pkg for pkg, _ in cmds}
        self.assertEqual(pkgs, {"lodash"})

    def test_unknown_ecosystem_skipped(self):
        items = [
            {
                "package": "foo",
                "ecosystem": "unknown-eco",
                "target_version": "1.0",
            }
        ]
        cmds = fix_mod.build_upgrade_commands(items, "minimal")
        self.assertEqual(len(cmds), 0)

    def test_all_ecosystems(self):
        """Verify command builders exist for all supported ecosystems."""
        for eco in ["npm", "pnpm", "yarn", "pypi", "go", "crates-io"]:
            items = [{"package": "pkg", "ecosystem": eco, "target_version": "1.0"}]
            cmds = fix_mod.build_upgrade_commands(items, "minimal")
            self.assertEqual(len(cmds), 1, f"No command for ecosystem {eco}")
            self.assertTrue(len(cmds[0][1]) > 0, f"Empty command for {eco}")


# ---------------------------------------------------------------------------
# npm overrides
# ---------------------------------------------------------------------------
class NpmOverridePlanTests(unittest.TestCase):
    def test_builds_parent_scoped_overrides_for_nested_vulnerable_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            package_lock = {
                "packages": {
                    "": {"dependencies": {"postcss": "^8.5.10"}},
                    "node_modules/postcss": {"version": "8.5.10"},
                    "node_modules/next": {"version": "16.2.6"},
                    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
                    "node_modules/@scope/parent": {"version": "1.0.0"},
                    "node_modules/@scope/parent/node_modules/esbuild": {
                        "version": "0.18.20"
                    },
                }
            }
            with open(
                os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(package_lock, f)
            analysis = {
                "project": {"path": tmp},
                "green": [
                    {
                        "type": "dependency_upgrade",
                        "package": "postcss",
                        "fix_config": {
                            "ecosystem": "npm",
                            "package": "postcss",
                            "current_versions": ["8.4.31"],
                            "target_version": "8.5.10",
                        },
                    },
                    {
                        "type": "dependency_upgrade",
                        "package": "esbuild",
                        "fix_config": {
                            "ecosystem": "npm",
                            "package": "esbuild",
                            "current_versions": ["0.18.20"],
                            "target_version": "0.25.0",
                        },
                    },
                ],
            }

            plan = fix_mod.build_npm_override_plan(analysis, tmp)

        self.assertEqual(
            [
                (item["parent"], item["package"], item["target_version"])
                for item in plan["overrides"]
            ],
            [
                ("next", "postcss", "8.5.10"),
                ("@scope/parent", "esbuild", "0.25.0"),
            ],
        )
        self.assertEqual(
            [
                (item["package"], item["target_version"])
                for item in plan["global_overrides"]
            ],
            [("postcss", "8.5.10"), ("esbuild", "0.25.0")],
        )

    def test_apply_npm_overrides_preserves_existing_parent_override_and_adds_global_fallback(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            package_json = {
                "dependencies": {"next": "^16.2.6", "postcss": "^8.5.10"},
                "overrides": {"next": {"styled-jsx": "5.1.6"}},
            }
            package_json_path = os.path.join(tmp, "package.json")
            with open(package_json_path, "w", encoding="utf-8") as f:
                json.dump(package_json, f)
            plan = {
                "overrides": [
                    {
                        "parent": "next",
                        "package": "postcss",
                        "target_version": "8.5.10",
                    }
                ],
                "global_overrides": [
                    {"package": "postcss", "target_version": "8.5.10"}
                ],
            }

            changed = fix_mod.apply_npm_overrides(tmp, plan)

            with open(package_json_path, "r", encoding="utf-8") as f:
                updated = json.load(f)

        self.assertTrue(changed)
        self.assertEqual(updated["overrides"]["next"]["styled-jsx"], "5.1.6")
        self.assertEqual(updated["overrides"]["next"]["postcss"], "8.5.10")
        self.assertEqual(updated["overrides"]["postcss"], "$postcss")

    def test_execute_override_fixes_rebuilds_lockfile_when_first_install_leaves_residuals(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            package_json_path = os.path.join(tmp, "package.json")
            lock_path = os.path.join(tmp, "package-lock.json")
            with open(package_json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"dependencies": {"next": "^16.2.6", "postcss": "^8.5.10"}},
                    f,
                )
            with open(lock_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "packages": {
                            "": {"dependencies": {"postcss": "^8.5.10"}},
                            "node_modules/postcss": {"version": "8.5.10"},
                            "node_modules/next": {"version": "16.2.6"},
                            "node_modules/next/node_modules/postcss": {
                                "version": "8.4.31"
                            },
                        }
                    },
                    f,
                )
            analysis = {
                "project": {"path": tmp},
                "green": [
                    {
                        "type": "dependency_upgrade",
                        "package": "postcss",
                        "fix_config": {
                            "ecosystem": "npm",
                            "package": "postcss",
                            "current_versions": ["8.4.31"],
                            "target_version": "8.5.10",
                        },
                    }
                ],
            }

            def fake_install(project_path):
                self.assertEqual(project_path, tmp)
                if not os.path.exists(lock_path):
                    with open(lock_path, "w", encoding="utf-8") as f:
                        json.dump(
                            {
                                "packages": {
                                    "": {"dependencies": {"postcss": "^8.5.10"}},
                                    "node_modules/postcss": {"version": "8.5.10"},
                                    "node_modules/next": {"version": "16.2.6"},
                                    "node_modules/next/node_modules/postcss": {
                                        "version": "8.5.10"
                                    },
                                }
                            },
                            f,
                        )
                return True, ""

            with mock.patch.object(
                fix_mod, "_run_npm_install", side_effect=fake_install
            ) as install:
                successes, failures = fix_mod.execute_override_fixes(analysis, tmp)

            with open(lock_path, "r", encoding="utf-8") as f:
                rebuilt_lock = json.load(f)

        self.assertEqual(install.call_count, 2)
        self.assertEqual(successes, ["next > postcss@8.5.10"])
        self.assertEqual(failures, [])
        self.assertEqual(
            rebuilt_lock["packages"]["node_modules/next/node_modules/postcss"][
                "version"
            ],
            "8.5.10",
        )


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
class CliHelperTests(unittest.TestCase):
    def test_parse_args_requires_explicit_strategy(self):
        args = fix_mod.parse_args(["analysis.json", "--strategy", "fixed"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertEqual(args.strategy, "fixed")

    def test_parse_args_accepts_overrides_strategy(self):
        args = fix_mod.parse_args(["analysis.json", "--strategy", "overrides"])
        self.assertEqual(args.strategy, "overrides")

    def test_fixed_strategy_maps_to_minimal(self):
        self.assertEqual(fix_mod.normalize_strategy("fixed"), "minimal")
        self.assertEqual(fix_mod.normalize_strategy("latest"), "latest")

    def test_strategy_label(self):
        self.assertEqual(fix_mod.strategy_label("minimal"), "升级到已修复版本")
        self.assertEqual(fix_mod.strategy_label("fixed"), "升级到已修复版本")
        self.assertEqual(fix_mod.strategy_label("latest"), "升级到最新版本")

    def test_post_fix_guidance_explains_rescan_and_transitive_residuals(self):
        lines = fix_mod.post_fix_guidance("minimal")
        text = "\n".join(lines)
        self.assertIn("重新运行补天扫描", text)
        self.assertIn("普通包管理器升级", text)
        self.assertIn("间接依赖", text)
        self.assertIn("overrides", text)

    def test_post_fix_guidance_for_overrides_warns_about_forced_updates(self):
        text = "\n".join(fix_mod.post_fix_guidance("overrides"))
        self.assertIn("强制覆盖更新", text)
        self.assertIn("兼容性", text)


if __name__ == "__main__":
    unittest.main()
