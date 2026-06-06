"""Unit tests for butian/scripts/fix.py"""

import json
import os
import sys
import tempfile
import unittest

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
# npm parent dependency upgrades
# ---------------------------------------------------------------------------
class NpmParentUpgradePlanTests(unittest.TestCase):
    def test_builds_direct_parent_upgrade_for_nested_vulnerable_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            package_lock = {
                "packages": {
                    "": {"dependencies": {"next": "^16.2.6", "postcss": "^8.5.10"}},
                    "node_modules/postcss": {"version": "8.5.10"},
                    "node_modules/next": {
                        "version": "16.2.6",
                        "dependencies": {"postcss": "8.4.31"},
                    },
                    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
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
                    }
                ],
            }

            plan = fix_mod.build_npm_parent_upgrade_plan(analysis, tmp)

        self.assertEqual(
            [
                (
                    item["upgrade_package"],
                    item["immediate_parent"],
                    item["package"],
                    item["current_version"],
                )
                for item in plan["upgrades"]
            ],
            [("next", "next", "postcss", "8.4.31")],
        )
        self.assertEqual(plan["skipped"], [])

    def test_traces_transitive_parent_to_direct_root_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            package_lock = {
                "packages": {
                    "": {"devDependencies": {"tsx": "^4.21.0"}},
                    "node_modules/tsx": {
                        "version": "4.21.0",
                        "dependencies": {"@esbuild-kit/core-utils": "3.3.2"},
                    },
                    "node_modules/@esbuild-kit/core-utils": {
                        "version": "3.3.2",
                        "dependencies": {"esbuild": "~0.18.20"},
                    },
                    "node_modules/@esbuild-kit/core-utils/node_modules/esbuild": {
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
                        "package": "esbuild",
                        "fix_config": {
                            "ecosystem": "npm",
                            "package": "esbuild",
                            "current_versions": ["0.18.20"],
                            "target_version": "0.25.0",
                        },
                    }
                ],
            }

            plan = fix_mod.build_npm_parent_upgrade_plan(analysis, tmp)

        self.assertEqual(
            [
                (
                    item["upgrade_package"],
                    item["immediate_parent"],
                    item["package"],
                )
                for item in plan["upgrades"]
            ],
            [("tsx", "@esbuild-kit/core-utils", "esbuild")],
        )

    def test_in_range_residual_still_upgrades_parent(self):
        """When parent declares ^8.4.0 and target is 8.5.10, it's in-range."""
        with tempfile.TemporaryDirectory() as tmp:
            package_lock = {
                "packages": {
                    "": {"dependencies": {"next": "^16.2.6", "postcss": "^8.5.10"}},
                    "node_modules/postcss": {"version": "8.5.10"},
                    "node_modules/next": {
                        "version": "16.2.6",
                        "requires": {"postcss": "^8.4.0"},
                    },
                    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
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
                    }
                ],
            }

            plan = fix_mod.build_npm_parent_upgrade_plan(analysis, tmp)

        self.assertEqual(len(plan["upgrades"]), 1)
        entry = plan["upgrades"][0]
        self.assertEqual(entry["package"], "postcss")
        self.assertEqual(entry["upgrade_package"], "next")


# CLI helpers
# ---------------------------------------------------------------------------
class CliHelperTests(unittest.TestCase):
    def test_parse_args_requires_explicit_strategy(self):
        args = fix_mod.parse_args(["analysis.json", "--strategy", "fixed"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertEqual(args.strategy, "fixed")

    def test_parse_args_accepts_parent_upgrade_strategy(self):
        args = fix_mod.parse_args(["analysis.json", "--strategy", "parent-upgrade"])
        self.assertEqual(args.strategy, "parent-upgrade")

    def test_fixed_strategy_maps_to_minimal(self):
        self.assertEqual(fix_mod.normalize_strategy("fixed"), "minimal")
        self.assertEqual(fix_mod.normalize_strategy("latest"), "latest")

    def test_strategy_label(self):
        self.assertEqual(fix_mod.strategy_label("minimal"), "升级到已修复版本")
        self.assertEqual(fix_mod.strategy_label("fixed"), "升级到已修复版本")
        self.assertEqual(fix_mod.strategy_label("latest"), "升级到最新版本")
        self.assertEqual(fix_mod.strategy_label("parent-upgrade"), "升级父依赖")

    def test_post_fix_guidance_explains_rescan_and_transitive_residuals(self):
        lines = fix_mod.post_fix_guidance("minimal")
        text = "\n".join(lines)
        self.assertIn("重新运行补天扫描", text)
        self.assertIn("普通包管理器升级", text)
        self.assertIn("父依赖信息", text)
        self.assertIn("升级父依赖", text)

    def test_post_fix_guidance_for_parent_upgrade_warns_about_parent_versions(self):
        text = "\n".join(fix_mod.post_fix_guidance("parent-upgrade"))
        self.assertIn("父依赖", text)
        self.assertIn("latest", text)


if __name__ == "__main__":
    unittest.main()
