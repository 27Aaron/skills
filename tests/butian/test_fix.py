"""Unit tests for butian/scripts/fix.py"""

import os
import sys
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
# CLI helpers
# ---------------------------------------------------------------------------
class CliHelperTests(unittest.TestCase):
    def test_parse_args_requires_explicit_strategy(self):
        args = fix_mod.parse_args(["analysis.json", "--strategy", "fixed"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertEqual(args.strategy, "fixed")

    def test_fixed_strategy_maps_to_minimal(self):
        self.assertEqual(fix_mod.normalize_strategy("fixed"), "minimal")
        self.assertEqual(fix_mod.normalize_strategy("latest"), "latest")

    def test_strategy_label(self):
        self.assertEqual(fix_mod.strategy_label("minimal"), "升级到已修复版本")
        self.assertEqual(fix_mod.strategy_label("latest"), "升级到最新版本")


if __name__ == "__main__":
    unittest.main()
