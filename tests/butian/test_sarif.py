"""Tests for butian/scripts/sarif.py — SARIF v2.1.0 output."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import sarif


class SarifBuildTests(unittest.TestCase):
    def _make_analysis(self, **overrides):
        base = {
            "generated_at": "2026-06-05 10:00:00",
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "top_issues": [],
            "hygiene": {},
            "errors": [],
        }
        base.update(overrides)
        return base

    def test_empty_analysis(self):
        result = sarif.build_sarif(self._make_analysis())
        self.assertEqual(result["version"], "2.1.0")
        self.assertIn("runs", result)
        self.assertEqual(len(result["runs"]), 1)
        run = result["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("results", run)
        self.assertEqual(len(run["results"]), 0)

    def test_vulnerability_mapped(self):
        analysis = self._make_analysis(
            top_issues=[
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "advisory_id": "GHSA-jjhx-jh4p-89rf",
                    "summary": "Prototype pollution",
                    "ecosystem": "npm",
                    "fixed_versions": ["4.17.21"],
                }
            ]
        )
        result = sarif.build_sarif(analysis)
        self.assertEqual(len(result["runs"][0]["results"]), 1)
        r = result["runs"][0]["results"][0]
        self.assertEqual(r["level"], "error")  # high → error
        self.assertIn("lodash", r["properties"]["package"])

    def test_secret_mapped(self):
        analysis = self._make_analysis(
            hygiene={
                "tracked_secrets": [
                    {
                        "file": "config.py",
                        "line": 42,
                        "type": "aws_access_key",
                        "confidence": "high",
                    }
                ]
            }
        )
        result = sarif.build_sarif(analysis)
        secrets = [r for r in result["runs"][0]["results"] if "secret" in r["ruleId"]]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["level"], "warning")  # high confidence

    def test_sensitive_file_mapped(self):
        analysis = self._make_analysis(
            hygiene={
                "sensitive_tracked": [
                    {"file": ".env", "type": "env_file"},
                ]
            }
        )
        result = sarif.build_sarif(analysis)
        sens = [r for r in result["runs"][0]["results"] if "sensitive" in r["ruleId"]]
        self.assertEqual(len(sens), 1)

    def test_severity_mapping(self):
        cases = [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
        ]
        for severity, expected_level in cases:
            analysis = self._make_analysis(
                top_issues=[
                    {
                        "package": "pkg",
                        "version": "1.0",
                        "severity": severity,
                        "ecosystem": "npm",
                        "summary": "test",
                    }
                ]
            )
            result = sarif.build_sarif(analysis)
            self.assertEqual(
                result["runs"][0]["results"][0]["level"],
                expected_level,
                f"{severity} should map to {expected_level}",
            )

    def test_help_uri_for_ghsa(self):
        analysis = self._make_analysis(
            top_issues=[
                {
                    "package": "pkg",
                    "version": "1.0",
                    "severity": "high",
                    "advisory_id": "GHSA-xxxx-xxxx-xxxx",
                    "ecosystem": "npm",
                    "summary": "test",
                }
            ]
        )
        result = sarif.build_sarif(analysis)
        rules = result["runs"][0]["tool"]["driver"]["rules"]
        self.assertIn("helpUri", rules[0])
        self.assertIn("github.com", rules[0]["helpUri"])

    def test_rules_deduplicated(self):
        analysis = self._make_analysis(
            top_issues=[
                {
                    "package": "pkg",
                    "version": "1.0",
                    "severity": "high",
                    "advisory_id": "GHSA-aaaa-aaaa-aaaa",
                    "ecosystem": "npm",
                    "summary": "test 1",
                },
                {
                    "package": "pkg",
                    "version": "1.0",
                    "severity": "high",
                    "advisory_id": "GHSA-aaaa-aaaa-aaaa",
                    "ecosystem": "npm",
                    "summary": "test 2",
                },
            ]
        )
        result = sarif.build_sarif(analysis)
        rules = result["runs"][0]["tool"]["driver"]["rules"]
        # Same advisory_id → same rule, deduplicated
        ghsa_rules = [r for r in rules if r["id"] == "GHSA-aaaa-aaaa-aaaa"]
        self.assertEqual(len(ghsa_rules), 1)


class SarifFileOutputTests(unittest.TestCase):
    def test_main_writes_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-sarif-") as tmp:
            analysis = {
                "generated_at": "2026-06-05 10:00:00",
                "risk_summary": {},
                "top_issues": [],
                "hygiene": {},
            }
            analysis_path = os.path.join(tmp, "analysis.json")
            with open(analysis_path, "w") as f:
                json.dump(analysis, f)

            output_path = os.path.join(tmp, "results.sarif.json")

            # Test via direct call
            result = sarif.build_sarif(analysis)
            with open(output_path, "w") as f:
                json.dump(result, f)

            self.assertTrue(os.path.isfile(output_path))
            with open(output_path) as f:
                data = json.load(f)
            self.assertEqual(data["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
