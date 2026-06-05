"""Tests for baseline (known-issue suppression) in scan.py."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import scan


class FingerprintTests(unittest.TestCase):
    def test_vulnerability_fingerprint(self):
        vuln = {
            "ecosystem": "npm",
            "package": "lodash",
            "version": "4.17.20",
            "advisory_id": "GHSA-jjhx-jh4p-89rf",
        }
        fp = scan.vulnerability_fingerprint(vuln)
        self.assertIn("vuln__", fp)
        self.assertIn("npm", fp)
        self.assertIn("lodash", fp)
        self.assertIn("GHSA", fp)

    def test_vulnerability_fingerprint_cve_fallback(self):
        vuln = {
            "ecosystem": "npm",
            "package": "pkg",
            "version": "1.0",
            "cve_id": "CVE-2024-1234",
        }
        fp = scan.vulnerability_fingerprint(vuln)
        self.assertIn("CVE-2024-1234", fp)

    def test_secret_fingerprint(self):
        secret = {"file": "config.py", "line": 42, "type": "aws_access_key"}
        fp = scan.secret_fingerprint(secret)
        self.assertEqual(fp, "secret__config.py__42__aws_access_key")

    def test_sensitive_file_fingerprint(self):
        item = {"file": ".env", "type": "env_file"}
        fp = scan.sensitive_file_fingerprint(item)
        self.assertEqual(fp, "sensitive__.env__env_file")

    def test_fingerprint_stability(self):
        vuln = {
            "ecosystem": "npm",
            "package": "Pkg",
            "version": "1.0",
            "advisory_id": "GHSA-x",
        }
        fp1 = scan.vulnerability_fingerprint(vuln)
        fp2 = scan.vulnerability_fingerprint(vuln)
        self.assertEqual(fp1, fp2)


class LoadBaselineTests(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory(prefix="butian-bl-") as tmp:
            fps = scan.load_baseline(tmp)
            self.assertEqual(fps, set())

    def test_loads_valid_baseline(self):
        with tempfile.TemporaryDirectory(prefix="butian-bl-") as tmp:
            baseline = {
                "version": 1,
                "entries": [
                    {"fingerprint": "vuln__npm__pkg__1.0__GHSA-x"},
                    {"fingerprint": "secret__config.py__42__aws"},
                ],
            }
            path = os.path.join(tmp, ".butian-baseline.json")
            with open(path, "w") as f:
                json.dump(baseline, f)

            fps = scan.load_baseline(tmp)
            self.assertEqual(len(fps), 2)
            self.assertIn("vuln__npm__pkg__1.0__GHSA-x", fps)

    def test_invalid_json_returns_empty(self):
        with tempfile.TemporaryDirectory(prefix="butian-bl-") as tmp:
            path = os.path.join(tmp, ".butian-baseline.json")
            with open(path, "w") as f:
                f.write("not json")
            fps = scan.load_baseline(tmp)
            self.assertEqual(fps, set())


class FilterBaselineTests(unittest.TestCase):
    def test_empty_baseline_returns_all(self):
        items = [
            {
                "package": "pkg",
                "version": "1.0",
                "ecosystem": "npm",
                "advisory_id": "GHSA-x",
            }
        ]
        result = scan.filter_with_baseline(items, set(), scan.vulnerability_fingerprint)
        self.assertEqual(len(result), 1)

    def test_matching_items_filtered(self):
        items = [
            {
                "package": "pkg",
                "version": "1.0",
                "ecosystem": "npm",
                "advisory_id": "GHSA-x",
            },
            {
                "package": "other",
                "version": "2.0",
                "ecosystem": "npm",
                "advisory_id": "GHSA-y",
            },
        ]
        fps = {scan.vulnerability_fingerprint(items[0])}
        result = scan.filter_with_baseline(items, fps, scan.vulnerability_fingerprint)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["package"], "other")

    def test_all_filtered(self):
        items = [
            {
                "package": "pkg",
                "version": "1.0",
                "ecosystem": "npm",
                "advisory_id": "GHSA-x",
            }
        ]
        fps = {scan.vulnerability_fingerprint(items[0])}
        result = scan.filter_with_baseline(items, fps, scan.vulnerability_fingerprint)
        self.assertEqual(len(result), 0)


class GenerateBaselineTests(unittest.TestCase):
    def test_generates_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-bl-") as tmp:
            scan_output = {
                "vulnerabilities": [
                    {
                        "package": "pkg",
                        "version": "1.0",
                        "ecosystem": "npm",
                        "advisory_id": "GHSA-x",
                    }
                ],
                "hygiene": {
                    "tracked_secrets": [{"file": "cfg.py", "line": 1, "type": "aws"}],
                    "sensitive_tracked": [],
                },
            }
            path = scan.generate_baseline(scan_output, tmp, reason="test")
            self.assertTrue(os.path.isfile(path))
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["version"], 1)
            self.assertEqual(len(data["entries"]), 2)
            self.assertEqual(data["entries"][0]["reason"], "test")


if __name__ == "__main__":
    unittest.main()
