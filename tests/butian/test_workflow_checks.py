import os
import tempfile
import unittest

from butian.scripts import workflow_checks


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


class WorkflowChecksTests(unittest.TestCase):
    def test_ignores_major_version_action_tags(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "ci.yml"),
                "on: [push]\npermissions: contents: read\njobs:\n  test:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: docker/setup-buildx-action@v3\n",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertEqual([], findings)

    def test_ignores_full_sha_action_refs(self):
        sha = "a" * 40
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "ci.yml"),
                "on: [push]\npermissions: contents: read\njobs:\n  test:\n"
                f"    steps:\n      - uses: actions/checkout@{sha}\n",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertEqual([], findings)

    def test_detects_overbroad_permissions(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "deploy.yml"),
                "on: [push]\npermissions: write-all\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertTrue(
                any(f["id"] == "actions.permissions_write_all" for f in findings)
            )

    def test_detects_missing_permissions_boundary(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "ci.yml"),
                "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            )

            findings = workflow_checks.scan_workflows(root)

            item = next(f for f in findings if f["id"] == "actions.missing_permissions")
            self.assertEqual(item["severity"], "low")
            self.assertIn("建议声明", item["title"])

    def test_detects_pull_request_target_checkout_risk(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "pr.yml"),
                """
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertTrue(
                any(f["id"] == "actions.risky_trigger_checkout" for f in findings)
            )
            self.assertTrue(
                any(f["id"] == "actions.checkout_persist_credentials" for f in findings)
            )

    def test_detects_untrusted_context_in_run(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "title.yml"),
                'on: [pull_request]\npermissions: contents: read\njobs:\n  t:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n',
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertTrue(
                any(f["id"] == "actions.untrusted_context_in_run" for f in findings)
            )

    def test_detects_untrusted_context_in_multiline_run_block(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "title.yml"),
                """on: [pull_request]
permissions: contents: read
jobs:
  t:
    steps:
      - run: |
          echo "title=${{ github.event.pull_request.title }}"
""",
            )

            findings = workflow_checks.scan_workflows(root)

            item = next(
                f for f in findings if f["id"] == "actions.untrusted_context_in_run"
            )
            self.assertEqual(item["line"], 7)
            self.assertIn("pull_request.title", item["evidence"])

    def test_detects_remote_script_pipe(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "install.yml"),
                "on: [push]\npermissions: contents: read\njobs:\n  t:\n    steps:\n      - run: curl https://example.com/install.sh | bash\n",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertTrue(
                any(f["id"] == "actions.remote_script_pipe" for f in findings)
            )

    def test_detects_self_hosted_runner_on_pr(self):
        with tempfile.TemporaryDirectory(prefix="butian-workflow-") as root:
            write(
                os.path.join(root, ".github", "workflows", "runner.yml"),
                "on: [pull_request]\npermissions: contents: read\njobs:\n  t:\n    runs-on: [self-hosted, linux]\n",
            )

            findings = workflow_checks.scan_workflows(root)

            self.assertTrue(
                any(f["id"] == "actions.self_hosted_pr_runner" for f in findings)
            )


if __name__ == "__main__":
    unittest.main()
