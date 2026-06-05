import json
import os
import subprocess
import tempfile
import unittest

from butian.scripts import scan


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
                handle.write(
                    'OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n'
                )

            findings = scan.scan_secrets(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], ".env.local")
            self.assertEqual(findings[0]["type"], "openai_key")

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


if __name__ == "__main__":
    unittest.main()
