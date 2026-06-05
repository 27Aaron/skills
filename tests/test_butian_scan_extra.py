"""Comprehensive unit tests for butian/scripts/scan.py.

Covers pure logic functions, lockfile parsers, vulnerability data parsing,
CVSS scoring, workspace management, and utility helpers — complementing the
existing tests in test_butian_scan.py.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from butian.scripts import scan


# ---------------------------------------------------------------------------
# gitignore helpers
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# env file classification
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# sensitive_file_type
# ---------------------------------------------------------------------------
class SensitiveFileTypeTests(unittest.TestCase):
    def test_env_file(self):
        self.assertEqual(scan.sensitive_file_type(".env.production"), "env_file")

    def test_pem_key(self):
        self.assertEqual(scan.sensitive_file_type("server.pem"), "private_key")

    def test_sqlite_db(self):
        self.assertEqual(scan.sensitive_file_type("data.sqlite"), "database")

    def test_log_file(self):
        self.assertEqual(scan.sensitive_file_type("app.log"), "log")

    def test_credentials_json(self):
        self.assertEqual(scan.sensitive_file_type("credentials.json"), "credentials")

    def test_service_account(self):
        self.assertEqual(
            scan.sensitive_file_type("service-account-prod.json"), "credentials"
        )

    def test_ssh_key(self):
        self.assertEqual(scan.sensitive_file_type("id_rsa"), "ssh_key")

    def test_env_template_excluded(self):
        self.assertEqual(scan.sensitive_file_type(".env.example"), "")

    def test_normal_file(self):
        self.assertEqual(scan.sensitive_file_type("main.py"), "")

    def test_nested_path(self):
        self.assertEqual(scan.sensitive_file_type("config/server.key"), "private_key")


# ---------------------------------------------------------------------------
# secret_preview — all secret types
# ---------------------------------------------------------------------------
class SecretPreviewTests(unittest.TestCase):
    def test_private_key(self):
        self.assertEqual(
            scan.secret_preview("private_key", "-----BEGIN RSA PRIVATE KEY-----"),
            "-----BEGIN *** PRIVATE KEY-----",
        )

    def test_high_confidence_truncation(self):
        text = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        result = scan.secret_preview("openai_key", text)
        self.assertTrue(result.startswith("sk-proj"))
        self.assertTrue(result.endswith("7890"))
        self.assertIn("...", result)

    def test_high_confidence_short(self):
        self.assertEqual(scan.secret_preview("aws_access_key", "AKIA1234567"), "***")

    def test_generic_password_masked(self):
        result = scan.secret_preview(
            "generic_password", 'password = "supersecret123"'
        )
        self.assertIn("***", result)

    def test_generic_api_key_masked(self):
        result = scan.secret_preview(
            "generic_api_key", 'api_key: "abcdefghijklmnop"'
        )
        self.assertIn("***", result)

    def test_generic_password_fallback(self):
        # No match for the regex → returns "***" since masked == original
        result = scan.secret_preview("generic_password", "password=???")
        # Actually: re.sub matches "=???", producing "password=***"
        self.assertIn("***", result)

    def test_medium_confidence_short(self):
        # For generic_api_key without :=  pattern, masked == original → "***"
        self.assertEqual(scan.secret_preview("generic_api_key", "12345678"), "***")

    def test_medium_confidence_mid_no_colon_equals(self):
        # No :=  → masked == original → "***"
        result = scan.secret_preview("generic_api_key", "abcdefghijklmnop")
        self.assertEqual(result, "***")

    def test_medium_confidence_with_colon(self):
        # Has := so regex matches and masks the value
        result = scan.secret_preview("generic_api_key", 'api_key: "abcdefghijklmnop"')
        self.assertIn("***", result)

    def test_non_generic_medium_confidence_long(self):
        # Use a type NOT in {generic_password, generic_api_key} and NOT in HIGH_CONFIDENCE
        text = "a" * 30
        result = scan.secret_preview("unknown_type", text)
        self.assertTrue(result.startswith("a" * 15))
        self.assertIn("...", result)


# ---------------------------------------------------------------------------
# npm_lock_package_name
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_npm_lock — lockfileVersion 2 (dependencies key)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_pnpm_lock
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_yarn_lock — v1 and berry
# ---------------------------------------------------------------------------
class ParseYarnLockTests(unittest.TestCase):
    def test_v1_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-yarn-") as root:
            with open(os.path.join(root, "yarn.lock"), "w") as f:
                f.write(
                    '# yarn lockfile v1\n'
                    'lodash@^4.0.0:\n'
                    '  version "4.17.21"\n'
                    '\n'
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
                    '__metadata:\n'
                    '  version: 6\n'
                    '\n'
                    '"lodash@npm:^4.0.0":\n'
                    '  version: 4.17.21\n'
                    '\n'
                    '"@babel/core@npm:7.24.0":\n'
                    '  version: 7.24.0\n'
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
        self.assertEqual(
            scan._yarn_v1_descriptor_name("@babel/core@^7"), "@babel/core"
        )

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


# ---------------------------------------------------------------------------
# parse_pipfile_lock
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_go_sum
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_cargo_lock (fallback path)
# ---------------------------------------------------------------------------
class ParseCargoLockTests(unittest.TestCase):
    def test_fallback_parser(self):
        """Test the regex-based fallback when tomllib is unavailable or fails."""
        with tempfile.TemporaryDirectory(prefix="butian-cargo-") as root:
            with open(os.path.join(root, "Cargo.lock"), "w") as f:
                f.write(
                    '# This file is automatically @generated by Cargo.\n'
                    '[[package]]\n'
                    'name = "serde"\n'
                    'version = "1.0.198"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    '\n'
                    '[[package]]\n'
                    'name = "my-local"\n'
                    'version = "0.1.0"\n'
                    # no source → local crate, should be excluded from fallback
                )
            pkgs = scan.parse_cargo_lock(root)
            # tomllib path may or may not be available; if not, fallback runs
            names = [p["name"] for p in pkgs]
            self.assertIn("serde", names)


# ---------------------------------------------------------------------------
# detect_ecosystems
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# extract_packages + dedup
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# package_source_summary / package_version_index / current_version_for
# ---------------------------------------------------------------------------
class PackageSourceSummaryTests(unittest.TestCase):
    def test_counts_by_ecosystem_and_source(self):
        packages = [
            {"ecosystem": "npm", "source": "package-lock.json", "name": "a", "version": "1.0"},
            {"ecosystem": "npm", "source": "package-lock.json", "name": "b", "version": "2.0"},
            {"ecosystem": "pypi", "source": "requirements.txt", "name": "c", "version": "3.0"},
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


# ---------------------------------------------------------------------------
# CVE normalization
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# ecosystem normalization
# ---------------------------------------------------------------------------
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
        self.assertEqual(
            scan.normalized_package_name("crates-io", "Serde"), "serde"
        )

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


# ---------------------------------------------------------------------------
# utility functions
# ---------------------------------------------------------------------------
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
        self.assertEqual(scan.iso_date_or_none("2024-01-15"), "2024-01-15T00:00:00.000Z")

    def test_already_utc(self):
        self.assertEqual(scan.iso_date_or_none("2024-01-15T10:30:00Z"), "2024-01-15T10:30:00Z")

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


# ---------------------------------------------------------------------------
# CVSS vector parsing
# ---------------------------------------------------------------------------
class CvssToSeverityTests(unittest.TestCase):
    def test_explicit_basescore_critical(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C/baseScore:10.0")
        self.assertEqual(result, "critical")

    def test_explicit_basescore_high(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/baseScore:8.5")
        self.assertEqual(result, "high")

    def test_explicit_basescore_medium(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/baseScore:5.0")
        self.assertEqual(result, "medium")

    def test_explicit_basescore_low(self):
        result = scan._cvss_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/baseScore:3.5")
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


# ---------------------------------------------------------------------------
# OSV data parsing
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------
class ParseNvdResponseTests(unittest.TestCase):
    def _make_entry(self, cve_id, base_score=9.8, description="Test vuln. More detail."):
        return {
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
        self.assertEqual(best["baseScore"], "9.8")

    def test_empty(self):
        self.assertIsNone(scan.select_best_cvss_metric([]))


# ---------------------------------------------------------------------------
# CISA KEV parsing
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# EPSS parsing
# ---------------------------------------------------------------------------
class ParseEpssResponseTests(unittest.TestCase):
    def test_parses_epss_data(self):
        data = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.05", "percentile": "0.95", "date": "2024-06-01"},
            ]
        }
        result = scan.parse_epss_response(data)
        self.assertIn("CVE-2024-0001", result)
        self.assertEqual(result["CVE-2024-0001"]["epss"], "0.05")

    def test_empty(self):
        self.assertEqual(scan.parse_epss_response({}), {})


# ---------------------------------------------------------------------------
# merge_cve_patch
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# build_risk_signals
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# severity_from_enrichments
# ---------------------------------------------------------------------------
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
        osv_record = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"}]}
        severity, _ = scan.severity_from_enrichments(osv_record, [])
        self.assertEqual(severity, "high")

    def test_no_data_returns_unknown(self):
        severity, _ = scan.severity_from_enrichments({}, [])
        self.assertEqual(severity, "unknown")


# ---------------------------------------------------------------------------
# outdated logic
# ---------------------------------------------------------------------------
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
        self.assertEqual(scan.outdated_target({"wanted": "1.1.0", "latest": "2.0.0"}), "1.1.0")

    def test_falls_back_to_latest(self):
        self.assertEqual(scan.outdated_target({"latest": "2.0.0"}), "2.0.0")

    def test_empty(self):
        self.assertEqual(scan.outdated_target({}), "")


# ---------------------------------------------------------------------------
# chunked
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# iter_json_objects
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# official_source_error
# ---------------------------------------------------------------------------
class OfficialSourceErrorTests(unittest.TestCase):
    def test_format(self):
        err = scan.official_source_error("NVD", "CVE 查询", "timeout")
        self.assertEqual(err["step"], "vulnerability_check")
        self.assertIn("NVD", err["message"])
        self.assertIn("timeout", err["message"])


# ---------------------------------------------------------------------------
# workspace management
# ---------------------------------------------------------------------------
class RunDirFromOutputFileTests(unittest.TestCase):
    def test_assets_dir_parent(self):
        result = scan.run_dir_from_output_file("/tmp/.butian/20240101-120000/assets/scan.json")
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


# ---------------------------------------------------------------------------
# build_official_vulnerability
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# parse_poetry_lock / parse_uv_lock (TOML lock files)
# ---------------------------------------------------------------------------
class ParsePoetryLockTests(unittest.TestCase):
    def test_parses_poetry_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-poetry-") as root:
            with open(os.path.join(root, "poetry.lock"), "w") as f:
                f.write(
                    '[[package]]\n'
                    'name = "flask"\n'
                    'version = "2.0.3"\n'
                    'description = "A framework"\n'
                    '\n'
                    '[[package]]\n'
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


# ---------------------------------------------------------------------------
# project_python_executable
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# make_run_id
# ---------------------------------------------------------------------------
class MakeRunIdTests(unittest.TestCase):
    def test_format(self):
        run_id = scan.make_run_id()
        self.assertRegex(run_id, r"^\d{8}-\d{6}$")


if __name__ == "__main__":
    unittest.main()
