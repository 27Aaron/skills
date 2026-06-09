import json
import os
import subprocess
import sys
import tempfile
import unittest

from butian.scripts import detect


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class ParseArgsTests(unittest.TestCase):
    def test_defaults_project_path_to_cwd(self):
        args = detect.parse_args([])
        self.assertEqual(args.project_path, ".")

    def test_custom_project_path(self):
        args = detect.parse_args(["/tmp/my-project"])
        self.assertEqual(args.project_path, "/tmp/my-project")

    def test_no_root_discovery_flag(self):
        args = detect.parse_args(["--no-root-discovery", "/tmp/x"])
        self.assertTrue(args.no_root_discovery)

    def test_no_root_discovery_defaults_false(self):
        args = detect.parse_args([])
        self.assertFalse(args.no_root_discovery)

    def test_output_flag(self):
        args = detect.parse_args(["--output", "/tmp/preflight.json"])
        self.assertEqual(args.output, "/tmp/preflight.json")

    def test_output_defaults_none(self):
        args = detect.parse_args([])
        self.assertIsNone(args.output)

    def test_compact_flag(self):
        args = detect.parse_args(["--compact"])
        self.assertTrue(args.compact)

    def test_compact_defaults_false(self):
        args = detect.parse_args([])
        self.assertFalse(args.compact)

    def test_all_flags_combined(self):
        args = detect.parse_args(
            [
                "--no-root-discovery",
                "--output",
                "/tmp/out.json",
                "--compact",
                "/some/path",
            ]
        )
        self.assertEqual(args.project_path, "/some/path")
        self.assertTrue(args.no_root_discovery)
        self.assertEqual(args.output, "/tmp/out.json")
        self.assertTrue(args.compact)


# ---------------------------------------------------------------------------
# default_output_path
# ---------------------------------------------------------------------------
class DefaultOutputPathTests(unittest.TestCase):
    def test_result_is_under_butian_assets_dir(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = detect.default_output_path(root)
            self.assertIn(".butian", result)
            self.assertIn("assets", result)

    def test_result_ends_with_preflight_json(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = detect.default_output_path(root)
            self.assertTrue(result.endswith("preflight.json"), result)


# ---------------------------------------------------------------------------
# detect_language_support
# ---------------------------------------------------------------------------
class DetectLanguageSupportTests(unittest.TestCase):
    def test_returns_unsupported_when_no_lockfiles(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = detect.detect_language_support(root)
            self.assertFalse(result["supported"])
            self.assertEqual(result["ecosystems"], [])
            self.assertEqual(result["matched_files"], [])

    def test_detects_npm_from_package_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                f.write("{}")
            result = detect.detect_language_support(root)
            self.assertTrue(result["supported"])
            self.assertIn("npm", result["ecosystems"])
            self.assertEqual(result["matched_files"][0]["ecosystem"], "npm")
            self.assertEqual(result["matched_files"][0]["file"], "package-lock.json")

    def test_detects_pypi_from_requirements_txt(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "requirements.txt"), "w") as f:
                f.write("flask==2.0\n")
            result = detect.detect_language_support(root)
            self.assertTrue(result["supported"])
            self.assertIn("pypi", result["ecosystems"])

    def test_detects_pypi_from_poetry_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "poetry.lock"), "w") as f:
                f.write("")
            result = detect.detect_language_support(root)
            self.assertIn("pypi", result["ecosystems"])
            # Should not appear twice even though pypi has multiple lockfiles
            self.assertEqual(result["ecosystems"].count("pypi"), 1)

    def test_detects_go_from_go_sum(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "go.sum"), "w") as f:
                f.write("")
            result = detect.detect_language_support(root)
            self.assertIn("go", result["ecosystems"])

    def test_detects_crates_io_from_cargo_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "Cargo.lock"), "w") as f:
                f.write("")
            result = detect.detect_language_support(root)
            self.assertIn("crates-io", result["ecosystems"])

    def test_detects_yarn_from_yarn_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "yarn.lock"), "w") as f:
                f.write("")
            result = detect.detect_language_support(root)
            self.assertIn("yarn", result["ecosystems"])

    def test_detects_pnpm_from_pnpm_lock(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "pnpm-lock.yaml"), "w") as f:
                f.write("")
            result = detect.detect_language_support(root)
            self.assertIn("pnpm", result["ecosystems"])

    def test_detects_expanded_language_ecosystems(self):
        cases = {
            "packagist": ["composer.lock"],
            "rubygems": ["Gemfile.lock"],
            "pub": ["pubspec.lock"],
            "hex": ["mix.lock"],
            "nuget": ["packages.lock.json", "packages.config"],
            "maven": ["pom.xml"],
        }
        for ecosystem, file_names in cases.items():
            for file_name in file_names:
                with self.subTest(ecosystem=ecosystem, file_name=file_name):
                    with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
                        with open(os.path.join(root, file_name), "w") as f:
                            f.write("")
                        result = detect.detect_language_support(root)
                        self.assertTrue(result["supported"])
                        self.assertIn(ecosystem, result["ecosystems"])
                        self.assertEqual(
                            result["matched_files"][0],
                            {"ecosystem": ecosystem, "file": file_name},
                        )

    def test_detects_all_expanded_ecosystems_together(self):
        files = [
            "composer.lock",
            "Gemfile.lock",
            "pubspec.lock",
            "mix.lock",
            "packages.lock.json",
            "pom.xml",
        ]
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            for file_name in files:
                with open(os.path.join(root, file_name), "w") as f:
                    f.write("")
            result = detect.detect_language_support(root)
            self.assertTrue(result["supported"])
            self.assertEqual(
                sorted(result["ecosystems"]),
                ["hex", "maven", "nuget", "packagist", "pub", "rubygems"],
            )
            self.assertEqual(len(result["matched_files"]), 6)

    def test_detects_multiple_ecosystems(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            for name in ["package-lock.json", "go.sum", "Cargo.lock"]:
                with open(os.path.join(root, name), "w") as f:
                    f.write("")
            result = detect.detect_language_support(root)
            self.assertEqual(
                sorted(result["ecosystems"]),
                ["crates-io", "go", "npm"],
            )
            self.assertEqual(len(result["matched_files"]), 3)

    def test_pypi_prefers_poetry_lock_over_requirements(self):
        """LOCKFILE_MAP lists poetry.lock first for pypi; first match wins."""
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            for name in ["poetry.lock", "requirements.txt"]:
                with open(os.path.join(root, name), "w") as f:
                    f.write("")
            result = detect.detect_language_support(root)
            self.assertEqual(result["matched_files"][0]["file"], "poetry.lock")

    def test_ignores_directories_named_like_lockfiles(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            os.makedirs(os.path.join(root, "package-lock.json"))
            result = detect.detect_language_support(root)
            self.assertFalse(result["supported"])


# ---------------------------------------------------------------------------
# build_preflight
# ---------------------------------------------------------------------------
class BuildPreflightTests(unittest.TestCase):
    def _make_args(self, **overrides):
        defaults = {
            "project_path": ".",
            "no_root_discovery": False,
            "output": None,
            "compact": False,
        }
        defaults.update(overrides)
        return type("Args", (), defaults)()

    def test_recommended_mode_is_full_scan_when_supported(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                f.write("{}")
            args = self._make_args()
            result = detect.build_preflight(root, args)
            self.assertEqual(result["recommended_scan_mode"], "full_dependency_scan")

    def test_recommended_mode_is_hygiene_only_when_unsupported(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            self.assertEqual(result["recommended_scan_mode"], "hygiene_only")

    def test_project_name_is_basename(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            self.assertEqual(result["project"]["name"], os.path.basename(root))
            self.assertEqual(result["project"]["path"], root)

    def test_generated_at_is_timestamp_format(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            # Should be YYYY-MM-DD HH:MM:SS
            self.assertRegex(
                result["generated_at"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
            )

    def test_output_file_uses_default_when_no_custom(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            self.assertTrue(result["output_file"].endswith("preflight.json"))

    def test_output_file_uses_custom_when_provided(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            custom = os.path.join(root, "custom-output.json")
            args = self._make_args(output=custom)
            result = detect.build_preflight(root, args)
            self.assertEqual(result["output_file"], custom)

    def test_workspace_dirs_are_under_run_dir(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            run_dir = result["butian_workspace"]["run_dir"]
            self.assertEqual(
                result["butian_workspace"]["assets_dir"],
                os.path.join(run_dir, "assets"),
            )
            self.assertEqual(
                result["butian_workspace"]["content_dir"],
                os.path.join(run_dir, "content"),
            )

    def test_butian_dir_is_created_on_disk(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            self.assertTrue(os.path.isdir(result["butian_workspace"]["run_dir"]))

    def test_gitignore_status_is_populated(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            gitignore = result["butian_workspace"]["gitignore"]
            self.assertIn("preexisting", gitignore)
            self.assertIn("added_butian_entry", gitignore)

    def test_preflight_creates_gitignore_for_workspace_dirs(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            args = self._make_args()
            result = detect.build_preflight(root, args)
            gitignore_path = os.path.join(root, ".gitignore")

            self.assertTrue(os.path.exists(gitignore_path))
            with open(gitignore_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            lines = content.splitlines()
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/security-report-*.md", lines)
            self.assertNotIn("docs/butian", lines)
            self.assertTrue(result["butian_workspace"]["gitignore"]["exists_after"])
            self.assertTrue(
                result["butian_workspace"]["gitignore"]["added_butian_entry"]
            )

    def test_preflight_appends_workspace_gitignore_rules(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            gitignore_path = os.path.join(root, ".gitignore")
            with open(gitignore_path, "w", encoding="utf-8") as handle:
                handle.write("node_modules/\n")
            args = self._make_args()
            result = detect.build_preflight(root, args)

            with open(gitignore_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            lines = content.splitlines()
            self.assertIn("node_modules/", content)
            self.assertIn(".butian/", lines)
            self.assertIn("docs/butian/security-report-*.md", lines)
            self.assertNotIn("docs/butian", lines)
            self.assertFalse(
                result["butian_workspace"]["gitignore"]["had_butian_entry"]
            )
            self.assertEqual(
                result["butian_workspace"]["gitignore"]["missing_entries"], []
            )


# ---------------------------------------------------------------------------
# main() — subprocess integration tests
# ---------------------------------------------------------------------------
class MainIntegrationTests(unittest.TestCase):
    @staticmethod
    def _project_root():
        return os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )

    def test_main_writes_json_to_stdout(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    "--compact",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            self.assertIn("generated_at", data)
            self.assertIn("project", data)
            self.assertIn("language_support", data)
            self.assertIn("recommended_scan_mode", data)
            self.assertIn("butian_workspace", data)

    def test_main_compact_output_is_single_line(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    "--compact",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            # Compact JSON: no newlines inside the JSON blob
            lines = result.stdout.strip().splitlines()
            self.assertEqual(len(lines), 1)

    def test_main_pretty_output_is_multiline(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            lines = result.stdout.strip().splitlines()
            self.assertGreater(len(lines), 5)

    def test_main_writes_preflight_json_on_disk(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    "--compact",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            output_file = data["output_file"]
            self.assertTrue(os.path.isfile(output_file))
            with open(output_file, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
            self.assertEqual(on_disk["project"]["path"], os.path.abspath(root))

    def test_main_with_custom_output_path(self):
        with (
            tempfile.TemporaryDirectory(prefix="butian-detect-") as root,
            tempfile.TemporaryDirectory(prefix="butian-detect-out-") as out_dir,
        ):
            output = os.path.join(out_dir, "custom.json")
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--compact",
                    "--output",
                    output,
                    "--no-root-discovery",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            self.assertEqual(data["output_file"], output)
            self.assertTrue(os.path.isfile(output))
            # .butian workspace should still be created under the project
            self.assertTrue(os.path.isdir(os.path.join(root, ".butian")))

    def test_main_detects_npm_project(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            with open(os.path.join(root, "package-lock.json"), "w") as f:
                f.write("{}")
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    "--compact",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            self.assertTrue(data["language_support"]["supported"])
            self.assertIn("npm", data["language_support"]["ecosystems"])
            self.assertEqual(data["recommended_scan_mode"], "full_dependency_scan")

    def test_main_unsupported_project_gets_hygiene_only(self):
        with tempfile.TemporaryDirectory(prefix="butian-detect-") as root:
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--no-root-discovery",
                    "--compact",
                    root,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            self.assertFalse(data["language_support"]["supported"])
            self.assertEqual(data["recommended_scan_mode"], "hygiene_only")

    def test_main_uses_find_project_root_without_flag(self):
        """Without --no-root-discovery, main() resolves via find_project_root."""
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
            with open(os.path.join(app, "package-lock.json"), "w") as f:
                json.dump({"lockfileVersion": 3, "packages": {}}, f)

            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "detect.py"),
                    "--compact",
                    app,
                ],
                cwd=self._project_root(),
                capture_output=True,
                text=True,
                check=True,
            )
            data = json.loads(result.stdout)
            # find_project_root should resolve to the nearest project marker
            self.assertEqual(data["project"]["path"], app)
            self.assertIn("npm", data["language_support"]["ecosystems"])


if __name__ == "__main__":
    unittest.main()
