"""Tests for realistic demo projects used for manual report review."""

import importlib.util
import os
import re
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO_DIR = os.path.join(ROOT, "tests", "demo")
PROJECTS_DIR = os.path.join(DEMO_DIR, "projects")
RUNNER_PATH = os.path.join(DEMO_DIR, "run_demo_audits.py")

EXPECTED_PROJECTS = {
    "dart",
    "dotnet",
    "elixir",
    "go",
    "javascript",
    "maven",
    "php",
    "python",
    "ruby",
    "rust",
}

BLOCKED_SECRET_SNIPPETS = (
    "AKIA",
    "ASIA",
    "sk-live",
    "sk_live",
    "sk-proj",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "-----BEGIN",
)


def load_demo_runner():
    spec = importlib.util.spec_from_file_location("demo_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DemoFixtureTests(unittest.TestCase):
    def test_demo_projects_cover_supported_ecosystems(self):
        projects = {
            name
            for name in os.listdir(PROJECTS_DIR)
            if os.path.isdir(os.path.join(PROJECTS_DIR, name))
        }
        self.assertEqual(projects, EXPECTED_PROJECTS)

    def test_demo_projects_ignore_runtime_workspace(self):
        for project in EXPECTED_PROJECTS:
            with self.subTest(project=project):
                gitignore_path = os.path.join(PROJECTS_DIR, project, ".gitignore")
                with open(gitignore_path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                self.assertIn(".butian/", text)
                self.assertIn("docs/butian/security-report-*.md", text)

    def test_runner_writes_only_markdown_and_html_to_docs(self):
        with open(RUNNER_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        self.assertIn("security-report.md", text)
        self.assertIn("security-report.html", text)
        self.assertIn("--final-report", text)
        self.assertIn("--no-open", text)
        self.assertIn("--no-root-discovery", text)
        self.assertNotIn("docs/analysis.json", text)
        self.assertNotIn("analysis.json\")", text)

    def test_runner_removes_previous_stable_reports_before_scan(self):
        runner = load_demo_runner()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            docs_dir = project / "docs"
            docs_dir.mkdir()
            (project / ".butian").mkdir()
            (docs_dir / "butian").mkdir()
            (docs_dir / "security-report.md").write_text("old markdown")
            (docs_dir / "security-report.html").write_text("old html")
            (docs_dir / "keep.md").write_text("keep")

            runner.reset_runtime(project)

            self.assertFalse((project / ".butian").exists())
            self.assertFalse((docs_dir / "butian").exists())
            self.assertFalse((docs_dir / "security-report.md").exists())
            self.assertFalse((docs_dir / "security-report.html").exists())
            self.assertTrue((docs_dir / "keep.md").exists())

    def test_demo_fixtures_use_safe_fake_secret_values(self):
        all_text = []
        for root, _dirs, files in os.walk(DEMO_DIR):
            for filename in files:
                path = os.path.join(root, filename)
                if filename.endswith((".pyc", ".png", ".jpg", ".jpeg", ".gif")):
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    all_text.append(handle.read())
        text = "\n".join(all_text)

        self.assertIn("demo_password_for_report", text)
        self.assertIn("demo_api_key_for_report", text)
        for snippet in BLOCKED_SECRET_SNIPPETS:
            self.assertNotIn(snippet, text)

    def test_demo_docs_do_not_contain_analysis_json(self):
        for project in EXPECTED_PROJECTS:
            docs_dir = os.path.join(PROJECTS_DIR, project, "docs")
            with self.subTest(project=project):
                if not os.path.isdir(docs_dir):
                    continue
                names = set(os.listdir(docs_dir))
                self.assertNotIn("analysis.json", names)
                self.assertFalse(
                    any(re.fullmatch(r".*analysis.*\.json", name) for name in names)
                )
