"""Detailed unit tests for butian/scripts/finding_utils.py."""

import os
import tempfile
import unittest

from butian.scripts import finding_utils


def write(path, content, *, mode="w"):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, mode, encoding=None if "b" in mode else "utf-8") as handle:
        handle.write(content)


class RelpathTests(unittest.TestCase):
    def test_returns_relative_path_inside_project(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "src", "app.py")
            os.makedirs(os.path.dirname(path))
            self.assertEqual(
                finding_utils.relpath(path, root), os.path.join("src", "app.py")
            )

    def test_returns_original_path_when_relpath_raises_value_error(self):
        original_relpath = finding_utils.os.path.relpath
        try:
            finding_utils.os.path.relpath = lambda *_args, **_kwargs: (
                _ for _ in ()
            ).throw(ValueError("different drives"))
            self.assertEqual(
                finding_utils.relpath("C:\\repo\\a.py", "D:\\repo"), "C:\\repo\\a.py"
            )
        finally:
            finding_utils.os.path.relpath = original_relpath


class ReadTextTests(unittest.TestCase):
    def test_reads_utf8_text(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "a.txt")
            write(path, "hello\n扫描\n")
            self.assertEqual(finding_utils.read_text(path), "hello\n扫描\n")

    def test_returns_empty_for_missing_file(self):
        self.assertEqual(finding_utils.read_text("/not/a/real/file"), "")

    def test_returns_empty_when_file_exceeds_max_bytes(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "large.txt")
            write(path, "abcdef")
            self.assertEqual(finding_utils.read_text(path, max_bytes=3), "")

    def test_ignores_invalid_utf8_bytes(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "bad.txt")
            write(path, b"ok\xffdone", mode="wb")
            self.assertEqual(finding_utils.read_text(path), "okdone")

    def test_returns_empty_for_symlinked_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as parent:
            outside = os.path.join(parent, "outside.txt")
            link = os.path.join(parent, "project-link.txt")
            write(outside, "outside")
            try:
                os.symlink(outside, link)
            except (AttributeError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            self.assertEqual(finding_utils.read_text(link), "")


class IterFilesTests(unittest.TestCase):
    def test_iterates_files_with_suffix_filter(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            write(os.path.join(root, "a.py"), "a")
            write(os.path.join(root, "b.txt"), "b")
            write(os.path.join(root, "nested", "c.PY"), "c")

            result = sorted(
                os.path.relpath(p, root)
                for p in finding_utils.iter_files(root, suffixes=[".py"])
            )

            self.assertEqual(result, ["a.py", os.path.join("nested", "c.PY")])

    def test_iterates_files_with_name_filter(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            write(os.path.join(root, "Dockerfile"), "FROM python\n")
            write(os.path.join(root, "dockerfile.prod"), "FROM python\n")
            write(os.path.join(root, "README.md"), "doc\n")

            result = sorted(
                os.path.basename(p)
                for p in finding_utils.iter_files(root, names=["dockerfile"])
            )

            self.assertEqual(result, ["Dockerfile"])

    def test_suffix_filter_allows_exact_name_matches(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            write(os.path.join(root, "Dockerfile"), "FROM python\n")
            write(os.path.join(root, "app.yml"), "name: app\n")
            write(os.path.join(root, "notes.txt"), "notes\n")

            result = sorted(
                os.path.basename(p)
                for p in finding_utils.iter_files(
                    root, suffixes=[".yml"], names=["dockerfile"]
                )
            )

            self.assertEqual(result, ["Dockerfile", "app.yml"])

    def test_excludes_default_heavy_directories(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            write(os.path.join(root, "node_modules", "pkg", "index.js"), "x")
            write(os.path.join(root, "src", "index.js"), "x")

            result = [
                os.path.relpath(p, root)
                for p in finding_utils.iter_files(root, suffixes=[".js"])
            ]

            self.assertEqual(result, [os.path.join("src", "index.js")])

    def test_custom_exclude_dirs_override_defaults(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            write(os.path.join(root, "node_modules", "pkg", "index.js"), "x")

            result = [
                os.path.relpath(p, root)
                for p in finding_utils.iter_files(
                    root, suffixes=[".js"], exclude_dirs=[]
                )
            ]

            self.assertEqual(result, [os.path.join("node_modules", "pkg", "index.js")])

    def test_stops_at_max_files(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            for index in range(5):
                write(os.path.join(root, f"{index}.txt"), str(index))

            result = list(
                finding_utils.iter_files(root, suffixes=[".txt"], max_files=2)
            )

            self.assertEqual(len(result), 2)

    def test_skips_symlinked_files_by_default(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as parent:
            project = os.path.join(parent, "project")
            os.makedirs(project)
            outside = os.path.join(parent, "outside.py")
            link = os.path.join(project, "linked.py")
            write(outside, "print('outside')\n")
            write(os.path.join(project, "inside.py"), "print('inside')\n")
            try:
                os.symlink(outside, link)
            except (AttributeError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            result = sorted(
                os.path.relpath(p, project)
                for p in finding_utils.iter_files(project, suffixes=[".py"])
            )

            self.assertEqual(result, ["inside.py"])


class LineForTextTests(unittest.TestCase):
    def test_returns_first_matching_line(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "a.txt")
            write(path, "one\ntwo\none\n")
            self.assertEqual(finding_utils.line_for_text(path, "one"), 1)
            self.assertEqual(finding_utils.line_for_text(path, "two"), 2)

    def test_returns_none_for_empty_needle_missing_file_or_missing_text(self):
        with tempfile.TemporaryDirectory(prefix="butian-findings-") as root:
            path = os.path.join(root, "a.txt")
            write(path, "one\n")
            self.assertIsNone(finding_utils.line_for_text(path, ""))
            self.assertIsNone(finding_utils.line_for_text(path, "missing"))
            self.assertIsNone(
                finding_utils.line_for_text(os.path.join(root, "missing.txt"), "one")
            )


class EvidenceSnippetTests(unittest.TestCase):
    def test_collapses_whitespace(self):
        self.assertEqual(finding_utils.evidence_snippet("  a\n\tb   c  "), "a b c")

    def test_truncates_to_max_len_with_ellipsis(self):
        result = finding_utils.evidence_snippet("abcdef", max_len=4)
        self.assertEqual(result, "a...")
        self.assertLessEqual(len(result), 4)

    def test_none_becomes_empty_string(self):
        self.assertEqual(finding_utils.evidence_snippet(None), "")


class MakeFindingTests(unittest.TestCase):
    def test_make_finding_normalizes_invalid_severity_and_confidence(self):
        finding = finding_utils.make_finding(
            "repo.example",
            category="repo_governance",
            severity="invalid",
            confidence="certain",
            file="example.yml",
            line=3,
            title="标题",
            detail="详情",
            evidence="证据",
            recommendation="建议",
            fixable=True,
            custom_value="kept",
            ignored_none=None,
        )

        self.assertEqual(finding["severity"], "info")
        self.assertEqual(finding["confidence"], "low")
        self.assertTrue(finding["fixable"])
        self.assertEqual(finding["custom_value"], "kept")
        self.assertNotIn("ignored_none", finding)

    def test_make_finding_uses_defaults(self):
        finding = finding_utils.make_finding(
            "repo.example",
            category="repo_governance",
            severity="medium",
            confidence="high",
            title="标题",
            detail="详情",
            recommendation="建议",
        )

        self.assertEqual(finding["file"], "")
        self.assertIsNone(finding["line"])
        self.assertEqual(finding["evidence"], "")
        self.assertEqual(finding["source"], "builtin")
        self.assertFalse(finding["fixable"])

    def test_make_finding_truncates_evidence(self):
        finding = finding_utils.make_finding(
            "repo.example",
            category="repo_governance",
            severity="medium",
            confidence="high",
            title="标题",
            detail="详情",
            evidence="x" * 220,
            recommendation="建议",
        )

        self.assertLessEqual(len(finding["evidence"]), 180)
        self.assertTrue(finding["evidence"].endswith("..."))


class DedupeFindingsTests(unittest.TestCase):
    def test_dedupes_by_id_file_line_and_evidence_preserving_order(self):
        first = {"id": "a", "file": "f", "line": 1, "evidence": "x", "title": "first"}
        duplicate = {
            "id": "a",
            "file": "f",
            "line": 1,
            "evidence": "x",
            "title": "duplicate",
        }
        second = {"id": "a", "file": "f", "line": 2, "evidence": "x", "title": "second"}

        result = finding_utils.dedupe_findings([first, duplicate, second])

        self.assertEqual(result, [first, second])

    def test_none_or_empty_returns_empty_list(self):
        self.assertEqual(finding_utils.dedupe_findings(None), [])
        self.assertEqual(finding_utils.dedupe_findings([]), [])


if __name__ == "__main__":
    unittest.main()
