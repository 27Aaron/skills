"""Unit tests for butian/scripts/visualize.py — HTML report generation."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

from butian.scripts import visualize


# ---------------------------------------------------------------------------
# json_for_script
# ---------------------------------------------------------------------------
class JsonForScriptTests(unittest.TestCase):
    def test_compact_json(self):
        result = visualize.json_for_script({"a": 1, "b": "c"})
        self.assertNotIn(": ", result)
        self.assertNotIn(", ", result)

    def test_escapes_ampersand(self):
        result = visualize.json_for_script({"x": "a&b"})
        self.assertIn("\\u0026", result)
        self.assertNotIn("&", result.replace("\\u0026", ""))

    def test_escapes_lt_gt(self):
        result = visualize.json_for_script({"x": "<b>bold</b>"})
        self.assertIn("\\u003c", result)
        self.assertIn("\\u003e", result)

    def test_escapes_line_separator(self):
        result = visualize.json_for_script({"x": " "})
        self.assertIn("\\u2028", result)

    def test_escapes_paragraph_separator(self):
        result = visualize.json_for_script({"x": " "})
        self.assertIn("\\u2029", result)

    def test_preserves_unicode(self):
        result = visualize.json_for_script({"msg": "发现漏洞"})
        self.assertIn("发现漏洞", result)

    def test_list(self):
        result = visualize.json_for_script([1, 2, 3])
        parsed = json.loads(result)
        self.assertEqual(parsed, [1, 2, 3])


# ---------------------------------------------------------------------------
# script_asset_for_html
# ---------------------------------------------------------------------------
class ScriptAssetForHtmlTests(unittest.TestCase):
    def test_escapes_close_script(self):
        result = visualize.script_asset_for_html('var x = "</script>"')
        self.assertIn("<\\/script", result)
        self.assertNotIn("</script", result.replace("<\\/script", ""))

    def test_no_change_normal(self):
        text = "var x = 42;"
        self.assertEqual(visualize.script_asset_for_html(text), text)

    def test_report_js_describes_nested_locked_dependencies(self):
        script = visualize.read_text(visualize.REPORT_JS)
        self.assertIn("dependencyContextText", script)
        self.assertIn("被父依赖锁定的嵌套副本", script)
        self.assertIn("if (context) return esc(context);", script)


# ---------------------------------------------------------------------------
# style_asset_for_html
# ---------------------------------------------------------------------------
class StyleAssetForHtmlTests(unittest.TestCase):
    def test_escapes_close_style(self):
        result = visualize.style_asset_for_html("body {} </style>")
        self.assertIn("<\\/style", result)

    def test_no_change_normal(self):
        text = "body { color: red; }"
        self.assertEqual(visualize.style_asset_for_html(text), text)


# ---------------------------------------------------------------------------
# should_open_report
# ---------------------------------------------------------------------------
class ShouldOpenReportTests(unittest.TestCase):
    def test_default_opens(self):
        args = SimpleNamespace(no_open=False)
        self.assertTrue(visualize.should_open_report(args))

    def test_no_open_flag(self):
        args = SimpleNamespace(no_open=True)
        self.assertFalse(visualize.should_open_report(args))

    def test_env_var_true(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "true"
            args = SimpleNamespace(no_open=False)
            self.assertFalse(visualize.should_open_report(args))
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_env_var_1(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "1"
            args = SimpleNamespace(no_open=False)
            self.assertFalse(visualize.should_open_report(args))
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_env_var_yes(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "yes"
            args = SimpleNamespace(no_open=False)
            self.assertFalse(visualize.should_open_report(args))
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_env_var_empty_opens(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ.pop("BUTIAN_NO_OPEN", None)
            args = SimpleNamespace(no_open=False)
            self.assertTrue(visualize.should_open_report(args))
        finally:
            if original is not None:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_env_var_random_value_opens(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "random"
            args = SimpleNamespace(no_open=False)
            self.assertTrue(visualize.should_open_report(args))
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original


# ---------------------------------------------------------------------------
# default_output_path
# ---------------------------------------------------------------------------
class DefaultOutputPathTests(unittest.TestCase):
    def test_generates_html_under_content(self):
        with tempfile.TemporaryDirectory(prefix="butian-viz-") as root:
            # Create a structure like .butian/run/assets/analysis.json
            assets_dir = os.path.join(root, ".butian", "20260605-120000", "assets")
            os.makedirs(assets_dir)
            analysis_path = os.path.join(assets_dir, "analysis.json")
            with open(analysis_path, "w") as f:
                f.write("{}")
            result = visualize.default_output_path(analysis_path)
            self.assertTrue(result.endswith("security-report.html"))
            self.assertIn("content", result)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class ParseArgsTests(unittest.TestCase):
    def test_required_only(self):
        args = visualize.parse_args(["analysis.json"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertIsNone(args.output_html)
        self.assertFalse(args.no_open)

    def test_with_output(self):
        args = visualize.parse_args(["analysis.json", "report.html"])
        self.assertEqual(args.output_html, "report.html")

    def test_no_open_flag(self):
        args = visualize.parse_args(["--no-open", "analysis.json"])
        self.assertTrue(args.no_open)


# ---------------------------------------------------------------------------
# read_text
# ---------------------------------------------------------------------------
class ReadTextTests(unittest.TestCase):
    def test_reads_file(self):
        with tempfile.NamedTemporaryFile(
            prefix="butian-read-", suffix=".txt", mode="w", delete=False
        ) as f:
            f.write("hello world")
            path = f.name
        try:
            self.assertEqual(visualize.read_text(path), "hello world")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# pipeline: --help
# ---------------------------------------------------------------------------
class PipelineHelpTests(unittest.TestCase):
    def test_visualize_help(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        result = subprocess.run(
            [
                sys.executable,
                os.path.join("butian", "scripts", "visualize.py"),
                "--help",
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
