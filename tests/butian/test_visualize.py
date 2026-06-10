"""Unit tests for butian/scripts/visualize.py - HTML report generation."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

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
        self.assertIn("semverSatisfies", script)
        self.assertIn("parent_range", script)


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
    def test_default_does_not_open(self):
        args = SimpleNamespace(no_open=False)
        self.assertFalse(visualize.should_open_report(args))

    def test_force_open_opens(self):
        args = SimpleNamespace(no_open=False, force_open=True)
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

    def test_env_var_empty_still_defaults_to_no_open(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ.pop("BUTIAN_NO_OPEN", None)
            args = SimpleNamespace(no_open=False)
            self.assertFalse(visualize.should_open_report(args))
        finally:
            if original is not None:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_env_var_random_value_still_defaults_to_no_open(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "random"
            args = SimpleNamespace(no_open=False)
            self.assertFalse(visualize.should_open_report(args))
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original

    def test_open_decision_reports_no_open_flag_reason(self):
        args = SimpleNamespace(no_open=True)
        should_open, reason = visualize.open_decision(args)
        self.assertFalse(should_open)
        self.assertEqual(reason, "no_open")

    def test_open_decision_reports_environment_reason(self):
        original = os.environ.get("BUTIAN_NO_OPEN")
        try:
            os.environ["BUTIAN_NO_OPEN"] = "true"
            args = SimpleNamespace(no_open=False)
            should_open, reason = visualize.open_decision(args)
        finally:
            if original is None:
                os.environ.pop("BUTIAN_NO_OPEN", None)
            else:
                os.environ["BUTIAN_NO_OPEN"] = original
        self.assertFalse(should_open)
        self.assertEqual(reason, "environment")

    def test_open_decision_defaults_to_no_open(self):
        args = SimpleNamespace(no_open=False, force_open=False)
        should_open, reason = visualize.open_decision(args, "report.html")

        self.assertFalse(should_open)
        self.assertEqual(reason, "default")

    def test_force_open_explicitly_opens(self):
        args = SimpleNamespace(no_open=False, force_open=True)
        should_open, reason = visualize.open_decision(args, "report.html")

        self.assertTrue(should_open)
        self.assertEqual(reason, "open")

    def test_no_open_still_overrides_force_open(self):
        args = SimpleNamespace(no_open=True, force_open=True)
        should_open, reason = visualize.open_decision(args)
        self.assertFalse(should_open)
        self.assertEqual(reason, "no_open")


class NoAutomaticOpenTests(unittest.TestCase):
    def test_main_does_not_call_open_report_without_force_open(self):
        with tempfile.TemporaryDirectory(prefix="butian-viz-") as root:
            analysis_path = os.path.join(
                root, ".butian", "20260605-120000", "assets", "analysis.json"
            )
            output_path = os.path.join(
                root, "docs", "butian", "2026-0605", "security-report.html"
            )
            os.makedirs(os.path.dirname(analysis_path))
            with open(analysis_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "project": {"name": "demo", "path": root},
                        "summary": {"tldr": "demo", "detail": "demo"},
                        "hygiene": {},
                    },
                    handle,
                )

            with (
                mock.patch.object(
                    sys, "argv", ["visualize.py", analysis_path, output_path]
                ),
                mock.patch.object(visualize, "open_report") as open_report,
                mock.patch.dict(os.environ, {"BUTIAN_NO_OPEN": ""}),
            ):
                visualize.main()

            open_report.assert_not_called()
            self.assertTrue(os.path.isfile(output_path))


# ---------------------------------------------------------------------------
# default_output_path
# ---------------------------------------------------------------------------
class DefaultOutputPathTests(unittest.TestCase):
    def test_generates_html_under_dated_docs_dir(self):
        with tempfile.TemporaryDirectory(prefix="butian-viz-") as root:
            # Create a structure like .butian/run/assets/analysis.json
            assets_dir = os.path.join(root, ".butian", "20260605-120000", "assets")
            os.makedirs(assets_dir)
            analysis_path = os.path.join(assets_dir, "analysis.json")
            with open(analysis_path, "w") as f:
                json.dump(
                    {
                        "project": {"path": root},
                        "butian_workspace": {
                            "run_dir": os.path.join(
                                root, ".butian", "20260605-120000"
                            )
                        },
                    },
                    f,
                )
            result = visualize.default_output_path(analysis_path)
            self.assertTrue(
                result.endswith("docs/butian/2026-0605/security-report.html")
            )
            self.assertNotIn("content", result)


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

    def test_force_open_flag(self):
        args = visualize.parse_args(["--force-open", "analysis.json"])
        self.assertTrue(args.force_open)


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

    def test_visualize_injects_shared_type_labels(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        with tempfile.TemporaryDirectory(prefix="butian-viz-") as temp_dir:
            analysis_path = os.path.join(
                temp_dir, ".butian", "20260605-1200", "assets", "analysis.json"
            )
            output_path = os.path.join(
                temp_dir, "docs", "butian", "2026-0605", "security-report.html"
            )
            os.makedirs(os.path.dirname(analysis_path))
            with open(analysis_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "project": {"name": "demo", "path": temp_dir},
                        "summary": {"tldr": "demo", "detail": "demo"},
                        "hygiene": {
                            "tracked_secrets": [
                                {
                                    "file": "app.py",
                                    "line": 1,
                                    "type": "openai_key",
                                    "preview": "sk-***",
                                }
                            ]
                        },
                    },
                    handle,
                )

            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join("butian", "scripts", "visualize.py"),
                    "--no-open",
                    analysis_path,
                    output_path,
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            with open(output_path, "r", encoding="utf-8") as handle:
                html = handle.read()
            self.assertIn("OpenAI API Key", html)
            self.assertNotIn("__SECRET_TYPE_LABELS__", html)
            self.assertNotIn("__SENSITIVE_TYPE_LABELS__", html)


if __name__ == "__main__":
    unittest.main()
