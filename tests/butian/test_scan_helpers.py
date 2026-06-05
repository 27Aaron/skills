"""Tests for scan.py helper functions: logging, progress, exit codes, binary detection."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import scan


class IsBinaryFileTests(unittest.TestCase):
    def test_text_file_is_not_binary(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello')\n")
            f.flush()
            self.assertFalse(scan.is_binary_file(f.name))
            os.unlink(f.name)

    def test_binary_file_detected(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"hello\x00world")
            f.flush()
            self.assertTrue(scan.is_binary_file(f.name))
            os.unlink(f.name)

    def test_missing_file_is_binary(self):
        self.assertTrue(scan.is_binary_file("/nonexistent/file.txt"))


class EvaluateSeverityThresholdTests(unittest.TestCase):
    def _vuln(self, severity):
        return {"severity": severity}

    def test_no_threshold(self):
        should_fail, count = scan.evaluate_severity_threshold(
            [self._vuln("critical")], None
        )
        self.assertFalse(should_fail)
        self.assertEqual(count, 0)

    def test_below_threshold(self):
        should_fail, count = scan.evaluate_severity_threshold(
            [self._vuln("low")], "high"
        )
        self.assertFalse(should_fail)
        self.assertEqual(count, 0)

    def test_at_threshold(self):
        should_fail, count = scan.evaluate_severity_threshold(
            [self._vuln("high")], "high"
        )
        self.assertTrue(should_fail)
        self.assertEqual(count, 1)

    def test_above_threshold(self):
        should_fail, count = scan.evaluate_severity_threshold(
            [self._vuln("critical")], "high"
        )
        self.assertTrue(should_fail)
        self.assertEqual(count, 1)

    def test_multiple_vulns_count(self):
        vulns = [self._vuln("high"), self._vuln("critical"), self._vuln("low")]
        should_fail, count = scan.evaluate_severity_threshold(vulns, "high")
        self.assertTrue(should_fail)
        self.assertEqual(count, 2)

    def test_empty_list(self):
        should_fail, count = scan.evaluate_severity_threshold([], "critical")
        self.assertFalse(should_fail)
        self.assertEqual(count, 0)


class ProgressReporterTests(unittest.TestCase):
    def test_disabled_produces_no_output(self):
        reporter = scan.ProgressReporter(enabled=False)
        # These should be no-ops
        reporter.update("test")
        reporter.finish("test")
        reporter.step(1, 5, "test")

    def test_enabled_does_not_crash(self):
        reporter = scan.ProgressReporter(enabled=True)
        reporter.update("scanning...")
        reporter.finish("done")
        reporter.step(1, 5, "detect")


class SetupLoggingTests(unittest.TestCase):
    def test_setup_returns_logger(self):
        import logging

        # Reset handlers to avoid duplicate
        logger = logging.getLogger("butian")
        logger.handlers.clear()

        result = scan.setup_logging(verbose=False, debug=False)
        self.assertIsInstance(result, logging.Logger)
        self.assertEqual(result.name, "butian")

        # Cleanup
        logger.handlers.clear()

    def test_setup_with_log_dir(self):
        import logging

        logger = logging.getLogger("butian")
        logger.handlers.clear()

        with tempfile.TemporaryDirectory(prefix="butian-log-") as tmp:
            scan.setup_logging(verbose=False, debug=False, log_dir=tmp)
            log_path = os.path.join(tmp, "scan.log")
            self.assertTrue(os.path.isfile(log_path))

        # Cleanup
        logger.handlers.clear()


if __name__ == "__main__":
    unittest.main()
