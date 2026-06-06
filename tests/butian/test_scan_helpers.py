"""Tests for scan.py helper functions: logging, binary detection."""

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
