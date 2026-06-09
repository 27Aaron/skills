"""Tests for scan.py helper functions: logging, binary detection."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import scan


def close_logger_handlers(logger):
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


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
        close_logger_handlers(logger)

        result = scan.setup_logging(verbose=False, debug=False)
        self.assertIsInstance(result, logging.Logger)
        self.assertEqual(result.name, "butian")

        # Cleanup
        close_logger_handlers(logger)


# ---------------------------------------------------------------------------
# workspace module compatibility
# ---------------------------------------------------------------------------
class WorkspaceModuleCompatibilityTests(unittest.TestCase):
    def test_scan_reexports_workspace_helpers(self):
        from butian.scripts import workspace

        self.assertIs(scan.ensure_butian_run, workspace.ensure_butian_run)
        self.assertIs(scan.default_asset_path, workspace.default_asset_path)
        self.assertIs(scan.run_dir_from_output_file, workspace.run_dir_from_output_file)
        self.assertIs(scan.find_project_root, workspace.find_project_root)
        self.assertIs(scan.ensure_safe_project_path, workspace.ensure_safe_project_path)

    def test_workspace_creates_run_directories(self):
        from butian.scripts import workspace

        with tempfile.TemporaryDirectory(prefix="butian-workspace-") as tmp:
            run_dir = workspace.ensure_butian_run(tmp, run_id="20260610-010203")
            self.assertTrue(os.path.isdir(os.path.join(run_dir, "assets")))
            self.assertTrue(os.path.isdir(os.path.join(run_dir, "content")))
            self.assertEqual(os.path.basename(run_dir), "20260610-010203")

    def test_workspace_rejects_windows_drive_roots(self):
        from butian.scripts import workspace

        self.assertTrue(workspace.is_protected_project_path("C:\\"))
        self.assertTrue(workspace.is_protected_project_path("D:/"))
        self.assertFalse(workspace.is_protected_project_path("C:\\Users\\alice\\repo"))

    def test_setup_with_log_dir(self):
        import logging

        logger = logging.getLogger("butian")
        close_logger_handlers(logger)

        with tempfile.TemporaryDirectory(prefix="butian-log-") as tmp:
            scan.setup_logging(verbose=False, debug=False, log_dir=tmp)
            log_path = os.path.join(tmp, "scan.log")
            self.assertTrue(os.path.isfile(log_path))

        # Cleanup
        close_logger_handlers(logger)


if __name__ == "__main__":
    unittest.main()
