"""Tests for local caching in scan.py."""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from butian.scripts import scan


class CacheDirTests(unittest.TestCase):
    def test_scan_reexports_cache_helpers(self):
        from butian.scripts import cache

        self.assertIs(scan.cache_dir, cache.cache_dir)
        self.assertIs(scan.cache_read, cache.cache_read)
        self.assertIs(scan.cache_write, cache.cache_write)
        self.assertIs(scan.cache_clean, cache.cache_clean)

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            d = scan.cache_dir(tmp, "osv")
            self.assertTrue(os.path.isdir(d))
            self.assertIn("osv", d)


class CacheReadWriteTests(unittest.TestCase):
    def test_read_missing_returns_none(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            path = os.path.join(tmp, "missing.json")
            self.assertIsNone(scan.cache_read(path))

    def test_write_and_read(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            path = os.path.join(tmp, "test.json")
            data = {"key": "value"}
            scan.cache_write(path, data, source="test", key="k")
            result = scan.cache_read(path)
            self.assertEqual(result, data)

    def test_expired_returns_none(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            path = os.path.join(tmp, "test.json")
            scan.cache_write(path, {"key": "value"})
            # Set mtime to 2 days ago
            old_time = time.time() - 172800
            os.utime(path, (old_time, old_time))
            result = scan.cache_read(path, ttl_seconds=86400)
            self.assertIsNone(result)

    def test_valid_cache_returned(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            path = os.path.join(tmp, "test.json")
            scan.cache_write(path, {"fresh": True})
            result = scan.cache_read(path, ttl_seconds=86400)
            self.assertIsNotNone(result)
            assert result is not None  # for type checkers
            self.assertTrue(result["fresh"])

    def test_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w") as f:
                f.write("not json")
            self.assertIsNone(scan.cache_read(path))


class CacheCleanTests(unittest.TestCase):
    def test_removes_expired(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            # Create cache structure
            cache_base = os.path.join(tmp, ".butian", "cache", "osv")
            os.makedirs(cache_base)
            old_file = os.path.join(cache_base, "old.json")
            new_file = os.path.join(cache_base, "new.json")

            with open(old_file, "w") as f:
                json.dump({"data": "old"}, f)
            old_time = time.time() - 172800
            os.utime(old_file, (old_time, old_time))

            with open(new_file, "w") as f:
                json.dump({"data": "new"}, f)

            scan.cache_clean(tmp, ttl_seconds=86400)

            self.assertFalse(os.path.isfile(old_file))
            self.assertTrue(os.path.isfile(new_file))

    def test_no_cache_dir_is_safe(self):
        with tempfile.TemporaryDirectory(prefix="butian-cache-") as tmp:
            scan.cache_clean(tmp)  # should not raise


if __name__ == "__main__":
    unittest.main()
