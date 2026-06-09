#!/usr/bin/env python3
"""Local cache helpers for official vulnerability source responses."""

from __future__ import annotations

import json
import os
import time

try:
    from .workspace import BUTIAN_DIR, CACHE_DIR_NAME
except ImportError:  # pragma: no cover - direct script execution
    from workspace import BUTIAN_DIR, CACHE_DIR_NAME  # type: ignore


def cache_dir(project_path, source):
    """Return the cache directory for a given source (osv/nvd/epss/kev)."""
    base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME, source)
    os.makedirs(base, exist_ok=True)
    return base


def cache_read(cache_path, ttl_seconds=86400):
    """Read from cache if not expired. Returns data dict or None."""
    if not os.path.isfile(cache_path):
        return None
    try:
        mtime = os.path.getmtime(cache_path)
        if time.time() - mtime > ttl_seconds:
            return None
        with open(cache_path, "r", encoding="utf-8") as f:
            entry = json.load(f)
        return entry.get("data")
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def cache_write(cache_path, data, source="unknown", key=""):
    """Write data to cache with metadata."""
    entry = {
        "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ttl_seconds": 86400,
        "source": source,
        "key": key,
        "data": data,
    }
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False, separators=(",", ":"))
    except OSError:
        pass


def cache_clean(project_path, ttl_seconds=86400):
    """Remove expired cache entries."""
    cache_base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME)
    if not os.path.isdir(cache_base):
        return
    now = time.time()
    try:
        for source_name in os.listdir(cache_base):
            source_path = os.path.join(cache_base, source_name)
            if not os.path.isdir(source_path):
                continue
            for fname in os.listdir(source_path):
                fpath = os.path.join(source_path, fname)
                try:
                    if now - os.path.getmtime(fpath) > ttl_seconds:
                        os.remove(fpath)
                except OSError:
                    pass
    except OSError:
        pass

