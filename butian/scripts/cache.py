#!/usr/bin/env python3
"""官方漏洞源响应的本地缓存工具。"""

from __future__ import annotations

import json
import os
import time

try:
    from .workspace import BUTIAN_DIR, CACHE_DIR_NAME
except ImportError:  # pragma: no cover - direct script execution
    from workspace import BUTIAN_DIR, CACHE_DIR_NAME  # type: ignore


def cache_dir(project_path, source):
    """返回指定漏洞源（osv/nvd/epss/kev）的缓存目录。"""
    base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME, source)
    os.makedirs(base, exist_ok=True)
    return base


def cache_read(cache_path, ttl_seconds=86400):
    """缓存未过期时读取数据字典，否则返回 None。"""
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
    """将数据和元数据写入缓存。"""
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
    """移除过期缓存条目。"""
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
