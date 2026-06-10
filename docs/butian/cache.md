# cache.py 技术文档

> 源码路径：`butian/scripts/cache.py`

## 概览

`cache.py` 维护官方漏洞源响应的本地缓存。缓存位于 `.butian/cache/`，跨 run 共享，默认 24 小时过期。缓存不保存源码、lockfile、环境变量或密钥。

## 职责

| #   | 职责     | 说明                                           |
| --- | -------- | ---------------------------------------------- |
| 1   | 目录定位 | 为 OSV、NVD、CISA KEV、FIRST EPSS 等来源建目录 |
| 2   | 缓存读取 | 过期、缺失、损坏 JSON 都返回 `None`            |
| 3   | 缓存写入 | 保存 `cached_at`、`source`、`key` 和 `data`    |
| 4   | 清理过期 | 删除超过 TTL 的缓存文件                        |

## 核心函数

| 函数                                                      | 作用                         |
| --------------------------------------------------------- | ---------------------------- |
| `cache_dir(project_path, source)`                         | 返回并创建指定数据源缓存目录 |
| `cache_read(cache_path, ttl_seconds=86400)`               | 读取未过期缓存               |
| `cache_write(cache_path, data, source="unknown", key="")` | 写入缓存                     |
| `cache_clean(project_path, ttl_seconds=86400)`            | 删除过期缓存                 |

## 兼容关系

`scan.py` 会 re-export 本模块函数，旧代码仍可通过 `scan.cache_read()`、`scan.cache_write()`、`scan.cache_clean()` 调用。

## 测试覆盖

- `tests/butian/test_cache.py`
