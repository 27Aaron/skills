import json
import os
import tempfile
import unittest

from butian.scripts import analyze

# ---------------------------------------------------------------------------
# Minimal scan output factory
# ---------------------------------------------------------------------------


def _make_scan(**overrides):
    """Return a realistic scan output dict with sensible defaults."""
    scan = {
        "generated_at": "2026-06-05 09:05:50",
        "scan_seconds": 1.23,
        "project": {
            "name": "demo-app",
            "path": "/tmp/demo",
            "ecosystems": ["npm"],
            "total_packages": 5,
        },
        "scan_config": {"scan_mode": "full_dependency_scan"},
        "hygiene": {
            "tracked_secrets": [],
            "sensitive_tracked": [],
            "gitignore_missing": [],
        },
        "vulnerabilities": [],
        "outdated": [],
        "errors": [],
        "package_sources": [],
        "butian_workspace": {},
    }
    scan.update(overrides)
    return scan


# ===========================================================================
# normalize_severity
# ===========================================================================


class TestNormalizeSeverity(unittest.TestCase):
    def test_valid_severity_levels(self):
        for level in ("critical", "high", "medium", "low", "info"):
            self.assertEqual(analyze.normalize_severity(level), level)

    def test_uppercase_is_lowered(self):
        self.assertEqual(analyze.normalize_severity("CRITICAL"), "critical")
        self.assertEqual(analyze.normalize_severity("High"), "high")

    def test_none_returns_info(self):
        self.assertEqual(analyze.normalize_severity(None), "info")

    def test_empty_string_returns_info(self):
        self.assertEqual(analyze.normalize_severity(""), "info")

    def test_invalid_value_returns_info(self):
        self.assertEqual(analyze.normalize_severity("unknown"), "info")
        self.assertEqual(analyze.normalize_severity("urgent"), "info")

    def test_integer_value_converted_to_string(self):
        self.assertEqual(analyze.normalize_severity(42), "info")

    def test_whitespace_value_returns_info(self):
        self.assertEqual(analyze.normalize_severity("  critical  "), "info")


# ===========================================================================
# severity_rank
# ===========================================================================


class TestSeverityRank(unittest.TestCase):
    def test_rank_ordering(self):
        ranks = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        for severity, expected in ranks.items():
            with self.subTest(severity=severity):
                self.assertEqual(
                    analyze.severity_rank({"severity": severity}), expected
                )

    def test_missing_severity_gets_info_rank(self):
        """Missing severity normalizes to 'info' which has rank 1."""
        self.assertEqual(analyze.severity_rank({}), 1)

    def test_invalid_severity_gets_info_rank(self):
        self.assertEqual(analyze.severity_rank({"severity": "unknown"}), 1)


# ===========================================================================
# to_list
# ===========================================================================


class TestToList(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(analyze.to_list(None), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(analyze.to_list([]), [])

    def test_empty_string_returns_empty(self):
        self.assertEqual(analyze.to_list(""), [])

    def test_single_string_wraps_in_list(self):
        self.assertEqual(analyze.to_list("hello"), ["hello"])

    def test_list_filters_none_items(self):
        self.assertEqual(analyze.to_list(["a", None, "b", None]), ["a", "b"])

    def test_list_filters_empty_strings(self):
        self.assertEqual(analyze.to_list(["a", "", "b"]), ["a", "b"])

    def test_list_with_valid_items(self):
        self.assertEqual(analyze.to_list(["x", "y"]), ["x", "y"])

    def test_zero_is_filtered_as_falsy(self):
        """Python's 'if x' treats 0 as falsy, so to_list filters it out."""
        self.assertEqual(analyze.to_list([0]), [])

    def test_false_is_filtered(self):
        self.assertEqual(analyze.to_list([False]), [])


# ===========================================================================
# unique_values
# ===========================================================================


class TestUniqueValues(unittest.TestCase):
    def test_none_input_returns_empty(self):
        self.assertEqual(analyze.unique_values(None), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(analyze.unique_values([]), [])

    def test_deduplicates_strings(self):
        self.assertEqual(
            analyze.unique_values(["a", "b", "a", "c"]),
            ["a", "b", "c"],
        )

    def test_filters_none(self):
        self.assertEqual(analyze.unique_values([None, "a", None]), ["a"])

    def test_converts_to_string(self):
        self.assertEqual(analyze.unique_values([42, 42, 99]), ["42", "99"])

    def test_empty_string_is_kept(self):
        # str("") == "" which is falsy, but the function checks `text_value`
        self.assertEqual(analyze.unique_values([""]), [])

    def test_preserves_order(self):
        self.assertEqual(
            analyze.unique_values(["c", "a", "b", "a"]),
            ["c", "a", "b"],
        )


# ===========================================================================
# version_key
# ===========================================================================


class TestVersionKey(unittest.TestCase):
    def test_simple_version(self):
        self.assertEqual(analyze.version_key("1.2.3"), (1, 2, 3))

    def test_version_with_v_prefix(self):
        self.assertEqual(analyze.version_key("v1.0.0"), (1, 0, 0))

    def test_none_returns_empty_tuple(self):
        self.assertEqual(analyze.version_key(None), ())

    def test_empty_string_returns_empty_tuple(self):
        self.assertEqual(analyze.version_key(""), ())

    def test_single_number(self):
        self.assertEqual(analyze.version_key("42"), (42,))

    def test_version_with_extra_text(self):
        self.assertEqual(analyze.version_key("1.2.3-beta.4"), (1, 2, 3, 4))

    def test_comparison_ordering(self):
        self.assertLess(analyze.version_key("1.2.3"), analyze.version_key("1.2.4"))
        self.assertLess(analyze.version_key("1.2.10"), analyze.version_key("1.2.20"))
        self.assertLess(analyze.version_key("1.9.0"), analyze.version_key("2.0.0"))


# ===========================================================================
# highest_version
# ===========================================================================


class TestHighestVersion(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(analyze.highest_version([]), "")

    def test_none_input(self):
        self.assertEqual(analyze.highest_version(None), "")

    def test_single_version(self):
        self.assertEqual(analyze.highest_version(["1.2.3"]), "1.2.3")

    def test_picks_highest(self):
        self.assertEqual(
            analyze.highest_version(["1.0.0", "2.0.0", "1.5.0"]),
            "2.0.0",
        )

    def test_semantic_ordering(self):
        self.assertEqual(
            analyze.highest_version(["4.17.20", "4.17.21", "4.17.23"]),
            "4.17.23",
        )

    def test_deduplicates(self):
        self.assertEqual(analyze.highest_version(["1.0.0", "1.0.0"]), "1.0.0")


# ===========================================================================
# clean_advisory_summary
# ===========================================================================


class TestCleanAdvisorySummary(unittest.TestCase):
    def test_normalizes_whitespace(self):
        self.assertEqual(
            analyze.clean_advisory_summary("foo   bar\n\nbaz"),
            "foo bar baz",
        )

    def test_strips_leading_trailing(self):
        self.assertEqual(analyze.clean_advisory_summary("  hello  "), "hello")

    def test_none_returns_empty(self):
        self.assertEqual(analyze.clean_advisory_summary(None), "")

    def test_empty_returns_empty(self):
        self.assertEqual(analyze.clean_advisory_summary(""), "")

    def test_removes_short_prefix_with_colon(self):
        self.assertEqual(
            analyze.clean_advisory_summary("GHSA-xxxx: Prototype pollution"),
            "Prototype pollution",
        )

    def test_removes_prefix_with_chinese_colon(self):
        self.assertEqual(
            analyze.clean_advisory_summary("漏洞描述：存在 SSRF 风险"),
            "存在 SSRF 风险",
        )

    def test_keeps_text_without_prefix(self):
        self.assertEqual(
            analyze.clean_advisory_summary("Prototype pollution in lodash"),
            "Prototype pollution in lodash",
        )


# ===========================================================================
# advisory_issue_phrase
# ===========================================================================


class TestAdvisoryIssuePhrase(unittest.TestCase):
    def test_empty_summary(self):
        result = analyze.advisory_issue_phrase("")
        self.assertIn("确认公开漏洞", result)

    def test_none_summary(self):
        result = analyze.advisory_issue_phrase(None)
        self.assertIn("确认公开漏洞", result)

    def test_ssrf(self):
        result = analyze.advisory_issue_phrase("Server-Side Request Forgery in fetch")
        self.assertIn("服务端请求伪造", result)

    def test_ssrf_with_websocket(self):
        result = analyze.advisory_issue_phrase(
            "Server-Side Request Forgery via WebSocket upgrade"
        )
        self.assertIn("WebSocket", result)
        self.assertIn("服务端请求伪造", result)

    def test_dos(self):
        result = analyze.advisory_issue_phrase("Denial of Service vulnerability")
        self.assertIn("拒绝服务", result)

    def test_dos_abbreviation(self):
        result = analyze.advisory_issue_phrase("Possible DoS in parsing")
        self.assertIn("拒绝服务", result)

    def test_middleware_proxy_bypass(self):
        result = analyze.advisory_issue_phrase("Middleware proxy bypass vulnerability")
        self.assertIn("中间件/代理绕过", result)

    def test_middleware_bypass_pages_i18n(self):
        result = analyze.advisory_issue_phrase(
            "Pages Router with i18n middleware proxy bypass"
        )
        self.assertIn("Pages Router", result)
        self.assertIn("i18n", result)

    def test_middleware_bypass_segment_prefetch(self):
        result = analyze.advisory_issue_phrase(
            "segment-prefetch route causes middleware proxy bypass"
        )
        self.assertIn("segment-prefetch", result)

    def test_middleware_bypass_segment_prefetch_incomplete_fix(self):
        result = analyze.advisory_issue_phrase(
            "segment-prefetch incomplete fix for middleware proxy bypass"
        )
        self.assertIn("修复不完整", result)

    def test_middleware_bypass_segment_prefetch_follow_up(self):
        result = analyze.advisory_issue_phrase(
            "segment-prefetch follow-up for middleware proxy bypass"
        )
        self.assertIn("修复不完整", result)

    def test_middleware_bypass_dynamic_route(self):
        result = analyze.advisory_issue_phrase(
            "dynamic route parameter injection middleware proxy bypass"
        )
        self.assertIn("动态路由", result)

    def test_path_traversal(self):
        result = analyze.advisory_issue_phrase(
            "path traversal via percent-encoded dots"
        )
        self.assertIn("路径穿越", result)

    def test_cache_issue(self):
        result = analyze.advisory_issue_phrase("cache poisoning risk")
        self.assertIn("缓存", result)

    def test_image_optimization_dos(self):
        result = analyze.advisory_issue_phrase(
            "Image Optimization API denial of service"
        )
        self.assertIn("Image Optimization", result)
        self.assertIn("拒绝服务", result)

    def test_connection_exhaustion(self):
        result = analyze.advisory_issue_phrase(
            "connection exhaustion with Cache Components"
        )
        self.assertIn("连接耗尽", result)

    def test_large_numeric_range_max(self):
        result = analyze.advisory_issue_phrase("large numeric range overflow max limit")
        self.assertIn("大范围数字展开", result)

    def test_host_confusion_percent_encoded(self):
        result = analyze.advisory_issue_phrase(
            "host confusion via percent-encoded authority"
        )
        self.assertIn("主机解析混淆", result)

    def test_generic_summary(self):
        result = analyze.advisory_issue_phrase("Prototype pollution in lodash")
        self.assertTrue(result.startswith("公告摘要："))


# ===========================================================================
# vulnerability_summary
# ===========================================================================


class TestVulnerabilitySummary(unittest.TestCase):
    def test_with_fixed_versions(self):
        item = {
            "package": "lodash",
            "version": "4.17.20",
            "fixed_versions": ["4.17.21"],
            "advisory_summary": "Prototype pollution",
        }
        result = analyze.vulnerability_summary(item)
        self.assertIn("lodash", result)
        self.assertIn("4.17.20", result)
        self.assertIn("升级到 4.17.21", result)

    def test_without_fixed_versions(self):
        item = {
            "package": "lodash",
            "version": "4.17.20",
            "fixed_versions": [],
            "advisory_summary": "Prototype pollution",
        }
        result = analyze.vulnerability_summary(item)
        self.assertIn("确认官方修复版本", result)

    def test_without_version(self):
        item = {
            "package": "lodash",
            "fixed_versions": ["4.17.21"],
            "advisory_summary": "Prototype pollution",
        }
        result = analyze.vulnerability_summary(item)
        self.assertNotIn("None", result)

    def test_uses_name_when_no_package(self):
        item = {
            "name": "my-dep",
            "version": "1.0",
            "fixed_versions": ["1.1"],
            "summary": "Some issue",
        }
        result = analyze.vulnerability_summary(item)
        self.assertIn("my-dep", result)

    def test_uses_default_when_no_package_or_name(self):
        item = {
            "version": "1.0",
            "fixed_versions": ["1.1"],
            "summary": "Some issue",
        }
        result = analyze.vulnerability_summary(item)
        self.assertIn("该依赖", result)


# ===========================================================================
# sort_items
# ===========================================================================


class TestSortItems(unittest.TestCase):
    def test_sorts_by_severity_descending(self):
        items = [
            {"severity": "low", "package": "a"},
            {"severity": "critical", "package": "b"},
            {"severity": "medium", "package": "c"},
        ]
        result = analyze.sort_items(items)
        self.assertEqual(result[0]["severity"], "critical")
        self.assertEqual(result[1]["severity"], "medium")
        self.assertEqual(result[2]["severity"], "low")

    def test_same_severity_sorts_by_name(self):
        items = [
            {"severity": "high", "package": "zebra"},
            {"severity": "high", "package": "alpha"},
        ]
        result = analyze.sort_items(items)
        self.assertEqual(result[0]["package"], "alpha")
        self.assertEqual(result[1]["package"], "zebra")

    def test_same_severity_and_name_sorts_by_version(self):
        items = [
            {"severity": "high", "package": "pkg", "version": "2.0"},
            {"severity": "high", "package": "pkg", "version": "1.0"},
        ]
        result = analyze.sort_items(items)
        self.assertEqual(result[0]["version"], "1.0")
        self.assertEqual(result[1]["version"], "2.0")

    def test_empty_list(self):
        self.assertEqual(analyze.sort_items([]), [])


# ===========================================================================
# build_top_issues
# ===========================================================================


class TestBuildTopIssues(unittest.TestCase):
    def test_empty_vulnerabilities(self):
        scan = _make_scan()
        self.assertEqual(analyze.build_top_issues(scan), [])

    def test_assigns_tier_and_rank(self):
        scan = _make_scan(
            vulnerabilities=[
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "summary": "Prototype pollution",
                    "fixed_versions": ["4.17.21"],
                    "ecosystem": "npm",
                },
                {
                    "package": "express",
                    "version": "4.18.0",
                    "severity": "critical",
                    "summary": "RCE",
                    "fixed_versions": ["4.18.1"],
                    "ecosystem": "npm",
                },
            ]
        )
        issues = analyze.build_top_issues(scan)

        self.assertEqual(len(issues), 2)
        # critical should come first
        self.assertEqual(issues[0]["package"], "express")
        self.assertEqual(issues[0]["severity"], "critical")
        self.assertEqual(issues[0]["tier"], "red")
        self.assertEqual(issues[0]["rank"], 1)

        self.assertEqual(issues[1]["package"], "lodash")
        self.assertEqual(issues[1]["severity"], "high")
        self.assertEqual(issues[1]["tier"], "red")
        self.assertEqual(issues[1]["rank"], 2)

    def test_medium_gets_yellow_tier(self):
        scan = _make_scan(
            vulnerabilities=[
                {
                    "package": "pkg",
                    "version": "1.0",
                    "severity": "medium",
                    "summary": "Issue",
                    "ecosystem": "npm",
                },
            ]
        )
        issues = analyze.build_top_issues(scan)
        self.assertEqual(issues[0]["tier"], "yellow")

    def test_low_and_info_get_green_tier(self):
        for severity in ("low", "info"):
            with self.subTest(severity=severity):
                scan = _make_scan(
                    vulnerabilities=[
                        {
                            "package": "pkg",
                            "version": "1.0",
                            "severity": severity,
                            "summary": "Issue",
                            "ecosystem": "npm",
                        },
                    ]
                )
                issues = analyze.build_top_issues(scan)
                self.assertEqual(issues[0]["tier"], "green")

    def test_normalizes_severity(self):
        scan = _make_scan(
            vulnerabilities=[
                {
                    "package": "pkg",
                    "severity": "CRITICAL",
                    "summary": "Big issue",
                    "ecosystem": "npm",
                },
            ]
        )
        issues = analyze.build_top_issues(scan)
        self.assertEqual(issues[0]["severity"], "critical")

    def test_summary_is_generated(self):
        scan = _make_scan(
            vulnerabilities=[
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "summary": "Prototype pollution",
                    "fixed_versions": ["4.17.21"],
                    "ecosystem": "npm",
                },
            ]
        )
        issues = analyze.build_top_issues(scan)
        self.assertIn("lodash", issues[0]["summary"])

    def test_nested_npm_residual_context_is_explained(self):
        with tempfile.TemporaryDirectory() as tmp:
            package_lock = {
                "packages": {
                    "": {"dependencies": {"postcss": "^8.5.10"}},
                    "node_modules/postcss": {"version": "8.5.10"},
                    "node_modules/next": {"version": "16.2.6"},
                    "node_modules/next/node_modules/postcss": {"version": "8.4.31"},
                }
            }
            with open(
                os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(package_lock, f)
            scan = _make_scan(
                project={"name": "demo-app", "path": tmp, "ecosystems": ["npm"]},
                vulnerabilities=[
                    {
                        "package": "postcss",
                        "version": "8.4.31",
                        "ecosystem": "npm",
                        "severity": "medium",
                        "fixed_versions": ["8.5.10"],
                        "summary": "PostCSS has XSS",
                    }
                ],
            )

            issues = analyze.build_top_issues(scan)

        self.assertEqual(issues[0]["dependency_context"]["kind"], "nested_locked")
        self.assertEqual(
            issues[0]["dependency_context"]["locations"][0]["parent"], "next"
        )
        self.assertIn("被父依赖锁定的嵌套副本", issues[0]["summary"])
        self.assertIn("顶层 postcss 当前版本为 8.5.10", issues[0]["summary"])


# ===========================================================================
# build_hygiene_items
# ===========================================================================


class TestBuildHygieneItems(unittest.TestCase):
    def test_empty_hygiene(self):
        scan = _make_scan()
        red, yellow, green = analyze.build_hygiene_items(scan)
        self.assertEqual(red, [])
        self.assertEqual(yellow, [])
        self.assertEqual(green, [])

    def test_secret_high_confidence(self):
        scan = _make_scan(
            hygiene={
                "tracked_secrets": [
                    {
                        "type": "openai_key",
                        "confidence": "high",
                        "file": ".env",
                        "line": 5,
                        "preview": "sk-proj...7890",
                    },
                ],
                "sensitive_tracked": [],
                "gitignore_missing": [],
            }
        )
        red, yellow, green = analyze.build_hygiene_items(scan)

        # secrets go to yellow
        self.assertEqual(len(yellow), 1)
        self.assertEqual(yellow[0]["type"], "secret_exposure")
        self.assertEqual(yellow[0]["severity"], "high")
        self.assertEqual(yellow[0]["secret_type"], "openai_key")
        self.assertIn(".env:5", yellow[0]["name"])

    def test_secret_medium_confidence(self):
        scan = _make_scan(
            hygiene={
                "tracked_secrets": [
                    {
                        "type": "generic_api_key",
                        "confidence": "medium",
                        "file": "config.py",
                        "line": None,
                        "preview": "AKIA...",
                    },
                ],
                "sensitive_tracked": [],
                "gitignore_missing": [],
            }
        )
        red, yellow, green = analyze.build_hygiene_items(scan)

        self.assertEqual(len(yellow), 1)
        self.assertEqual(yellow[0]["severity"], "medium")

    def test_sensitive_file_high_severity_types(self):
        for file_type in ("env_file", "private_key", "credentials", "ssh_key"):
            with self.subTest(file_type=file_type):
                scan = _make_scan(
                    hygiene={
                        "tracked_secrets": [],
                        "sensitive_tracked": [
                            {"type": file_type, "file": f"prod.{file_type}"},
                        ],
                        "gitignore_missing": [],
                    }
                )
                red, yellow, green = analyze.build_hygiene_items(scan)
                self.assertEqual(len(red), 1)
                self.assertEqual(red[0]["severity"], "high")
                self.assertEqual(red[0]["type"], "sensitive_file_tracked")

    def test_sensitive_file_medium_severity_types(self):
        for file_type in ("log", "database"):
            with self.subTest(file_type=file_type):
                scan = _make_scan(
                    hygiene={
                        "tracked_secrets": [],
                        "sensitive_tracked": [
                            {"type": file_type, "file": f"app.{file_type}"},
                        ],
                        "gitignore_missing": [],
                    }
                )
                red, yellow, green = analyze.build_hygiene_items(scan)
                self.assertEqual(len(yellow), 1)
                self.assertEqual(yellow[0]["severity"], "medium")

    def test_gitignore_missing_adds_yellow_and_green(self):
        scan = _make_scan(
            hygiene={
                "tracked_secrets": [],
                "sensitive_tracked": [],
                "gitignore_missing": [".env", "*.pem"],
            }
        )
        red, yellow, green = analyze.build_hygiene_items(scan)

        self.assertEqual(len(yellow), 1)
        self.assertEqual(yellow[0]["type"], "gitignore_missing")
        self.assertEqual(yellow[0]["severity"], "low")
        self.assertIn(".env", yellow[0]["disposal"])

        self.assertEqual(len(green), 1)
        self.assertEqual(green[0]["type"], "gitignore_fix")
        self.assertEqual(green[0]["fix_config"]["patterns"], [".env", "*.pem"])

    def test_no_hygiene_key(self):
        scan = _make_scan()
        del scan["hygiene"]
        red, yellow, green = analyze.build_hygiene_items(scan)
        self.assertEqual(red, [])
        self.assertEqual(yellow, [])
        self.assertEqual(green, [])


# ===========================================================================
# build_dependency_fix_items
# ===========================================================================


class TestBuildDependencyFixItems(unittest.TestCase):
    def test_groups_by_package(self):
        issues = [
            {
                "package": "lodash",
                "version": "4.17.20",
                "severity": "high",
                "ecosystem": "npm",
                "advisory_id": "GHSA-1",
                "fixed_versions": ["4.17.21"],
                "summary": "Pollution",
            },
            {
                "package": "lodash",
                "version": "4.17.20",
                "severity": "medium",
                "ecosystem": "npm",
                "advisory_id": "GHSA-2",
                "fixed_versions": ["4.17.23"],
                "summary": "Injection",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)

        self.assertEqual(len(green), 1)
        self.assertEqual(green[0]["package"], "lodash")
        self.assertEqual(green[0]["fix_config"]["target_version"], "4.17.23")
        self.assertIn("命中 2 个漏洞", green[0]["summary"])
        self.assertIn("只覆盖包管理器可解析的普通升级", green[0]["summary"])
        self.assertEqual(green[0]["fix_config"]["upgrade_scope"], "direct_package")
        self.assertIn("间接依赖", green[0]["fix_config"]["residual_guidance"])

    def test_no_fixed_versions_skipped(self):
        issues = [
            {
                "package": "broken-pkg",
                "version": "1.0",
                "severity": "high",
                "ecosystem": "npm",
                "advisory_id": "GHSA-3",
                "fixed_versions": [],
                "summary": "No fix",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)
        self.assertEqual(green, [])

    def test_missing_fixed_triggers_notice(self):
        issues = [
            {
                "package": "mixed-pkg",
                "version": "1.0",
                "severity": "high",
                "ecosystem": "npm",
                "advisory_id": "GHSA-4",
                "fixed_versions": ["1.1"],
                "summary": "Fixable",
            },
            {
                "package": "mixed-pkg",
                "version": "1.0",
                "severity": "medium",
                "ecosystem": "npm",
                "advisory_id": "GHSA-5",
                "fixed_versions": [],
                "summary": "Not fixable",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)

        self.assertEqual(len(green), 1)
        self.assertIn("部分公告未给出明确修复版本", green[0]["summary"])

    def test_target_version_is_highest(self):
        issues = [
            {
                "package": "pkg",
                "version": "1.0",
                "severity": "high",
                "ecosystem": "npm",
                "advisory_id": "A",
                "fixed_versions": ["1.5"],
                "summary": "A",
            },
            {
                "package": "pkg",
                "version": "1.0",
                "severity": "medium",
                "ecosystem": "npm",
                "advisory_id": "B",
                "fixed_versions": ["2.0"],
                "summary": "B",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)
        self.assertEqual(green[0]["fix_config"]["target_version"], "2.0")

    def test_severity_inherits_from_highest_issue(self):
        issues = [
            {
                "package": "pkg",
                "version": "1.0",
                "severity": "medium",
                "ecosystem": "npm",
                "advisory_id": "A",
                "fixed_versions": ["2.0"],
                "summary": "A",
            },
            {
                "package": "pkg",
                "version": "1.0",
                "severity": "critical",
                "ecosystem": "npm",
                "advisory_id": "B",
                "fixed_versions": ["2.0"],
                "summary": "B",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)
        self.assertEqual(green[0]["severity"], "critical")

    def test_empty_issues(self):
        self.assertEqual(analyze.build_dependency_fix_items([]), [])

    def test_advisory_id_fallbacks(self):
        issues = [
            {
                "package": "pkg",
                "version": "1.0",
                "severity": "high",
                "ecosystem": "npm",
                "cve_id": "CVE-2026-0001",
                "fixed_versions": ["2.0"],
                "summary": "Issue",
            },
        ]
        green = analyze.build_dependency_fix_items(issues)
        self.assertEqual(green[0]["fix_config"]["advisory_ids"], ["CVE-2026-0001"])


# ===========================================================================
# count_risks
# ===========================================================================


class TestCountRisks(unittest.TestCase):
    def test_empty_groups(self):
        result = analyze.count_risks()
        self.assertEqual(
            result,
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        )

    def test_counts_across_groups(self):
        group_a = [{"severity": "critical"}, {"severity": "high"}]
        group_b = [{"severity": "high"}, {"severity": "medium"}]

        result = analyze.count_risks(group_a, group_b)

        self.assertEqual(result["critical"], 1)
        self.assertEqual(result["high"], 2)
        self.assertEqual(result["medium"], 1)
        self.assertEqual(result["low"], 0)

    def test_normalizes_invalid_severity(self):
        group = [{"severity": "unknown"}]
        result = analyze.count_risks(group)
        self.assertEqual(result["info"], 1)


# ===========================================================================
# build_summary
# ===========================================================================


class TestBuildSummary(unittest.TestCase):
    def _make_analysis(self, **overrides):
        analysis = {
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "top_issues": [],
            "red": [],
            "yellow": [],
            "green": [],
        }
        analysis.update(overrides)
        return analysis

    def test_hygiene_only_mode(self):
        scan = _make_scan(
            scan_config={"scan_mode": "hygiene_only"},
        )
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertIn("未执行依赖漏洞扫描", result["tldr"])
        self.assertIn("暂无法执行依赖漏洞扫描", result["detail"])
        self.assertTrue(any("暂无法执行" in p for p in result["priority"]))

    def test_critical_high_vulnerabilities(self):
        scan = _make_scan()
        analysis = self._make_analysis(
            risk_summary={"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
            top_issues=[{}, {}, {}],
        )
        result = analyze.build_summary(scan, analysis)

        self.assertIn("紧急和高风险", result["tldr"])
        self.assertTrue(any("3 个紧急/高风险项" in p for p in result["priority"]))

    def test_secrets_found(self):
        scan = _make_scan(
            hygiene={
                "tracked_secrets": [{"type": "openai_key"}],
                "sensitive_tracked": [],
                "gitignore_missing": [],
            }
        )
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertIn("凭证或敏感文件", result["tldr"])
        self.assertTrue(any("研发确认凭证" in p for p in result["priority"]))

    def test_errors_in_scan(self):
        scan = _make_scan(errors=[{"message": "pip failed"}])
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertIn("部分检查失败", result["tldr"])
        self.assertTrue(any("复查扫描错误" in p for p in result["priority"]))

    def test_clean_scan(self):
        scan = _make_scan()
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertIn("没有发现明确安全风险", result["tldr"])
        self.assertTrue(any("没有需要立即处理" in p for p in result["priority"]))

    def test_medium_low_vulnerabilities(self):
        scan = _make_scan()
        analysis = self._make_analysis(
            risk_summary={"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
            top_issues=[{}, {}, {}],
        )
        result = analyze.build_summary(scan, analysis)

        self.assertIn("中风险或低风险", result["tldr"])

    def test_vuln_count_but_no_severity(self):
        scan = _make_scan()
        analysis = self._make_analysis(
            risk_summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 5},
            top_issues=[{}] * 5,
        )
        result = analyze.build_summary(scan, analysis)

        self.assertIn("严重度数据不足", result["tldr"])

    def test_detail_mentions_project_name(self):
        scan = _make_scan(project={"name": "my-cool-app", "path": "/tmp/app"})
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertIn("my-cool-app", result["detail"])

    def test_tier_stats(self):
        scan = _make_scan()
        analysis = self._make_analysis(
            red=[{"severity": "high"}],
            yellow=[{"severity": "medium"}, {"severity": "low"}],
            green=[{"severity": "info"}],
        )
        result = analyze.build_summary(scan, analysis)

        self.assertEqual(result["tier_stats"]["red"], "1 项优先处理")
        self.assertEqual(result["tier_stats"]["yellow"], "2 项需要人工确认")
        self.assertEqual(result["tier_stats"]["green"], "1 项可作为修复计划")

    def test_gitignore_missing_in_priority(self):
        scan = _make_scan(
            hygiene={
                "tracked_secrets": [],
                "sensitive_tracked": [],
                "gitignore_missing": [".env"],
            }
        )
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertTrue(any(".gitignore" in p for p in result["priority"]))

    def test_outdated_in_priority_and_detail(self):
        scan = _make_scan(outdated=[{"name": "old-pkg"}])
        analysis = self._make_analysis()
        result = analyze.build_summary(scan, analysis)

        self.assertTrue(any("过期依赖" in p for p in result["priority"]))
        self.assertIn("过期依赖 1 个", result["detail"])

    def test_dependency_fix_priority_mentions_rescan_and_transitive_residuals(self):
        scan = _make_scan()
        analysis = self._make_analysis(
            green=[
                {
                    "type": "dependency_upgrade",
                    "package": "postcss",
                    "fix_config": {"upgrade_scope": "direct_package"},
                }
            ],
        )
        result = analyze.build_summary(scan, analysis)

        self.assertTrue(any("重新运行补天扫描" in p for p in result["priority"]))
        self.assertTrue(any("间接依赖" in p for p in result["priority"]))
        self.assertTrue(any("确认强制覆盖" in p for p in result["priority"]))


HYGIENE_ONLY_NOTICE_SHORT = "暂无法执行依赖漏洞扫描"


# ===========================================================================
# build_analysis
# ===========================================================================


class TestBuildAnalysis(unittest.TestCase):
    def test_full_integration(self):
        scan = _make_scan(
            vulnerabilities=[
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "summary": "Prototype pollution",
                    "fixed_versions": ["4.17.21"],
                    "ecosystem": "npm",
                    "advisory_id": "GHSA-1",
                },
            ],
            hygiene={
                "tracked_secrets": [
                    {
                        "type": "openai_key",
                        "confidence": "high",
                        "file": ".env",
                        "line": 3,
                        "preview": "sk-...",
                    },
                ],
                "sensitive_tracked": [
                    {"type": "env_file", "file": ".env.production"},
                ],
                "gitignore_missing": [".env"],
            },
        )

        result = analyze.build_analysis(scan, source_scan_file="/tmp/scan.json")

        # top-level metadata
        self.assertEqual(result["generated_at"], "2026-06-05 09:05:50")
        self.assertEqual(result["scan_seconds"], 1.23)
        self.assertEqual(result["vulnerability_count"], 1)
        self.assertEqual(result["package_count"], 5)
        self.assertEqual(result["source_scan_file"], "/tmp/scan.json")

        # risk summary: 1 vuln high + 1 secret high + 1 sensitive file high = 3
        self.assertEqual(result["risk_summary"]["high"], 3)

        # issues sorted
        self.assertEqual(len(result["top_issues"]), 1)
        self.assertEqual(result["top_issues"][0]["package"], "lodash")

        # hygiene red (sensitive file) + yellow (secret) + yellow (gitignore)
        self.assertTrue(len(result["red"]) >= 1)
        self.assertTrue(len(result["yellow"]) >= 1)

        # green has dependency upgrade + gitignore fix
        green_types = [g["type"] for g in result["green"]]
        self.assertIn("dependency_upgrade", green_types)
        self.assertIn("gitignore_fix", green_types)

        # summary present
        self.assertIn("tldr", result["summary"])
        self.assertIn("detail", result["summary"])
        self.assertIn("priority", result["summary"])

    def test_empty_scan(self):
        scan = _make_scan()
        result = analyze.build_analysis(scan)

        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["outdated_count"], 0)
        self.assertEqual(result["top_issues"], [])
        self.assertEqual(result["red"], [])
        self.assertEqual(result["yellow"], [])
        self.assertEqual(result["green"], [])
        self.assertEqual(result["errors"], [])

    def test_passes_output_file(self):
        scan = _make_scan()
        result = analyze.build_analysis(scan, output_file="/tmp/analysis.json")
        self.assertEqual(result["output_file"], "/tmp/analysis.json")


# ===========================================================================
# default_output_path
# ===========================================================================


class TestDefaultOutputPath(unittest.TestCase):
    def test_generates_analysis_json_under_assets(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            run_dir = os.path.join(tmpdir, ".butian", "run-20260605")
            assets_dir = os.path.join(run_dir, "assets")
            os.makedirs(assets_dir)

            scan_path = os.path.join(assets_dir, "scan.json")
            result = analyze.default_output_path(scan_path)

            self.assertEqual(result, os.path.join(assets_dir, "analysis.json"))
            # assets dir should already exist
            self.assertTrue(os.path.isdir(assets_dir))

    def test_creates_assets_dir_if_missing(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            run_dir = os.path.join(tmpdir, ".butian", "run-20260605")
            os.makedirs(run_dir)

            scan_path = os.path.join(run_dir, "assets", "scan.json")
            result = analyze.default_output_path(scan_path)

            self.assertTrue(os.path.isdir(os.path.dirname(result)))


# ===========================================================================
# parse_args
# ===========================================================================


class TestParseArgs(unittest.TestCase):
    def test_scan_json_required(self):
        with self.assertRaises(SystemExit):
            analyze.parse_args([])

    def test_scan_json_only(self):
        args = analyze.parse_args(["scan.json"])
        self.assertEqual(args.scan_json, "scan.json")
        self.assertIsNone(args.output_json)

    def test_scan_json_and_output(self):
        args = analyze.parse_args(["scan.json", "output.json"])
        self.assertEqual(args.scan_json, "scan.json")
        self.assertEqual(args.output_json, "output.json")


# ===========================================================================
# write_json
# ===========================================================================


class TestWriteJson(unittest.TestCase):
    def test_writes_valid_json(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            path = os.path.join(tmpdir, "test.json")
            data = {"key": "值", "list": [1, 2, 3]}
            analyze.write_json(path, data)

            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)

            self.assertEqual(loaded, data)

    def test_creates_parent_directory(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            path = os.path.join(tmpdir, "sub", "dir", "test.json")
            analyze.write_json(path, {"ok": True})

            self.assertTrue(os.path.isfile(path))

    def test_json_ends_with_newline(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            path = os.path.join(tmpdir, "test.json")
            analyze.write_json(path, {"a": 1})

            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()

            self.assertTrue(content.endswith("\n"))

    def test_preserves_unicode(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            path = os.path.join(tmpdir, "test.json")
            data = {"label": "紧急风险"}
            analyze.write_json(path, data)

            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()

            self.assertIn("紧急风险", content)
            self.assertNotIn("\\u", content)


# ===========================================================================
# main (end-to-end)
# ===========================================================================


class TestMain(unittest.TestCase):
    def test_main_writes_analysis_file(self):
        with tempfile.TemporaryDirectory(prefix="butian-test-") as tmpdir:
            scan_path = os.path.join(tmpdir, "scan.json")
            output_path = os.path.join(tmpdir, "analysis.json")

            scan_data = _make_scan()
            with open(scan_path, "w", encoding="utf-8") as handle:
                json.dump(scan_data, handle)

            # patch sys.argv and call main
            import sys

            original_argv = sys.argv
            sys.argv = ["analyze.py", scan_path, output_path]
            try:
                result = analyze.main()
            finally:
                sys.argv = original_argv

            self.assertEqual(result, 0)
            self.assertTrue(os.path.isfile(output_path))

            with open(output_path, "r", encoding="utf-8") as handle:
                analysis = json.load(handle)

            self.assertIn("summary", analysis)
            self.assertIn("risk_summary", analysis)


if __name__ == "__main__":
    unittest.main()
