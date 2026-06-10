"""Unit tests for butian/scripts/report.py - Markdown report rendering."""

import os
import subprocess
import sys
import tempfile
import unittest

from butian.scripts import report
from butian.scripts import scan as scan_mod


# ---------------------------------------------------------------------------
# text / cell
# ---------------------------------------------------------------------------
class TextTests(unittest.TestCase):
    def test_none_to_empty(self):
        self.assertEqual(report.text(None), "")

    def test_strips(self):
        self.assertEqual(report.text("  hello  "), "hello")

    def test_preserves_inner(self):
        self.assertEqual(report.text("a b c"), "a b c")


class CellTests(unittest.TestCase):
    def test_pipe_escaped(self):
        self.assertEqual(report.cell("a|b"), "a\\|b")

    def test_newline_replaced(self):
        self.assertEqual(report.cell("a\nb"), "a b")

    def test_none_to_empty(self):
        self.assertEqual(report.cell(None), "")


# ---------------------------------------------------------------------------
# to_list
# ---------------------------------------------------------------------------
class ToListTests(unittest.TestCase):
    def test_none(self):
        self.assertEqual(report.to_list(None), [])

    def test_empty_list(self):
        self.assertEqual(report.to_list([]), [])

    def test_list_with_falsy(self):
        self.assertEqual(report.to_list(["a", "", None, "b"]), ["a", "b"])

    def test_single_string(self):
        self.assertEqual(report.to_list("hello"), ["hello"])

    def test_single_int(self):
        self.assertEqual(report.to_list(42), [42])


# ---------------------------------------------------------------------------
# clean_version
# ---------------------------------------------------------------------------
class CleanVersionTests(unittest.TestCase):
    def test_strips_v(self):
        self.assertEqual(report.clean_version("v1.2.3"), "1.2.3")

    def test_no_v(self):
        self.assertEqual(report.clean_version("1.2.3"), "1.2.3")

    def test_none(self):
        self.assertEqual(report.clean_version(None), "")


# ---------------------------------------------------------------------------
# outdated_update_target / is_outdated_item
# ---------------------------------------------------------------------------
class OutdatedUpdateTargetTests(unittest.TestCase):
    def test_wanted_first(self):
        self.assertEqual(
            report.outdated_update_target({"wanted": "1.1", "latest": "2.0"}), "1.1"
        )

    def test_update_second(self):
        self.assertEqual(
            report.outdated_update_target({"update": "1.1", "latest": "2.0"}), "1.1"
        )

    def test_latest_fallback(self):
        self.assertEqual(report.outdated_update_target({"latest": "2.0"}), "2.0")

    def test_empty(self):
        self.assertEqual(report.outdated_update_target({}), None)


class IsOutdatedItemTests(unittest.TestCase):
    def test_outdated(self):
        self.assertTrue(report.is_outdated_item({"current": "1.0", "wanted": "1.1"}))

    def test_current(self):
        self.assertFalse(report.is_outdated_item({"current": "1.0", "wanted": "1.0"}))

    def test_v_prefix(self):
        self.assertTrue(report.is_outdated_item({"current": "v1.0", "latest": "v2.0"}))

    def test_no_target(self):
        self.assertFalse(
            report.is_outdated_item({"current": "1.0", "wanted": "", "latest": ""})
        )


# ---------------------------------------------------------------------------
# date_from_analysis
# ---------------------------------------------------------------------------
class DateFromAnalysisTests(unittest.TestCase):
    def test_extracts_date(self):
        self.assertEqual(
            report.date_from_analysis({"generated_at": "2026-06-05 09:05:50"}),
            "2026-06-05",
        )

    def test_missing(self):
        self.assertEqual(report.date_from_analysis({}), "unknown-date")


# ---------------------------------------------------------------------------
# severity_label
# ---------------------------------------------------------------------------
class SeverityLabelTests(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(report.severity_label("critical"), "紧急")

    def test_high(self):
        self.assertEqual(report.severity_label("high"), "高风险")

    def test_medium(self):
        self.assertEqual(report.severity_label("medium"), "中风险")

    def test_low(self):
        self.assertEqual(report.severity_label("low"), "低风险")

    def test_info(self):
        self.assertEqual(report.severity_label("info"), "待确认")

    def test_unknown(self):
        self.assertEqual(report.severity_label("unknown"), "待确认")

    def test_none(self):
        self.assertEqual(report.severity_label(None), "待确认")

    def test_case_insensitive(self):
        self.assertEqual(report.severity_label("HIGH"), "高风险")


# ---------------------------------------------------------------------------
# is_hygiene_only
# ---------------------------------------------------------------------------
class IsHygieneOnlyTests(unittest.TestCase):
    def test_hygiene_mode(self):
        self.assertTrue(
            report.is_hygiene_only({"scan_config": {"scan_mode": "hygiene_only"}})
        )

    def test_full_scan(self):
        self.assertFalse(
            report.is_hygiene_only(
                {"scan_config": {"scan_mode": "full_dependency_scan"}}
            )
        )

    def test_missing_config(self):
        self.assertFalse(report.is_hygiene_only({}))


# ---------------------------------------------------------------------------
# security_ids
# ---------------------------------------------------------------------------
class SecurityIdsTests(unittest.TestCase):
    def test_advisory_id(self):
        self.assertEqual(
            report.security_ids({"advisory_id": "GHSA-aaaa-bbbb-cccc"}),
            ["GHSA-aaaa-bbbb-cccc"],
        )

    def test_aliases_list(self):
        self.assertEqual(
            report.security_ids({"aliases": ["GHSA-xxxx-xxxx-xxxx", "CVE-2024-0001"]}),
            ["CVE-2024-0001", "GHSA-xxxx-xxxx-xxxx"],
        )

    def test_cve_fields_are_included_before_ghsa(self):
        self.assertEqual(
            report.security_ids(
                {
                    "cve_id": "CVE-2024-0002",
                    "cve_ids": ["CVE-2024-0001", "CVE-2024-0002"],
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                }
            ),
            ["CVE-2024-0001", "CVE-2024-0002", "GHSA-aaaa-bbbb-cccc"],
        )

    def test_comma_separated(self):
        self.assertEqual(
            report.security_ids(
                {"advisory_ids": "GHSA-aaaa-bbbb-cccc, GHSA-dddd-eeee-ffff"}
            ),
            ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"],
        )

    def test_deduplicates(self):
        ids = report.security_ids(
            {
                "advisory_id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
            }
        )
        self.assertEqual(ids, ["GHSA-aaaa-bbbb-cccc"])

    def test_no_ids(self):
        self.assertEqual(report.security_ids({}), [])

    def test_rejects_malicious_markdown_link_fragments(self):
        self.assertEqual(
            report.security_ids(
                {
                    "advisory_id": "GHSA-aaaa-bbbb-cccc](javascript:alert(1))",
                    "aliases": ["CVE-2024-0001](https://evil.example)"],
                }
            ),
            [],
        )


class SecurityIdMarkdownTests(unittest.TestCase):
    def test_non_cve_url_is_encoded(self):
        self.assertEqual(
            report.security_id_url("PYSEC-2026-1 test"),
            "https://osv.dev/vulnerability/PYSEC-2026-1%20test",
        )


# ---------------------------------------------------------------------------
# render_summary
# ---------------------------------------------------------------------------
class RenderSummaryTests(unittest.TestCase):
    def test_full_summary(self):
        analysis = {
            "summary": {
                "tldr": "发现高风险漏洞",
                "detail": "详细信息",
                "priority": ["优先处理紧急项"],
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_summary(analysis)
        self.assertIn("发现高风险漏洞", result)
        self.assertIn("详细信息", result)
        self.assertIn("优先处理紧急项", result)
        self.assertIn("能力边界", result)
        self.assertIn("安全的价值不只在于发现问题", result)
        self.assertNotIn("SSH", result)
        self.assertNotIn("inventory", result)
        self.assertNotIn("服务器漏洞", result)

    def test_hygiene_only(self):
        analysis = {
            "summary": {"tldr": "仓库安检"},
            "scan_config": {"scan_mode": "hygiene_only"},
        }
        result = report.render_summary(analysis)
        self.assertIn("暂无法执行依赖漏洞扫描", result)

    def test_missing_summary(self):
        result = report.render_summary({})
        self.assertIn("没有生成摘要", result)


# ---------------------------------------------------------------------------
# render_vulnerabilities
# ---------------------------------------------------------------------------
class RenderVulnerabilitiesTests(unittest.TestCase):
    def test_with_issues(self):
        analysis = {
            "top_issues": [
                {
                    "severity": "high",
                    "package": "lodash",
                    "version": "4.17.20",
                    "fixed_versions": ["4.17.21"],
                    "summary": "Prototype pollution",
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2024-0001"],
                    "cve_enrichments": [
                        {
                            "cveId": "CVE-2024-0001",
                            "nvdPublishedAt": "2024-05-01T00:00:00.000Z",
                            "cvssMetrics": [
                                {
                                    "baseScore": "8.8",
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            ],
                            "cweIds": ["CWE-400"],
                            "epss": "0.0004",
                            "epssPercentile": "0.128",
                            "epssScoreDate": "2026-06-06T00:00:00.000Z",
                            "kevListed": True,
                        }
                    ],
                }
            ],
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_vulnerabilities(analysis)
        self.assertIn("lodash", result)
        self.assertIn("4.17.21", result)
        self.assertIn("高风险", result)
        self.assertIn(
            "[GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc)",
            result,
        )
        self.assertIn(
            "[CVE-2024-0001](https://www.cve.org/CVERecord?id=CVE-2024-0001)", result
        )
        self.assertIn(
            "| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |", result
        )
        self.assertNotIn("说明", result)
        self.assertNotIn("Prototype pollution", result)
        self.assertNotIn("EPSS 12.8%", result)

    def test_fixed_versions_below_current_version_are_removed(self):
        result = report.render_vulnerabilities(
            {
                "top_issues": [
                    {
                        "severity": "high",
                        "package": "django",
                        "version": "2.2.0",
                        "fixed_versions": ["1.11.23", "2.2.28", "3.2.25"],
                        "advisory_id": "PYSEC-2024-1",
                    }
                ],
                "scan_config": {"scan_mode": "full_dependency_scan"},
            }
        )

        self.assertIn("| 高风险 | django | 2.2.0 | 2.2.28 |", result)
        self.assertNotIn("1.11.23", result)
        self.assertNotIn("3.2.25", result)

    def test_malicious_security_id_does_not_break_markdown_link(self):
        result = report.render_vulnerabilities(
            {
                "top_issues": [
                    {
                        "severity": "high",
                        "package": "bad-lib",
                        "version": "1.0.0",
                        "summary": "Bad advisory",
                        "advisory_id": "GHSA-aaaa-bbbb-cccc](javascript:alert(1))",
                    }
                ],
                "scan_config": {"scan_mode": "full_dependency_scan"},
            }
        )

        self.assertIn("| 高风险 | bad-lib | 1.0.0 | 待确认 | - |", result)
        self.assertNotIn("javascript:", result)
        self.assertNotIn("evil.example", result)

    def test_no_issues_full_scan(self):
        result = report.render_vulnerabilities(
            {"scan_config": {"scan_mode": "full_dependency_scan"}}
        )
        self.assertIn("未命中已确认的依赖风险项", result)

    def test_no_issues_hygiene_only(self):
        result = report.render_vulnerabilities(
            {"scan_config": {"scan_mode": "hygiene_only"}}
        )
        self.assertIn("暂无法执行依赖漏洞扫描", result)


# ---------------------------------------------------------------------------
# render_hygiene
# ---------------------------------------------------------------------------
class RenderHygieneTests(unittest.TestCase):
    def test_all_clean(self):
        result = report.render_hygiene({"hygiene": {}})
        self.assertIn("没有发现硬编码密钥", result)

    def test_with_secrets(self):
        analysis = {
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": "src/config.ts",
                        "line": 12,
                        "type": "generic_sk_key",
                        "confidence": "high",
                        "preview": "sk-***",
                    }
                ],
            }
        }
        result = report.render_hygiene(analysis)
        self.assertIn("src/config.ts:12", result)
        self.assertIn("LLM/API 密钥", result)
        self.assertNotIn("generic_sk_key", result)

    def test_with_sensitive_tracked(self):
        analysis = {
            "hygiene": {
                "sensitive_tracked": [
                    {"file": ".env", "type": "env_file", "size": 128},
                ],
            }
        }
        result = report.render_hygiene(analysis)
        self.assertIn(".env", result)
        self.assertIn("环境变量文件", result)
        self.assertNotIn("env_file", result)

    def test_secret_type_labels_cover_scan_secret_types(self):
        scan_secret_types = {secret_type for secret_type, _ in scan_mod.SECRET_REGEXES}
        self.assertEqual(scan_secret_types - set(report.SECRET_TYPE_LABELS), set())

    def test_sensitive_type_labels_cover_scan_sensitive_types(self):
        scan_sensitive_types = {
            file_type for file_type, _ in scan_mod.SENSITIVE_FILE_PATTERNS
        }
        self.assertEqual(
            scan_sensitive_types - set(report.SENSITIVE_TYPE_LABELS), set()
        )

    def test_with_gitignore_missing(self):
        analysis = {
            "hygiene": {"gitignore_missing": [".env", "*.pem"]},
        }
        result = report.render_hygiene(analysis)
        self.assertIn(".env", result)
        self.assertIn("*.pem", result)

    def test_with_gitignore_state(self):
        analysis = {
            "hygiene": {},
            "butian_workspace": {
                "gitignore": {"preexisting": True, "added_butian_entry": True},
            },
        }
        result = report.render_hygiene(analysis)
        self.assertNotIn("本次是否新增 `.butian/`", result)
        self.assertNotIn("工作区忽略规则", result)

    def test_with_structured_local_checks(self):
        analysis = {
            "hygiene": {
                "workflow_checks": [
                    {
                        "id": "actions.remote_script_pipe",
                        "category": "github_actions",
                        "severity": "medium",
                        "confidence": "high",
                        "file": ".github/workflows/ci.yml",
                        "line": 5,
                        "title": "workflow 直接执行远程脚本",
                        "evidence": "run: curl https://example.com/install.sh | bash",
                        "recommendation": "下载固定版本并校验 checksum/signature，或使用可信 action/包管理器替代。",
                    }
                ],
                "iac_checks": [
                    {
                        "id": "iac.docker_latest_tag",
                        "category": "iac_container",
                        "severity": "medium",
                        "confidence": "high",
                        "file": "Dockerfile",
                        "line": 1,
                        "title": "Dockerfile 使用 latest 镜像标签",
                        "evidence": "FROM node:latest",
                        "recommendation": "固定版本标签。",
                    }
                ],
            }
        }

        result = report.render_hygiene(analysis)

        self.assertIn("GitHub Actions 工作流安全", result)
        self.assertIn("workflow 直接执行远程脚本", result)
        self.assertIn("checksum/signature", result)
        self.assertIn("IaC / 容器 / 部署配置", result)
        self.assertIn("Dockerfile:1", result)
        self.assertIn("| 等级 | 位置 | 检查项 | 依据 | 处理 |", result)
        self.assertIn("run: curl https://example.com/install.sh", result)

    def test_dependabot_is_rendered_as_maintenance_advice(self):
        analysis = {
            "hygiene": {
                "repository_checks": [
                    {
                        "id": "repo.missing_dependabot",
                        "category": "repo_governance",
                        "severity": "info",
                        "confidence": "high",
                        "file": ".github/dependabot.yml",
                        "title": "配置 Dependabot",
                        "evidence": "",
                        "recommendation": "建议新增 .github/dependabot.yml，让 GitHub 按计划检查 .github/workflows 中引用的 Action 版本；如项目还有 npm、pip 等依赖，再补充对应包管理生态，后续通过 Dependabot PR 或通知处理更新。",
                        "kind": "maintenance_advice",
                    }
                ]
            }
        }

        result = report.render_hygiene(analysis)

        self.assertIn("| 建议 | .github/dependabot.yml | 配置 Dependabot |", result)
        self.assertIn("| 等级 | 位置 | 检查项 | 处理 |", result)
        self.assertNotIn("| 等级 | 位置 | 检查项 | 依据 | 处理 |", result)
        self.assertNotIn("维护建议", result)


# ---------------------------------------------------------------------------
# render_outdated
# ---------------------------------------------------------------------------
class RenderOutdatedTests(unittest.TestCase):
    def test_with_outdated(self):
        analysis = {
            "outdated": [
                {
                    "package": "react",
                    "current": "18.2.0",
                    "latest": "19.1.0",
                    "ecosystem": "npm",
                },
            ],
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_outdated(analysis)
        self.assertIn("react", result)
        self.assertIn("18.2.0", result)
        self.assertIn("19.1.0", result)
        self.assertIn("版本维护优化项", result)
        self.assertIn("发布窗口", result)

    def test_no_outdated(self):
        result = report.render_outdated(
            {"scan_config": {"scan_mode": "full_dependency_scan"}}
        )
        self.assertIn("没有检测到", result)
        self.assertIn("版本维护规划", result)
        self.assertIn("发布窗口", result)

    def test_hygiene_only(self):
        result = report.render_outdated({"scan_config": {"scan_mode": "hygiene_only"}})
        self.assertIn("暂无法执行", result)
        self.assertIn("版本维护规划", result)
        self.assertIn("发布窗口", result)


# ---------------------------------------------------------------------------
# render_server_environment
# ---------------------------------------------------------------------------
class RenderServerEnvironmentTests(unittest.TestCase):
    def test_render_server_environment_with_confirmed_issue_and_maintenance(self):
        analysis = {
            "server": {
                "summary": {
                    "package_count": 3,
                    "confirmed_count": 1,
                    "maintenance_count": 1,
                    "public_port_count": 2,
                    "service_count": 4,
                    "software_version_count": 3,
                    "native_security_update_count": 2,
                },
            },
            "server_issues": [
                {
                    "package": "nginx",
                    "version": "1.24.0",
                    "severity": "high",
                    "summary": "nginx confirmed",
                    "aliases": ["CVE-2026-0001"],
                }
            ],
            "server_maintenance": [
                {
                    "title": "Docker 容器 web 使用旧镜像标签 nginx:1.18",
                    "summary": "只基于明确镜像标签，作为维护建议处理。",
                }
            ],
        }

        result = report.render_server_environment(analysis)

        self.assertIn("系统包数量：3", result)
        self.assertIn("已确认服务器风险：1", result)
        self.assertIn("维护建议：1", result)
        self.assertIn("对外监听端口：2", result)
        self.assertIn("运行服务：4", result)
        self.assertIn("常见软件版本：3", result)
        self.assertIn("安全更新线索：2", result)
        self.assertIn("### 已确认服务器风险", result)
        self.assertIn("nginx", result)
        self.assertIn(
            "[CVE-2026-0001](https://www.cve.org/CVERecord?id=CVE-2026-0001)",
            result,
        )
        self.assertIn("### 维护建议", result)
        self.assertIn("Docker 容器 web 使用旧镜像标签", result)
        self.assertLess(
            result.index("### 已确认服务器风险"), result.index("### 维护建议")
        )

    def test_render_server_environment_empty(self):
        self.assertEqual(
            report.render_server_environment({}), "未启用服务器运行环境扫描。"
        )


# ---------------------------------------------------------------------------
# Markdown structure
# ---------------------------------------------------------------------------
class RenderMarkdownStructureTests(unittest.TestCase):
    def test_render_markdown_includes_server_environment_section(self):
        markdown = report.render_markdown(
            {
                "project": {"name": "demo", "path": "/tmp/demo"},
                "generated_at": "2026-06-09 12:00:00",
                "scan_seconds": 1,
                "summary": {"tldr": "demo", "detail": "demo", "priority": []},
                "server": {
                    "summary": {
                        "package_count": 3,
                        "confirmed_count": 1,
                        "maintenance_count": 0,
                        "public_port_count": 1,
                    }
                },
                "server_issues": [
                    {
                        "package": "openssl",
                        "version": "3.0.2",
                        "summary": "openssl confirmed",
                    }
                ],
                "hygiene": {"gitignore_missing": [".env"]},
                "errors": [{"step": "server_collect", "message": "SSH timeout"}],
            }
        )

        self.assertIn("## 服务器运行环境", markdown)
        self.assertNotIn("未启用服务器运行环境扫描", markdown)
        self.assertIn("openssl confirmed", markdown)
        self.assertIn("## 覆盖说明", markdown)
        self.assertNotIn("## 需要人工确认的事项", markdown)
        self.assertLess(
            markdown.index("## 报告总结"), markdown.index("## 当前风险")
        )
        self.assertIn("[server_collect] SSH timeout", markdown)

    def test_render_markdown_omits_llm_fix_context_section(self):
        markdown = report.render_markdown(
            {
                "project": {"name": "demo", "path": "/tmp/demo"},
                "generated_at": "2026-06-08 12:00:00",
                "scan_seconds": 1,
                "top_issues": [
                    {
                        "severity": "high",
                        "package": "lodash",
                        "version": "4.17.20",
                        "fixed_versions": ["4.17.21"],
                    }
                ],
            }
        )
        self.assertIn("## 当前风险", markdown)
        self.assertIn("lodash", markdown)
        self.assertIn("4.17.20", markdown)
        self.assertIn("4.17.21", markdown)
        self.assertNotIn("## 大模型修复上下文", markdown)
        self.assertNotIn("FIX-001", markdown)
        self.assertNotIn("本节用于后续人工或大模型修复", markdown)


# ---------------------------------------------------------------------------
# render_manual_items
# ---------------------------------------------------------------------------
class RenderManualItemsTests(unittest.TestCase):
    def test_with_items(self):
        analysis = {
            "red": [
                {
                    "name": "密钥已入 git 历史",
                    "severity": "critical",
                    "path": ".env.production",
                    "why_keep": "需确认",
                    "risk": "凭证泄露",
                    "indirect_release": "轮换后清理",
                }
            ],
            "yellow": [],
        }
        result = report.render_manual_items(analysis)
        self.assertIn("密钥已入 git 历史", result)
        self.assertIn("紧急", result)
        self.assertIn("需确认", result)

    def test_empty(self):
        result = report.render_manual_items({"red": [], "yellow": []})
        self.assertIn("没有需要额外人工确认", result)

    def test_low_evidence_server_clues_are_not_manual_items(self):
        analysis = {
            "red": [],
            "yellow": [
                {
                    "name": "仅由服务版本推断的 nginx 风险",
                    "source": "服务器扫描",
                    "kind": "低证据",
                    "evidence_level": "low",
                    "why_manual": "只有服务 banner，没有发行版包公告闭环。",
                }
            ],
        }

        result = report.render_manual_items(analysis)

        self.assertIn("没有需要额外人工确认", result)
        self.assertNotIn("nginx", result)


# ---------------------------------------------------------------------------
# render_errors
# ---------------------------------------------------------------------------
class RenderErrorsTests(unittest.TestCase):
    def test_with_errors(self):
        analysis = {
            "errors": [{"step": "vulnerability_check", "message": "NVD timeout"}]
        }
        result = report.render_errors(analysis)
        self.assertIn("vulnerability_check", result)
        self.assertIn("NVD timeout", result)

    def test_no_errors(self):
        result = report.render_errors({})
        self.assertIn("没有记录到扫描错误", result)


# ---------------------------------------------------------------------------
# render_next_steps
# ---------------------------------------------------------------------------
class RenderNextStepsTests(unittest.TestCase):
    def test_with_priority(self):
        analysis = {"summary": {"priority": ["先升 lodash", "再补 gitignore"]}}
        result = report.render_next_steps(analysis)
        self.assertIn("先升 lodash", result)

    def test_no_priority(self):
        result = report.render_next_steps({})
        self.assertIn("阅读报告后再决定是否修复", result)

    def test_dependency_fix_notes_rescan_and_transitive_residuals(self):
        analysis = {
            "green": [
                {
                    "type": "dependency_upgrade",
                    "package": "postcss",
                    "fix_config": {
                        "upgrade_scope": "direct_package",
                        "residual_guidance": "复扫仍出现同名旧版本时，通常是间接依赖被父包锁定。",
                    },
                }
            ]
        }
        result = report.render_next_steps(analysis)
        self.assertIn("重新运行扫描", result)
        self.assertIn("父依赖信息", result)
        self.assertIn("升级父依赖", result)
        self.assertIn("确认风险项是否真正消失", result)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class ParseArgsTests(unittest.TestCase):
    def test_required_only(self):
        args = report.parse_args(["analysis.json"])
        self.assertEqual(args.analysis_json, "analysis.json")
        self.assertIsNone(args.output_markdown)

    def test_with_output(self):
        args = report.parse_args(["analysis.json", "report.md"])
        self.assertEqual(args.output_markdown, "report.md")


# ---------------------------------------------------------------------------
# default_output_path
# ---------------------------------------------------------------------------
class DefaultOutputPathTests(unittest.TestCase):
    def test_generates_path_under_docs(self):
        analysis = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"path": "/tmp/test-project"},
            "butian_workspace": {"run_dir": "/tmp/test-project/.butian/20260608-1200"},
        }
        with tempfile.TemporaryDirectory(prefix="butian-report-") as root:
            analysis["project"]["path"] = root
            analysis["butian_workspace"]["run_dir"] = os.path.join(
                root, ".butian", "20260608-1200"
            )
            path = report.default_output_path(analysis)
            self.assertTrue(path.endswith("security-report-20260608-1200.md"))
            self.assertIn("docs/butian", path)


# ---------------------------------------------------------------------------
# pipeline: --help
# ---------------------------------------------------------------------------
class PipelineHelpTests(unittest.TestCase):
    def test_report_help(self):
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        result = subprocess.run(
            [sys.executable, os.path.join("butian", "scripts", "report.py"), "--help"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
