"""Unit tests for butian/scripts/report.py — Markdown report rendering."""

import os
import subprocess
import sys
import tempfile
import unittest

from butian.scripts import report, scan as scan_mod


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
                }
            ],
            "scan_config": {"scan_mode": "full_dependency_scan"},
        }
        result = report.render_vulnerabilities(analysis)
        self.assertIn("lodash", result)
        self.assertIn("4.17.21", result)
        self.assertIn("高风险", result)
        self.assertIn("[GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc)", result)
        self.assertIn("[CVE-2024-0001](https://www.cve.org/CVERecord?id=CVE-2024-0001)", result)
        self.assertIn("| 影响程度 | 依赖名称 | 当前版本 | 安全编号 | 修复版本 | 说明 |", result)

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
        self.assertEqual(scan_sensitive_types - set(report.SENSITIVE_TYPE_LABELS), set())

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
# render_llm_fix_context
# ---------------------------------------------------------------------------
class RenderLlmFixContextTests(unittest.TestCase):
    def test_full_context_keeps_dependency_hygiene_and_outdated_fix_fields(self):
        analysis = {
            "top_issues": [
                {
                    "severity": "high",
                    "package": "postcss",
                    "version": "8.4.31",
                    "fixed_versions": ["8.4.38"],
                    "advisory_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2024-0001"],
                    "summary": "存在公开漏洞。",
                    "cve_enrichments": [
                        {
                            "cveId": "CVE-2024-0001",
                            "description": "NVD supplied vulnerability description.",
                            "nvdPublishedAt": "2024-05-01T00:00:00.000Z",
                            "cvssMetrics": [
                                {
                                    "version": "3.1",
                                    "baseScore": "8.8",
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            ],
                            "cweIds": ["CWE-400", "CWE-770"],
                            "epss": "0.0004",
                            "epssPercentile": "0.128",
                            "epssScoreDate": "2026-06-06T00:00:00.000Z",
                            "kevListed": True,
                            "kevDateAdded": "2024-05-10",
                            "kevDueDate": "2024-06-01",
                            "kevKnownRansomwareCampaignUse": "Known",
                            "kevRequiredAction": "Apply mitigations per vendor instructions.",
                        }
                    ],
                    "dependency_context": {
                        "kind": "nested_locked",
                        "locations": [
                            {
                                "parent": "next",
                                "parent_range": "^8.4.0",
                                "path": "node_modules/next/node_modules/postcss",
                            }
                        ],
                        "top_level_versions": ["8.4.40"],
                    },
                }
            ],
            "green": [
                {
                    "type": "dependency_upgrade",
                    "package": "postcss",
                    "fix_config": {
                        "ecosystem": "npm",
                        "package": "postcss",
                        "current_versions": ["8.4.31"],
                        "target_version": "8.4.38",
                        "upgrade_scope": "nested_parent",
                        "residual_guidance": "先升级父依赖 next。",
                    },
                }
            ],
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": "src/config.ts",
                        "line": 7,
                        "type": "openai_key",
                        "confidence": "high",
                        "preview": "sk-***",
                    }
                ],
                "gitignore_missing": [".env"],
                "workflow_checks": [
                    {
                        "id": "actions.remote_script_pipe",
                        "category": "github_actions",
                        "severity": "medium",
                        "confidence": "high",
                        "file": ".github/workflows/ci.yml",
                        "line": 12,
                        "title": "workflow 直接执行远程脚本",
                        "evidence": "run: curl https://example.com/install.sh | bash",
                        "recommendation": "固定版本并校验 checksum。",
                    }
                ],
            },
            "outdated": [
                {
                    "package": "react",
                    "ecosystem": "npm",
                    "current": "18.2.0",
                    "wanted": "18.3.1",
                    "latest": "19.1.0",
                }
            ],
        }

        result = report.render_llm_fix_context(analysis)

        self.assertIn("### FIX-001 依赖漏洞：postcss", result)
        self.assertIn("- 安全编号：[CVE-2024-0001](https://www.cve.org/CVERecord?id=CVE-2024-0001)、[GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc)", result)
        self.assertIn("- EPSS：30 天内被利用概率 0.04%；百分位 12.8%；评分日期 2026-06-06。", result)
        self.assertIn("- CVSS：最高分 8.8；向量 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`。", result)
        self.assertIn("- CWE：CWE-400、CWE-770。", result)
        self.assertIn("- CISA KEV：已收录；收录日期 2024-05-10；修复截止 2024-06-01；已知勒索软件利用；处置要求 Apply mitigations per vendor instructions.。", result)
        self.assertIn("- NVD 发布时间：2024-05-01。", result)
        self.assertIn("- 修复配置：生态 npm；包 postcss；目标版本 8.4.38；范围 nested_parent。", result)
        self.assertIn("- 嵌套依赖：父依赖 next；父依赖版本范围 ^8.4.0；顶层版本 8.4.40；位置 node_modules/next/node_modules/postcss。", result)
        self.assertIn("### FIX-002 硬编码密钥：src/config.ts:7", result)
        self.assertIn("- 密钥类型：OpenAI API Key", result)
        self.assertIn("### FIX-003 .gitignore 规则补充", result)
        self.assertIn("- 需要补充：`.env`", result)
        self.assertIn("### FIX-004 仓库安检：workflow 直接执行远程脚本", result)
        self.assertIn("- 来源 ID：actions.remote_script_pipe", result)
        self.assertIn("### FIX-005 过期依赖：react", result)
        self.assertIn("- 跨大版本：是", result)

    def test_empty_context_has_clear_message(self):
        result = report.render_llm_fix_context({})
        self.assertIn("没有可供大模型修复的结构化事项", result)

    def test_render_markdown_includes_llm_fix_context_section(self):
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
        self.assertIn("## 大模型修复上下文", markdown)
        self.assertIn("### FIX-001 依赖漏洞：lodash", markdown)


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
        self.assertIn("重新运行补天扫描", result)
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
