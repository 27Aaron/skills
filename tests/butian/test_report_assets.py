import json
import os
import shutil
import subprocess
import textwrap
import unittest
from datetime import datetime, timedelta, timezone

from butian.scripts import report

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORT_CSS = os.path.join(ROOT, "butian", "templates", "report.css")
REPORT_JS = os.path.join(ROOT, "butian", "templates", "report.js")


class ButianReportAssetTests(unittest.TestCase):
    def test_markdown_hygiene_only_warns_dependency_scan_was_not_run(self):
        analysis = {
            "generated_at": "2026-06-05 09:05:50",
            "scan_seconds": 0.1,
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": [],
                "total_packages": 0,
            },
            "scan_config": {"scan_mode": "hygiene_only"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {},
            "outdated": [],
            "red": [],
            "yellow": [],
            "errors": [],
        }

        markdown = report.render_markdown(analysis)

        self.assertIn("暂无法执行依赖漏洞扫描", markdown)
        self.assertIn("仓库安检", markdown)
        self.assertNotIn("未命中已确认的依赖风险项。", markdown)

    def test_markdown_info_severity_is_pending_not_low_risk(self):
        analysis = {
            "generated_at": "2026-06-05 09:05:50",
            "scan_seconds": 0.1,
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 1,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": "curious-lib",
                    "version": "1.0.0",
                    "severity": "info",
                    "advisory_id": "GHSA-test-info",
                    "summary": "命中公开漏洞，但严重度数据不足，需要复核公告影响范围。",
                }
            ],
            "hygiene": {},
            "outdated": [],
            "red": [],
            "yellow": [],
            "errors": [],
        }

        markdown = report.render_markdown(analysis)

        self.assertIn("| 待确认 | curious-lib | 1.0.0 |", markdown)
        self.assertNotIn("| 低风险 | curious-lib | 1.0.0 |", markdown)

    def test_html_hygiene_only_warns_dependency_scan_was_not_run(self):
        if not shutil.which("node"):
            self.skipTest("node is required for report asset rendering tests")

        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": [],
                "total_packages": 0,
            },
            "scan_config": {"scan_mode": "hygiene_only"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {},
            "outdated": [],
        }
        code = textwrap.dedent(
            f"""
            const fs = require("fs");
            const vm = require("vm");
            const elements = {{
              meta: {{ textContent: "" }},
              app: {{ innerHTML: "" }},
            }};
            const context = {{
              window: {{
                __BUTIAN_REPORT_DATA__: {json.dumps(data)},
                location: {{ href: "file:///tmp/report.html" }},
              }},
              document: {{
                getElementById: (id) => elements[id],
                addEventListener: () => {{}},
              }},
              navigator: {{ clipboard: {{ writeText: () => Promise.resolve() }} }},
              atob: (value) => Buffer.from(value, "base64").toString("binary"),
              btoa: (value) => Buffer.from(value, "binary").toString("base64"),
              setTimeout: () => {{}},
              console,
            }};
            vm.createContext(context);
            vm.runInContext(fs.readFileSync({json.dumps(REPORT_JS)}, "utf8"), context);
            process.stdout.write(elements.app.innerHTML);
            """
        )

        result = subprocess.run(
            ["node", "-e", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        html = result.stdout

        self.assertIn("暂无法执行依赖漏洞扫描", html)
        self.assertIn("仓库安检", html)
        self.assertNotIn("未命中已确认的依赖风险项", html)

    def test_fixed_versions_render_as_wrapping_chips(self):
        if not shutil.which("node"):
            self.skipTest("node is required for report asset rendering tests")

        published_at = (
            datetime.now(timezone.utc) - timedelta(days=45)
        ).isoformat().replace("+00:00", "Z")
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "risk_summary": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 1,
                "info": 1,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": ["demo"]},
            "top_issues": [
                {
                    "package": "uuid",
                    "version": "13.0.0",
                    "severity": "high",
                    "fixed_versions": ["11.1.1", "12.0.1", "13.0.1"],
                    "advisory_id": "GHSA-w5hq-g745-h8pq",
                    "summary": "Missing buffer bounds check",
                    "cve_enrichments": [
                        {
                            "description": "A crafted request may exhaust service resources.",
                            "nvdPublishedAt": published_at,
                            "cvssMetrics": [
                                {
                                    "version": "3.1",
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                                    "baseScore": "7.5",
                                }
                            ],
                            "cweIds": ["CWE-400"],
                            "epss": "0.0004",
                            "epssPercentile": "0.128",
                            "epssScoreDate": "2026-06-06T00:00:00.000Z",
                        }
                    ],
                },
                {
                    "package": "curious-lib",
                    "version": "1.0.0",
                    "severity": "info",
                    "fixed_versions": [],
                    "advisory_id": "GHSA-test-info",
                    "summary": "Severity data is not available yet",
                },
            ],
            "outdated": [
                {
                    "package": "hono",
                    "current": "4.12.14",
                    "latest": "4.12.21",
                    "ecosystem": "npm",
                },
                *[
                    {
                        "package": f"demo-lib-{idx}",
                        "current": "1.0.0",
                        "latest": "1.0.1",
                        "ecosystem": "npm",
                    }
                    for idx in range(6)
                ],
                {
                    "package": "@scope/very-long-hidden-package-name",
                    "current": "2026.10.100",
                    "latest": "2026.11.101",
                    "ecosystem": "npm",
                },
            ],
        }
        code = textwrap.dedent(
            f"""
            const fs = require("fs");
            const vm = require("vm");
            const elements = {{
              meta: {{ textContent: "" }},
              app: {{ innerHTML: "" }},
            }};
            const context = {{
              window: {{
                __BUTIAN_REPORT_DATA__: {json.dumps(data)},
                location: {{ href: "file:///tmp/report.html" }},
              }},
              document: {{
                getElementById: (id) => elements[id],
                addEventListener: () => {{}},
              }},
              navigator: {{ clipboard: {{ writeText: () => Promise.resolve() }} }},
              atob: (value) => Buffer.from(value, "base64").toString("binary"),
              btoa: (value) => Buffer.from(value, "binary").toString("base64"),
              setTimeout: () => {{}},
              console,
            }};
            vm.createContext(context);
            vm.runInContext(fs.readFileSync({json.dumps(REPORT_JS)}, "utf8"), context);
            process.stdout.write(elements.app.innerHTML);
            """
        )

        result = subprocess.run(
            ["node", "-e", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        html = result.stdout

        self.assertIn('<div class="k">风险等级</div>', html)
        self.assertIn("风险项分布", html)
        self.assertIn("当前风险", html)
        self.assertIn("<th>影响程度</th>", html)
        self.assertNotIn("风险等级分布", html)
        self.assertNotIn("<th>严重程度</th>", html)
        self.assertIn("<th>依赖名称</th>", html)
        self.assertIn("<th>当前版本</th>", html)
        self.assertIn("<th>最近版本</th>", html)
        self.assertNotIn("<th>生态</th>", html)
        self.assertNotIn("<td>npm</td>", html)
        self.assertIn("--outdated-current-col:", html)
        self.assertIn("--outdated-latest-col:", html)
        self.assertIn('class="outdated-extra"', html)
        self.assertIn("@scope/very-long-hidden-package-name", html)
        self.assertNotIn("信息 <b>", html)
        self.assertIn("待确认 <b>1</b>", html)
        self.assertIn('class="sev-badge sev-info">待确认</span>', html)
        self.assertIn('class="sev-badge sev-critical">紧急</span>', html)
        self.assertIn('class="sev-badge sev-high">高风险</span>', html)
        self.assertIn("紧急 <b>1</b>", html)
        self.assertIn("高风险 <b>1</b>", html)
        self.assertIn("中风险 <b>1</b>", html)
        self.assertIn("低风险 <b>1</b>", html)
        self.assertNotIn(">严重</span>", html)
        self.assertNotIn(">高危</span>", html)
        self.assertNotIn(">中危", html)
        self.assertNotIn(">低危", html)
        self.assertNotIn("<span>能力边界</span>", html)
        self.assertNotIn("并跑一次测试", html)
        self.assertNotIn("可更新到", html)
        self.assertNotIn("最近可用版本为", html)
        self.assertIn(
            "有新版本 4.12.21 可用，建议在近期迭代中安排升级。",
            html,
        )
        self.assertIn('class="fixed-list"', html)
        self.assertEqual(html.count('class="fixed-chip"'), 3)
        self.assertNotIn("11.1.1、12.0.1、13.0.1", html)

        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()
        self.assertIn(".fixed-list", css)
        self.assertIn("grid-template-columns: repeat(2, max-content)", css)
        self.assertIn("td.fixed-cell", css)
        self.assertIn(".outdated-table .col-current", css)
        self.assertIn(".outdated-table .col-latest", css)
        self.assertIn('data-label="详情"', html)
        self.assertIn("@media (max-width: 860px)", css)
        self.assertIn(".vuln-table thead", css)
        self.assertIn('content: attr(data-label)', css)
        self.assertIn('class="vuln-detail-header"', html)
        self.assertIn('class="detail-dossier"', html)
        self.assertIn('class="detail-story"', html)
        self.assertIn('class="detail-action"', html)
        self.assertIn('class="detail-facts"', html)
        self.assertIn(">建议处理</div>", html)
        self.assertIn("建议升级到 13.0.1 或更高版本。升级后重新扫描", html)
        self.assertIn(
            'class="sig-tag sig-epss" title="EPSS 百分位 12.8%，30 天内被利用概率 0.04%">EPSS 12.8%</span>',
            html,
        )
        self.assertIn('class="sig-tag sig-age">已公开 1 个月</span>', html)
        self.assertIn(">远程可达</span>", html)
        self.assertIn(">可用性 高</span>", html)
        self.assertNotIn("🌐", html)
        self.assertNotIn("🔒", html)
        self.assertIn("--detail-panel-bg", css)
        self.assertIn("--detail-card-bg", css)
        self.assertNotIn("--detail-panel-bg: rgba(9, 30, 26, 0.76)", css)
        self.assertNotIn("--detail-card-bg: rgba(15, 39, 34, 0.78)", css)
        self.assertIn("--detail-panel-bg: rgba(17, 24, 29, 0.82)", css)
        self.assertIn("--detail-card-bg: rgba(255, 255, 255, 0.045)", css)
        self.assertIn("--vuln-row-open-bg: rgba(255, 255, 255, 0.055)", css)
        self.assertNotIn(".vuln-detail::before", css)
        self.assertNotIn("border: 1px solid var(--detail-card-border);", css)
        self.assertNotIn("background: var(--detail-card-bg)", css)
        self.assertNotIn("max-width: 92ch", css)
        self.assertIn("max-width: none", css)
        self.assertIn(".detail-dossier", css)
        self.assertIn(".detail-story", css)
        self.assertIn(".detail-action", css)
        self.assertIn(".detail-facts", css)
        self.assertIn("overflow-y: auto", css)
        self.assertIn(".sig-age", css)
        self.assertIn(".vuln-detail-header", css)
        self.assertNotIn("border-left-width: 4px", css)
        self.assertNotIn("border-left-color: var(--warning-ink)", css)

    def test_html_report_assets_do_not_ship_copy_command_handlers(self):
        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()

        self.assertNotIn("navigator.clipboard", js)
        self.assertNotIn('class="copy"', js)
        self.assertNotIn("function copyBtn", js)
        self.assertNotIn("function cmdBlock", js)

    def _render_html(self, data):
        if not shutil.which("node"):
            self.skipTest("node is required for report asset rendering tests")
        code = textwrap.dedent(
            f"""
            const fs = require("fs");
            const vm = require("vm");
            const elements = {{
              meta: {{ textContent: "" }},
              app: {{ innerHTML: "" }},
            }};
            const context = {{
              window: {{
                __BUTIAN_REPORT_DATA__: {json.dumps(data)},
                location: {{ href: "file:///tmp/report.html" }},
              }},
              document: {{
                getElementById: (id) => elements[id],
                addEventListener: () => {{}},
              }},
              navigator: {{ clipboard: {{ writeText: () => Promise.resolve() }} }},
              atob: (value) => Buffer.from(value, "base64").toString("binary"),
              btoa: (value) => Buffer.from(value, "binary").toString("base64"),
              setTimeout: () => {{}},
              console,
            }};
            vm.createContext(context);
            vm.runInContext(fs.readFileSync({json.dumps(REPORT_JS)}, "utf8"), context);
            process.stdout.write(elements.app.innerHTML);
            """
        )
        result = subprocess.run(
            ["node", "-e", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout

    def test_html_hides_empty_hygiene_section(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertNotIn('section-title">仓库安检', html)
        self.assertNotIn('仓库安检</span><span class="count">0 项', html)

    def test_html_keeps_hygiene_section_when_attention_items_exist(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {"gitignore_missing": [".env"]},
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn('section-title">仓库安检', html)
        self.assertIn("建议补充 .env", html)

    def test_html_renders_structured_local_hygiene_checks(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
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
                        "id": "iac.docker_secret_env",
                        "category": "iac_container",
                        "severity": "high",
                        "confidence": "high",
                        "file": "Dockerfile",
                        "line": 2,
                        "title": "Dockerfile ENV 中疑似写入敏感值",
                        "evidence": "ENV <SECRET>=...",
                        "recommendation": "改用运行时 secret 注入。",
                    }
                ],
            },
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn('section-title">仓库安检', html)
        self.assertIn("GitHub Actions 工作流安全", html)
        self.assertIn("workflow 直接执行远程脚本", html)
        self.assertIn("checksum/signature", html)
        self.assertIn("IaC / 容器 / 部署配置", html)
        self.assertIn("Dockerfile:2", html)
        self.assertIn('class="hygiene-group"', html)
        self.assertIn('class="hygiene-finding"', html)
        self.assertIn('class="hygiene-finding-note hygiene-finding-context"', html)
        self.assertNotIn("<span>依据</span>", html)
        self.assertNotIn("<span>处理</span>", html)

    def test_html_renders_dependabot_as_maintenance_advice(self):
        data = {
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 1,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
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
            },
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn("依赖配置与维护", html)
        self.assertIn('class="sev-badge sev-low">建议</span>', html)
        self.assertIn("配置 Dependabot", html)
        self.assertNotIn("检测到 .github/workflows/", html)
        self.assertNotIn("dependabot.yml not found", html)
        self.assertNotIn("维护建议", html)
        self.assertNotIn("有 1 条", html)

    def test_tldr_fallback_uses_risk_item_term_for_critical_high(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "risk_summary": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {},
            "top_issues": [
                {
                    "package": "bad-pkg",
                    "version": "1.0.0",
                    "severity": "critical",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": "GHSA-test",
                    "summary": "test vuln",
                }
            ],
            "hygiene": {},
            "outdated": [],
        }
        html = self._render_html(data)
        self.assertIn("已确认依赖风险项", html)

    def test_tldr_fallback_uses_risk_item_term_for_unknown_severity(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 2,
            },
            "summary": {},
            "top_issues": [
                {
                    "package": "curious-lib",
                    "version": "1.0.0",
                    "severity": "info",
                    "fixed_versions": [],
                    "advisory_id": "GHSA-test-info",
                    "summary": "severity unknown",
                },
                {
                    "package": "other-lib",
                    "version": "2.0.0",
                    "severity": "info",
                    "fixed_versions": [],
                    "advisory_id": "GHSA-test-info2",
                    "summary": "severity unknown 2",
                },
            ],
            "hygiene": {},
            "outdated": [],
        }
        html = self._render_html(data)
        self.assertIn("命中已确认风险项", html)

    def test_detail_and_priority_fallback_use_risk_item_term(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "risk_summary": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {},
            "top_issues": [
                {
                    "package": "bad-pkg",
                    "version": "1.0.0",
                    "severity": "high",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": "GHSA-test",
                    "summary": "test vuln",
                }
            ],
            "hygiene": {},
            "outdated": [],
        }
        html = self._render_html(data)
        self.assertIn("识别出 1 个已确认风险项", html)
        self.assertIn("已确认依赖风险项", html)

    def test_readable_tldr_and_detail_use_risk_item_term(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 5,
            },
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "", "detail": "", "priority": []},
            "top_issues": [
                {
                    "package": "bad-pkg",
                    "version": "1.0.0",
                    "severity": "medium",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": "GHSA-test",
                    "summary": "test vuln",
                }
            ],
            "hygiene": {},
            "outdated": [],
        }
        html = self._render_html(data)
        self.assertIn("已确认依赖风险项", html)
        self.assertIn("已确认风险项", html)

    def test_outdated_section_uses_risk_item_term(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": ["demo"]},
            "top_issues": [],
            "hygiene": {},
            "outdated": [],
        }
        html = self._render_html(data)
        self.assertIn("版本维护规划", html)
        self.assertIn("发布窗口", html)


if __name__ == "__main__":
    unittest.main()
