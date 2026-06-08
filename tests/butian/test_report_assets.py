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
            (datetime.now(timezone.utc) - timedelta(days=45))
            .isoformat()
            .replace("+00:00", "Z")
        )
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
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
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
        self.assertIn("content: attr(data-label)", css)
        self.assertIn("--mobile-risk-label-col: clamp(76px, 18vw, 108px);", css)
        self.assertIn(
            "grid-template-columns: var(--mobile-risk-label-col) minmax(0, 1fr);",
            css,
        )
        self.assertIn(".vuln-table td.sev .sev-badge", css)
        self.assertIn("justify-self: start;", css)
        self.assertNotIn(
            "@media (max-width: 520px) {\n    .vuln-table td,\n    .outdated-table td {",
            css,
        )
        self.assertIn(
            "@media (max-width: 440px) {\n    .vuln-table td,\n    .outdated-table td {",
            css,
        )
        self.assertIn('class="detail-dossier detail-dossier-split"', html)
        self.assertIn('class="detail-story"', html)
        self.assertIn('class="detail-signal-row"', html)
        self.assertIn('class="detail-story-heading"', html)
        self.assertIn(
            'class="detail-signal-row"><div class="detail-label">关键信号</div><div class="signal-tags">',
            html,
        )
        self.assertIn(
            'class="detail-story-heading"><div class="detail-label">漏洞描述</div></div>',
            html,
        )
        self.assertLess(
            html.index('class="detail-signal-row"'),
            html.index('class="detail-story-heading"'),
        )
        self.assertNotIn('class="vuln-detail-header"', html)
        self.assertIn('class="detail-action"', html)
        self.assertIn('class="detail-facts"', html)
        self.assertIn(">建议处理</div>", html)
        self.assertIn("建议升级到 13.0.1 或更高版本。升级后重新扫描", html)
        self.assertIn(
            'class="sig-tag sig-epss" data-tooltip="EPSS 百分位 12.8%，30 天内被利用概率 0.04%">EPSS 12.8%</span>',
            html,
        )
        self.assertIn('class="sig-tag sig-age">已公开 1 个月</span>', html)
        self.assertIn(
            'class="cvss-tag" data-tooltip="攻击者可通过网络直接利用，不需要物理接触或内网访问">远程可达</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="利用条件简单，不需要特殊配置或时机">低复杂度</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="攻击者不需要任何认证或权限即可利用">无需权限</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="不需要受害者进行任何操作即可触发漏洞">无需交互</span>',
            html,
        )
        self.assertIn(
            'class="cia-tag cia-h" data-tooltip="可能导致服务完全不可用">可用性 高</span>',
            html,
        )
        self.assertNotIn('class="sig-tag sig-epss" title=', html)
        self.assertNotIn('class="cvss-tag" title=', html)
        self.assertNotIn('class="cia-tag cia-h" title=', html)
        self.assertNotIn("🌐", html)
        self.assertNotIn("🔒", html)
        self.assertIn("--detail-row-bg", css)
        self.assertIn("--detail-row-bg: transparent;", css)
        self.assertIn("--detail-row-edge", css)
        self.assertIn("--detail-panel-bg", css)
        self.assertIn("--detail-card-bg", css)
        self.assertNotIn("--detail-panel-bg: rgba(9, 30, 26, 0.76)", css)
        self.assertNotIn("--detail-card-bg: rgba(15, 39, 34, 0.78)", css)
        self.assertNotIn("--detail-panel-bg: rgba(17, 24, 29, 0.82)", css)
        self.assertNotIn("--detail-panel-bg: rgba(5, 18, 22, 0.44)", css)
        self.assertIn("--detail-panel-bg: transparent", css)
        self.assertIn("--detail-card-bg: rgba(255, 255, 255, 0.045)", css)
        self.assertIn("--vuln-row-open-bg: transparent;", css)
        self.assertNotIn("--vuln-row-open-bg: rgba(255, 255, 255, 0.055)", css)
        detail_css = css.split(".vuln-detail {", 1)[1].split("}", 1)[0]
        self.assertIn("border: 0;", detail_css)
        self.assertIn("border-radius: 0;", detail_css)
        self.assertIn("background: var(--detail-panel-bg);", detail_css)
        self.assertIn("box-shadow: none;", detail_css)
        self.assertNotIn("var(--detail-panel-border)", detail_css)
        self.assertNotIn(".vuln-detail::before", css)
        self.assertNotIn("border: 1px solid var(--detail-card-border);", css)
        self.assertNotIn("background: var(--detail-card-bg)", css)
        self.assertNotIn("max-width: 92ch", css)
        self.assertIn("max-width: none", css)
        self.assertIn(".detail-dossier", css)
        detail_cell_css = css.split(".vuln-detail-row > td {", 1)[1].split("}", 1)[0]
        self.assertIn("padding: 0;", detail_cell_css)
        dossier_css = css.split(".detail-dossier {", 1)[1].split("}", 1)[0]
        self.assertIn("gap: 18px;", dossier_css)
        self.assertIn("align-items: stretch;", dossier_css)
        self.assertIn("padding: 0 18px;", dossier_css)
        split_css = css.split(".detail-dossier-split {", 1)[1].split("}", 1)[0]
        self.assertIn("--detail-bottom-row-min: 92px;", split_css)
        split_facts_line_css = css.split(
            ".detail-dossier-split > .detail-facts::before {", 1
        )[1].split("}", 1)[0]
        self.assertIn("top: 13px;", split_facts_line_css)
        self.assertIn("bottom: 13px;", split_facts_line_css)
        self.assertIn(".detail-story", css)
        story_css = css.split(".detail-story {", 1)[1].split("}", 1)[0]
        self.assertIn("height: 100%;", story_css)
        self.assertIn("min-height: auto;", story_css)
        self.assertIn(".detail-signal-row", css)
        signal_row_css = css.split(".detail-signal-row {", 1)[1].split("}", 1)[0]
        self.assertIn("--detail-field-value-line: 21.58px;", signal_row_css)
        self.assertIn("--detail-signal-tag-line: 24px;", signal_row_css)
        self.assertIn("display: grid;", signal_row_css)
        self.assertIn("grid-template-columns: 1fr;", signal_row_css)
        self.assertIn("gap: 7px;", signal_row_css)
        compact_signal_row_css = " ".join(signal_row_css.split())
        self.assertIn("padding: 13px 0 calc(", compact_signal_row_css)
        self.assertIn(
            "13px + var(--detail-field-value-line) - var(--detail-signal-tag-line)",
            compact_signal_row_css,
        )
        self.assertIn(".detail-story-heading", css)
        self.assertIn(".detail-action", css)
        action_css = css.split(".detail-action {", 1)[1].split("}", 1)[0]
        self.assertIn("margin-top: auto;", action_css)
        split_action_css = css.split(".detail-dossier-split .detail-action {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("min-height: var(--detail-bottom-row-min);", split_action_css)
        self.assertIn("padding-top: 12px;", split_action_css)
        self.assertIn(".detail-facts", css)
        facts_css = css.split(".detail-facts {\n    display: grid;", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("align-content: start;", facts_css)
        self.assertIn("position: relative;", facts_css)
        self.assertNotIn("border-left: 1px solid var(--detail-card-border);", facts_css)
        self.assertIn("overflow-y: auto", css)
        self.assertIn(".sig-age", css)
        self.assertNotIn(".vuln-detail-header", css)
        self.assertNotIn("border-left-width: 4px", css)
        self.assertNotIn("border-left-color: var(--warning-ink)", css)

    def test_html_report_assets_do_not_ship_copy_command_handlers(self):
        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()

        self.assertNotIn("navigator.clipboard", js)
        self.assertNotIn('class="copy"', js)
        self.assertNotIn("function copyBtn", js)
        self.assertNotIn("function cmdBlock", js)

    def test_html_risk_detail_rows_expand_on_click_with_motion(self):
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
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": "hover-lib",
                    "version": "1.0.0",
                    "severity": "high",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": "GHSA-hover",
                    "summary": "hover detail",
                    "cve_enrichments": [
                        {
                            "description": "Hover should reveal this dossier.",
                            "cvssMetrics": [{"baseScore": "8.8"}],
                        }
                    ],
                }
            ],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn('class="detail-dossier detail-dossier-compact"', html)
        self.assertNotIn('class="detail-facts"', html)
        self.assertIn('role="button"', html)
        self.assertIn('aria-expanded="false"', html)
        self.assertIn('onclick="toggleVulnDetail(this)"', html)
        self.assertIn('onkeydown="handleVulnDetailKey(event, this)"', html)
        self.assertNotIn('onmouseenter="openVulnDetail(this)"', html)
        self.assertNotIn('onmouseleave="scheduleCloseVulnDetail(this)"', html)
        self.assertNotIn('onfocus="openVulnDetail(this)"', html)
        self.assertNotIn('onblur="scheduleCloseVulnDetail(this)"', html)
        self.assertNotIn(
            'onmouseenter="openVulnDetail(this.previousElementSibling)"',
            html,
        )
        self.assertNotIn(
            'onmouseleave="closeVulnDetail(this.previousElementSibling)"',
            html,
        )

        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()
        self.assertNotIn("VULN_DETAIL_OPEN_DELAY_MS", js)
        self.assertNotIn("function scheduleOpenVulnDetail", js)
        self.assertIn("const VULN_DETAIL_SCAN_DELAY_MS = 380", js)
        self.assertIn("function closeOtherVulnDetails", js)
        self.assertIn("function scheduleVulnDetailScan", js)
        self.assertNotIn("function scheduleCloseVulnDetail", js)
        self.assertNotIn("function isHoveringVulnDetailPair", js)
        self.assertIn("function handleVulnDetailKey", js)
        self.assertNotIn("function initVulnDetailHover", js)
        self.assertNotIn("initVulnDetailHover(app)", js)
        self.assertIn("function tooltipAttr", js)
        self.assertIn("function initCustomTooltips", js)
        self.assertIn('const CUSTOM_TOOLTIP_CLASS = "report-tooltip"', js)
        self.assertIn('root.querySelectorAll("[data-tooltip]")', js)
        self.assertIn('target.removeAttribute("title")', js)
        self.assertIn('target.addEventListener("pointerenter"', js)
        self.assertIn('target.addEventListener("click"', js)
        self.assertNotIn("window.scheduleOpenVulnDetail", js)
        self.assertNotIn("window.openVulnDetail", js)
        self.assertNotIn("window.scheduleCloseVulnDetail", js)
        self.assertNotIn("window.closeVulnDetail", js)
        self.assertNotIn('row.addEventListener("mouseenter"', js)
        self.assertNotIn('row.addEventListener("mouseleave"', js)
        self.assertNotIn('row.addEventListener("focus"', js)
        self.assertNotIn('row.addEventListener("blur"', js)
        self.assertNotIn('detail.addEventListener("mouseenter"', js)
        self.assertNotIn('detail.addEventListener("mouseleave"', js)
        self.assertIn('tr.setAttribute("aria-expanded"', js)
        self.assertIn('classList.add("vuln-detail-scan-ready")', js)
        self.assertIn("}, VULN_DETAIL_SCAN_DELAY_MS)", js)

        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()
        self.assertIn(".report-tooltip", css)
        tooltip_css = css.split(".report-tooltip {", 1)[1].split("}", 1)[0]
        self.assertIn("position: fixed;", tooltip_css)
        self.assertIn("pointer-events: none;", tooltip_css)
        self.assertIn("opacity: 0;", tooltip_css)
        tooltip_visible_css = css.split(".report-tooltip.is-visible {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("opacity: 1;", tooltip_visible_css)
        self.assertNotIn(
            ".vuln-row:hover + .vuln-detail-row,\n.vuln-detail-row:hover {\n    display:",
            css,
        )
        self.assertIn(".detail-dossier-compact", css)
        compact_css = css.split(".detail-dossier-compact {", 1)[1].split("}", 1)[0]
        self.assertIn("grid-template-columns: 1fr;", compact_css)
        self.assertIn("padding: 0 18px;", compact_css)
        detail_cell_css = css.split(".vuln-detail-row > td {", 1)[1].split("}", 1)[0]
        self.assertIn("padding: 0;", detail_cell_css)
        self.assertIn("background: var(--detail-row-bg);", detail_cell_css)
        self.assertNotIn("linear-gradient(180deg", detail_cell_css)
        self.assertIn("background-repeat: no-repeat;", detail_cell_css)
        self.assertIn("background-size: 100% 100%;", detail_cell_css)
        self.assertNotIn("var(--surface-bg)", detail_cell_css)
        self.assertIn("box-shadow:", detail_cell_css)
        self.assertNotIn("vuln-detail-shell", css)
        detail_shell_css = css.split(".vuln-detail {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow: hidden;", detail_shell_css)
        self.assertIn("contain: paint;", detail_shell_css)
        self.assertIn("background: var(--detail-panel-bg);", detail_shell_css)
        self.assertIn("box-shadow: none;", detail_shell_css)
        self.assertNotIn(".vuln-detail::before", css)
        dossier_css = css.split(".detail-dossier {", 1)[1].split("}", 1)[0]
        self.assertIn("position: relative;", dossier_css)
        self.assertIn("z-index: 1;", dossier_css)
        self.assertIn("align-items: stretch;", dossier_css)
        self.assertIn(".vuln-table .vuln-detail-row:hover {", css)
        detail_hover_css = css.split(".vuln-table .vuln-detail-row:hover {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("background: transparent !important;", detail_hover_css)
        self.assertIn(
            ".vuln-table tbody tr:hover:not(.vuln-row):not(.vuln-row-open) {", css
        )
        self.assertIn(".vuln-table tr.vuln-detail-row {", css)
        mobile_detail_row_css = css.split(".vuln-table tr.vuln-detail-row {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("background: transparent;", mobile_detail_row_css)
        self.assertIn("padding: 0;", mobile_detail_row_css)
        self.assertIn(".detail-dossier-compact .detail-story {", css)
        self.assertIn(".detail-dossier-compact .detail-facts", css)
        compact_story_css = css.split(".detail-dossier-compact .detail-story {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("min-height: auto;", compact_story_css)
        self.assertIn(".detail-dossier-compact .detail-action {", css)
        compact_action_css = css.split(".detail-dossier-compact .detail-action {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("margin-top: 12px;", compact_action_css)
        self.assertIn(".detail-dossier-split > .detail-facts::before", css)
        self.assertIn(".detail-facts::before", css)
        mobile_facts_line_css = css.split("    .detail-facts::before {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("display: none;", mobile_facts_line_css)
        self.assertIn(".vuln-detail-row.vuln-detail-open .vuln-detail", css)
        self.assertIn(
            ".vuln-detail-row.vuln-detail-scan-ready .vuln-detail::after", css
        )
        detail_open_css = css.split(
            ".vuln-detail-row.vuln-detail-open .vuln-detail {", 1
        )[1].split("}", 1)[0]
        self.assertIn("animation: vuln-detail-reveal 0.38s", detail_open_css)
        scan_open_css = css.split(
            ".vuln-detail-row.vuln-detail-scan-ready .vuln-detail::after {", 1
        )[1].split("}", 1)[0]
        self.assertIn("animation: vuln-detail-scan 0.82s ease-out both;", scan_open_css)
        self.assertIn("@keyframes vuln-detail-reveal", css)
        reveal_css = css.split("@keyframes vuln-detail-reveal {", 1)[1].split("}", 1)[0]
        self.assertNotIn("blur", reveal_css)
        self.assertIn("@keyframes vuln-detail-scan", css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)

    def test_html_more_buttons_expand_only_on_click_not_hover(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 16,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 8,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": f"risk-lib-{idx}",
                    "version": "1.0.0",
                    "severity": "high",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": f"GHSA-risk-{idx}",
                    "summary": "risk",
                }
                for idx in range(8)
            ],
            "hygiene": {},
            "outdated": [
                {
                    "package": f"old-lib-{idx}",
                    "current": "1.0.0",
                    "wanted": "1.1.0",
                    "latest": "2.0.0",
                }
                for idx in range(8)
            ],
        }

        html = self._render_html(data)

        self.assertIn(
            '<button type="button" class="fix-btn open table-toggle-btn" aria-expanded="false" onclick="toggleVulns(this)">余下 1 项</button>',
            html,
        )
        self.assertIn(
            '<button type="button" class="fix-btn open table-toggle-btn" aria-expanded="false" onclick="toggleOutdated(this)">余下 1 项</button>',
            html,
        )
        self.assertNotIn("onmouseenter=\"scheduleVulnTableToggleScan", html)
        self.assertNotIn("onmouseenter=\"scheduleOutdatedTableToggleScan", html)
        self.assertNotIn("onmouseleave=\"cancelTableToggleScan", html)

        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()
        self.assertNotIn("TABLE_TOGGLE_SCAN_DELAY_MS", js)
        self.assertNotIn("function scheduleTableToggleScan", js)
        self.assertNotIn("function cancelTableToggleScan", js)
        self.assertNotIn("function scheduleVulnTableToggleScan", js)
        self.assertNotIn("function scheduleOutdatedTableToggleScan", js)
        self.assertNotIn("table-toggle-scanning", js)
        self.assertNotIn("window.scheduleVulnTableToggleScan", js)
        self.assertNotIn("window.scheduleOutdatedTableToggleScan", js)
        self.assertNotIn("window.cancelTableToggleScan", js)

        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()
        fix_btn_css = css.split(".fix-btn {", 1)[1].split("}", 1)[0]
        self.assertIn("position: relative;", fix_btn_css)
        self.assertIn("overflow: hidden;", fix_btn_css)
        self.assertNotIn(".fix-btn.table-toggle-scanning", css)
        self.assertNotIn("@keyframes table-toggle-scan", css)

    def test_report_summary_orders_action_before_light_boundary_note(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 3,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {
                "tldr": "发现 1 个已确认依赖风险项，其中 1 个高风险，主要集中在 focus-pkg；仓库安检未发现凭证或敏感文件问题。建议先升级有明确修复版本的高风险依赖，完成后复扫确认。",
                "detail": "本次检查覆盖项目 demo，仓库安检通过。",
                "priority": ["先升级 focus-pkg，再重新运行补天扫描。"],
            },
            "top_issues": [
                {
                    "package": "focus-pkg",
                    "version": "1.0.0",
                    "severity": "high",
                    "fixed_versions": ["1.0.1"],
                    "advisory_id": "GHSA-high",
                    "summary": "high risk",
                }
            ],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn(
            "发现 1 个已确认依赖风险项，其中 1 个为高风险项，仓库安检未发现凭证或敏感文件问题。",
            html,
        )
        self.assertNotIn("主要集中在 focus-pkg", html)
        self.assertNotIn("建议先升级有明确修复版本", html)
        self.assertNotIn("其中 1 个高风险，主要集中在 focus-pkg", html)
        tldr_index = html.index("TL;DR")
        detail_index = html.index("本次检查覆盖项目 demo")
        priority_index = html.index("重新运行补天扫描")
        boundary_index = html.index("不能替代代码审计")
        self.assertLess(tldr_index, detail_index)
        self.assertLess(detail_index, priority_index)
        self.assertLess(priority_index, boundary_index)
        self.assertIn('class="summary-boundary"', html)
        self.assertNotIn('class="summary-boundary warning"', html)

        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()
        boundary_css = css.split(".summary-boundary {", 1)[1].split("}", 1)[0]
        self.assertIn("margin: 10px 0 0;", boundary_css)
        self.assertIn("background: transparent;", boundary_css)
        self.assertIn("border-top: 1px solid var(--line);", boundary_css)
        self.assertNotIn(".summary-boundary.warning", css)

    def test_html_risk_table_sorts_by_severity_epss_then_cvss(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 4,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 3,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": "medium-hot",
                    "version": "1.0.0",
                    "severity": "medium",
                    "advisory_id": "GHSA-medium",
                    "summary": "medium",
                    "cve_enrichments": [
                        {
                            "epssPercentile": "0.99",
                            "cvssMetrics": [{"baseScore": "9.8"}],
                        }
                    ],
                },
                {
                    "package": "high-low-epss-high-cvss",
                    "version": "1.0.0",
                    "severity": "high",
                    "advisory_id": "GHSA-low-epss",
                    "summary": "high",
                    "cve_enrichments": [
                        {
                            "epssPercentile": "0.10",
                            "cvssMetrics": [{"baseScore": "9.8"}],
                        }
                    ],
                },
                {
                    "package": "high-same-epss-low-cvss",
                    "version": "1.0.0",
                    "severity": "high",
                    "advisory_id": "GHSA-low-cvss",
                    "summary": "high",
                    "cve_enrichments": [
                        {
                            "epssPercentile": "0.80",
                            "cvssMetrics": [{"baseScore": "7.5"}],
                        }
                    ],
                },
                {
                    "package": "high-same-epss-high-cvss",
                    "version": "1.0.0",
                    "severity": "high",
                    "advisory_id": "GHSA-high-cvss",
                    "summary": "high",
                    "cve_enrichments": [
                        {
                            "epssPercentile": "0.80",
                            "cvssMetrics": [{"baseScore": "8.8"}],
                        }
                    ],
                },
            ],
            "hygiene": {},
            "outdated": [],
            "red": [],
            "yellow": [],
            "errors": [],
        }

        html = self._render_html(data)

        first = html.index("high-same-epss-high-cvss")
        second = html.index("high-same-epss-low-cvss")
        third = html.index("high-low-epss-high-cvss")
        fourth = html.index("medium-hot")
        self.assertLess(first, second)
        self.assertLess(second, third)
        self.assertLess(third, fourth)

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
        self.assertIn(
            '<div class="hygiene-group-head"><span>依赖配置与维护</span></div>',
            html,
        )
        self.assertIn('class="sev-badge sev-low">建议</span>', html)
        self.assertIn("配置 Dependabot", html)
        self.assertNotIn("<b>1 项</b>", html)
        self.assertNotIn("检测到 .github/workflows/", html)
        self.assertNotIn("dependabot.yml not found", html)
        self.assertNotIn("维护建议", html)
        self.assertNotIn("有 1 条", html)

    def test_hygiene_cards_share_report_surface_styles(self):
        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()

        summary_css = css.split(".hygiene-summary {", 1)[1].split("}", 1)[0]
        self.assertIn("padding: 16px;", summary_css)

        groups_css = css.split(".hygiene-groups {", 1)[1].split("}", 1)[0]
        self.assertIn("gap: 8px;", groups_css)
        self.assertIn("margin-top: 0;", groups_css)

        group_css = css.split(".hygiene-group {", 1)[1].split("}", 1)[0]
        self.assertIn("border: 0;", group_css)
        self.assertIn("border-radius: 0;", group_css)
        self.assertIn("background: transparent;", group_css)
        self.assertNotIn("overflow: hidden;", group_css)
        self.assertNotIn("var(--surface-border", group_css)
        self.assertNotIn("var(--tile-bg)", group_css)

        group_head_css = css.split(".hygiene-group-head {", 1)[1].split("}", 1)[0]
        self.assertIn("justify-content: flex-start;", group_head_css)
        self.assertIn("padding: 0 0 8px;", group_head_css)
        self.assertIn("background: transparent;", group_head_css)
        self.assertNotIn("border-bottom:", group_head_css)
        self.assertNotIn("var(--tile-bg-strong)", group_head_css)

        self.assertNotIn(".hygiene-group-head b", css)

        group_list_css = css.split(".hygiene-group-list {", 1)[1].split("}", 1)[0]
        self.assertIn("gap: 8px;", group_list_css)

        finding_css = css.split(".hygiene-finding {", 1)[1].split("}", 1)[0]
        self.assertIn("margin: 0;", finding_css)
        self.assertIn("border: 1px solid var(--summary-point-border);", finding_css)
        self.assertIn("border-radius: var(--radius-field);", finding_css)
        self.assertIn("background: var(--summary-point-bg);", finding_css)
        self.assertIn("padding: 9px 11px;", finding_css)

        finding_loc_css = css.split(".hygiene-finding-loc {", 1)[1].split("}", 1)[0]
        self.assertIn("border: 1px solid var(--pill-border);", finding_loc_css)
        self.assertIn("border-radius: var(--radius-pill);", finding_loc_css)
        self.assertIn("background: var(--pill-bg);", finding_loc_css)

        finding_note_css = css.split(".hygiene-finding-note {", 1)[1].split("}", 1)[0]
        self.assertIn("border: 1px solid var(--field-border);", finding_note_css)
        self.assertIn("border-radius: var(--radius-field);", finding_note_css)
        self.assertIn("background: var(--field-bg);", finding_note_css)

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
