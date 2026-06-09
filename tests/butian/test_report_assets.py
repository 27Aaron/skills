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
                    for idx in range(12)
                ],
                {
                    "package": "@scope/very-long-hidden-package-name",
                    "current": "2026.10.100",
                    "latest": "2026.11.101",
                    "ecosystem": "npm",
                },
                {
                    "package": "hidden-lib",
                    "current": "0.1.0",
                    "latest": "0.2.0",
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
        self.assertIn('class="outdated-list"', html)
        self.assertIn('class="outdated-row"', html)
        self.assertEqual(html.count('<article class="outdated-row'), 15)
        self.assertEqual(html.count('class="outdated-row">'), 7)
        self.assertEqual(
            html.count('class="outdated-row outdated-mobile-extra">'),
            7,
        )
        self.assertEqual(
            html.count('class="outdated-row outdated-mobile-extra outdated-extra"'),
            1,
        )
        self.assertIn(
            '<button type="button" class="fix-btn open outdated-toggle-btn" aria-expanded="false" onclick="toggleOutdated(this)"><span class="outdated-toggle-label outdated-toggle-label-desktop">余下 1 项</span><span class="outdated-toggle-label outdated-toggle-label-mobile">余下 8 项</span><span class="outdated-toggle-label outdated-toggle-label-expanded">收起</span></button>',
            html,
        )
        self.assertIn('<div class="outdated-package" title="hono">hono</div>', html)
        self.assertIn('class="outdated-version-flow"', html)
        self.assertIn('<code class="outdated-current">4.12.14</code>', html)
        self.assertIn('<span class="outdated-arrow">→</span>', html)
        self.assertIn('<code class="outdated-latest">4.12.21</code>', html)
        self.assertIn("hidden-lib", html)
        self.assertNotIn('class="outdated-card"', html)
        self.assertNotIn('<span class="outdated-version-label">当前</span>', html)
        self.assertNotIn('<span class="outdated-version-label">最近</span>', html)
        self.assertNotIn('class="stable-table outdated-table"', html)
        self.assertNotIn("<th>最近版本</th>", html)
        self.assertNotIn("<th>建议</th>", html)
        self.assertNotIn('data-label="建议"', html)
        self.assertNotIn("<th>生态</th>", html)
        self.assertNotIn("<td>npm</td>", html)
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
        self.assertIn(
            "当前版本在处理特殊输入时可能大量占用资源。攻击者提交构造好的内容后，服务可能变慢、卡住，甚至无法响应。建议升级到 13.0.1 或更高版本。",
            html,
        )
        self.assertNotIn("这个版本", html)
        self.assertNotIn("当前版本存在资源耗尽风险", html)
        self.assertNotIn("可更新到", html)
        self.assertNotIn("最近可用版本为", html)
        self.assertNotIn("有新版本 4.12.21 可用", html)
        self.assertNotIn("建议在近期迭代中安排升级", html)
        self.assertIn('class="fixed-list"', html)
        self.assertEqual(html.count('class="fixed-chip"'), 1)
        self.assertIn('<span class="fixed-chip">13.0.1</span>', html)
        self.assertNotIn('<span class="fixed-chip">11.1.1</span>', html)
        self.assertNotIn('<span class="fixed-chip">12.0.1</span>', html)
        self.assertNotIn("11.1.1、12.0.1、13.0.1", html)

        with open(REPORT_CSS, "r", encoding="utf-8") as handle:
            css = handle.read()
        self.assertIn(".fixed-list", css)
        self.assertIn("grid-template-columns: repeat(2, max-content)", css)
        self.assertIn("td.fixed-cell", css)
        bar_css = css.split(".bar {", 1)[1].split("}", 1)[0]
        self.assertIn("position: relative;", bar_css)
        self.assertIn("isolation: isolate;", bar_css)
        self.assertIn(".bar::before", css)
        bar_gloss_css = css.split(".bar::before {", 1)[1].split("}", 1)[0]
        self.assertIn("linear-gradient(", bar_gloss_css)
        self.assertIn("rgba(255, 255, 255, 0.18) 0%", bar_gloss_css)
        self.assertIn("z-index: 1;", bar_gloss_css)
        self.assertIn(".bar::after", css)
        bar_pulse_css = css.split(".bar::after {", 1)[1].split("}", 1)[0]
        self.assertIn("radial-gradient(", bar_pulse_css)
        self.assertIn("rgba(255, 255, 255, 0.58) 0%", bar_pulse_css)
        self.assertIn("rgba(255, 255, 255, 0.3) 52%", bar_pulse_css)
        self.assertIn(
            "drop-shadow(0 0 5px rgba(255, 255, 255, 0.28))",
            bar_pulse_css,
        )
        self.assertIn("mix-blend-mode: screen;", bar_pulse_css)
        self.assertIn("animation: risk-bar-pulse 6.6s", bar_pulse_css)
        self.assertIn("@keyframes risk-bar-pulse", css)
        risk_pulse_css = css.split("@keyframes risk-bar-pulse {", 1)[1].split(
            ".lead {", 1
        )[0]
        self.assertIn("opacity: 0.62;", risk_pulse_css)
        self.assertIn("opacity: 0.48;", risk_pulse_css)
        self.assertIn(".outdated-list", css)
        outdated_list_css = css.split(".outdated-list {", 1)[1].split("}", 1)[0]
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr));", outdated_list_css)
        self.assertIn(".outdated-row", css)
        self.assertIn(".outdated-version-flow", css)
        outdated_code_css = css.split(".outdated-version-flow code {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow-wrap: anywhere;", outdated_code_css)
        self.assertIn("white-space: normal;", outdated_code_css)
        self.assertNotIn("text-overflow: ellipsis;", outdated_code_css)
        self.assertIn(".outdated-toggle", css)
        self.assertIn(".outdated-row.outdated-extra", css)
        self.assertIn(".outdated-expanded .outdated-row.outdated-extra", css)
        self.assertIn(".outdated-row.outdated-mobile-extra", css)
        self.assertIn(".outdated-expanded .outdated-row.outdated-mobile-extra", css)
        self.assertIn(".outdated-toggle-label-mobile", css)
        self.assertIn(".outdated-toggle-label-expanded", css)
        self.assertIn(".vuln-table tr.vuln-extra", css)
        self.assertIn(
            ".vuln-table.vuln-expanded tr.vuln-extra:not(.vuln-detail-row)",
            css,
        )
        self.assertNotIn(".outdated-folded-note", css)
        self.assertNotIn(".outdated-card", css)
        self.assertNotIn(".outdated-table .col-current", css)
        self.assertNotIn(".outdated-table .col-latest", css)
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
            "@media (max-width: 440px) {\n    .vuln-table td {",
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
        self.assertIn('class="detail-facts-bottom"', html)
        self.assertIn(">处理建议</div>", html)
        self.assertNotIn(">建议处理</div>", html)
        self.assertIn("建议升级到 13.0.1 或更高版本。升级后重新扫描", html)
        self.assertIn(
            'class="sig-tag sig-epss" data-tooltip="EPSS 用公开数据预测漏洞被真实利用的可能性：未来 30 天利用概率约 0.04%，比约 12.8% 的漏洞更容易被利用。数值越高，越要优先处理。">EPSS 12.8%</span>',
            html,
        )
        self.assertIn('class="sig-tag sig-age">已公开 1 个月</span>', html)
        self.assertIn(
            'class="cvss-tag" data-tooltip="攻击者可以从网络上尝试利用，不需要接触你的电脑或服务器">远程可达</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="利用门槛低，通常不需要特殊条件；越容易利用，越应该靠前处理">低复杂度</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="攻击者不需要账号或登录权限，就可能尝试利用">无需权限</span>',
            html,
        )
        self.assertIn(
            'class="cvss-tag" data-tooltip="不需要用户点击链接或打开文件，服务收到特定请求就可能触发">无需交互</span>',
            html,
        )
        self.assertIn(
            'class="sig-tag sig-cvss-high" data-tooltip="CVSS 是漏洞严重度评分，7.5 属于高风险；分数越高，影响通常越大">CVSS 7.5</span>',
            html,
        )
        self.assertIn(
            'class="sig-tag sig-cwe" data-tooltip="CWE 是漏洞类型编号，用来说明问题属于哪类安全缺陷">CWE-400</span>',
            html,
        )
        self.assertIn(
            'class="cia-tag cia-h" data-tooltip="可能让服务明显卡住、崩溃或不可用">可用性 高</span>',
            html,
        )
        self.assertIn(
            '<section class="detail-field detail-field-bottom"><div class="detail-label">EPSS 利用预测（评分日期 2026-06）</div><div class="detail-value">近 30 天被利用概率约 <b>0.04%</b>，利用可能性高于 12.8% 的漏洞。</div></section>',
            html,
        )
        self.assertLess(html.index('class="detail-action"'), html.index('class="detail-facts-bottom"'))
        self.assertNotIn("EPSS 是公开数据给出的利用预测", html)
        self.assertNotIn("EPSS 百分位", html)
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
        tag_base_css = css.split(".sig-tag,\n.cvss-tag,\n.cia-tag {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("border: 1px solid transparent;", tag_base_css)
        self.assertIn("box-shadow:", tag_base_css)
        epss_css = css.split(".sig-epss {", 1)[1].split("}", 1)[0]
        self.assertIn("border-color: #c4b5fd;", epss_css)
        self.assertIn("background: #f5f3ff;", epss_css)
        self.assertIn("color: #4c1d95;", epss_css)
        cvss_tag_css = css.split("/* ---- CVSS attack condition", 1)[1].split(
            ".cvss-tag {", 1
        )[1].split("}", 1)[0]
        self.assertIn("border-color: #bfdbfe;", cvss_tag_css)
        self.assertIn("background: #eff6ff;", cvss_tag_css)
        self.assertIn("color: #1d4ed8;", cvss_tag_css)
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
        self.assertIn("--detail-bottom-row-min: 72px;", split_css)
        split_facts_line_css = css.split(
            ".detail-dossier-split > .detail-facts::before,\n.detail-dossier-split > .detail-facts-bottom::before {",
            1,
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
        split_action_css = css.split(".detail-dossier-split > .detail-action {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("grid-area: action;", split_action_css)
        self.assertIn("margin-top: 0;", split_action_css)
        self.assertIn("min-height: var(--detail-bottom-row-min);", split_action_css)
        self.assertIn("padding-top: 12px;", split_action_css)
        self.assertIn(".detail-facts", css)
        facts_css = css.split(".detail-facts {\n    grid-area: facts;", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("display: grid;", facts_css)
        self.assertIn("align-content: start;", facts_css)
        self.assertIn("position: relative;", facts_css)
        self.assertNotIn("border-left: 1px solid var(--detail-card-border);", facts_css)
        self.assertIn("overflow-y: auto", css)
        self.assertIn(".sig-age", css)
        self.assertNotIn(".vuln-detail-header", css)
        self.assertNotIn("border-left-width: 4px", css)
        self.assertNotIn("border-left-color: var(--warning-ink)", css)

    def test_current_risk_details_use_precise_plain_language(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {"name": "demo", "path": "/tmp/demo", "ecosystems": ["npm"]},
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 5,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": "next",
                    "version": "16.2.4",
                    "severity": "high",
                    "fixed_versions": ["16.2.5"],
                    "advisory_id": "GHSA-ssrf",
                    "advisory_summary": "Next.js vulnerable to server-side request forgery in applications using WebSocket upgrades",
                    "cve_enrichments": [{"cweIds": ["CWE-918"]}],
                },
                {
                    "package": "fast-uri",
                    "version": "3.1.0",
                    "severity": "high",
                    "fixed_versions": ["3.1.1"],
                    "advisory_id": "GHSA-path",
                    "advisory_summary": "fast-uri vulnerable to path traversal via percent-encoded dot segments",
                    "cve_enrichments": [{"cweIds": ["CWE-22"]}],
                },
                {
                    "package": "next",
                    "version": "16.2.4",
                    "severity": "high",
                    "fixed_versions": ["16.2.5"],
                    "advisory_id": "GHSA-middleware",
                    "advisory_summary": "Next.js has a Middleware / Proxy bypass in App Router applications via segment-prefetch routes",
                    "cve_enrichments": [{"cweIds": ["CWE-288"]}],
                },
                {
                    "package": "brace-expansion",
                    "version": "5.0.5",
                    "severity": "high",
                    "fixed_versions": ["5.0.6"],
                    "advisory_id": "GHSA-dos",
                    "advisory_summary": "brace-expansion: Large numeric range defeats documented `max` DoS protection",
                    "cve_enrichments": [{"cweIds": ["CWE-400"]}],
                },
                {
                    "package": "uuid",
                    "version": "13.0.0",
                    "severity": "high",
                    "fixed_versions": ["13.0.1"],
                    "advisory_id": "GHSA-buffer",
                    "advisory_summary": "uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided",
                    "cve_enrichments": [{"cweIds": ["CWE-787", "CWE-823"]}],
                },
                {
                    "package": "hono",
                    "version": "4.12.14",
                    "severity": "medium",
                    "fixed_versions": ["4.12.21"],
                    "advisory_id": "GHSA-ip",
                    "advisory_summary": "Hono: IP Restriction bypasses static deny rules for non-canonical IPv6",
                    "cve_enrichments": [{"cweIds": ["CWE-185", "CWE-1289"]}],
                },
                {
                    "package": "hono",
                    "version": "4.12.14",
                    "severity": "medium",
                    "fixed_versions": ["4.12.18"],
                    "advisory_id": "GHSA-cache-leak",
                    "advisory_summary": "Hono's Cache Middleware ignores Vary: Authorization / Vary: Cookie leading to cross-user cache leakage",
                    "cve_enrichments": [{"cweIds": ["CWE-524"]}],
                },
                {
                    "package": "next",
                    "version": "16.2.4",
                    "severity": "medium",
                    "fixed_versions": ["16.2.5"],
                    "advisory_id": "GHSA-xss",
                    "advisory_summary": "Next.js vulnerable to cross-site scripting in App Router applications using CSP nonces",
                    "cve_enrichments": [{"cweIds": ["CWE-79"]}],
                },
                {
                    "package": "next",
                    "version": "16.2.4",
                    "severity": "medium",
                    "fixed_versions": ["16.2.5"],
                    "advisory_id": "GHSA-cache-redirect",
                    "advisory_summary": "Next.js's Middleware / Proxy redirects can be cache-poisoned",
                    "cve_enrichments": [{"cweIds": ["CWE-349"]}],
                },
                {
                    "package": "hono",
                    "version": "4.12.14",
                    "severity": "low",
                    "fixed_versions": ["4.12.18"],
                    "advisory_id": "GHSA-jwt-date",
                    "advisory_summary": "Hono has improper validation of NumericDate claims (exp, nbf, iat) in JWT verify()",
                    "cve_enrichments": [{"cweIds": ["CWE-1284"]}],
                },
            ],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn(
            "当前版本在 WebSocket upgrade 场景下可能错误转发服务端请求。攻击者可能让服务器访问内部服务、云元数据地址或其他非预期目标。建议升级到 16.2.5 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在规范化 URL 路径时可能判断不严。如果项目用它做路径白名单或前缀校验，限制可能被绕过，请求可能被导向不该允许的位置。建议升级到 3.1.1 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在特定路由场景下可能绕过中间件或代理检查。如果项目依赖这些检查做登录或权限控制，受保护页面可能被直接访问。建议升级到 16.2.5 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在展开超大数字范围时可能先消耗大量内存和 CPU。攻击者提交构造好的内容后，服务可能变慢、卡住，甚至无法响应。建议升级到 5.0.6 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在调用方传入输出缓冲区时可能缺少边界检查。生成结果可能被部分写入或写到非预期位置，依赖这些值的逻辑可能得到异常数据。建议升级到 13.0.1 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在解析非标准 IPv6 地址时可能与访问限制规则不一致。如果项目依赖 IP 黑名单或静态 deny 规则，部分本应拒绝的请求可能被放行。建议升级到 4.12.21 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在缓存响应时可能没有正确区分 Authorization 或 Cookie。不同用户之间可能看到不该共享的缓存内容。建议升级到 4.12.18 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在输出脚本、样式或 HTML 内容时可能没有充分转义不可信输入。如果项目把用户可控内容传入相关接口，页面中可能执行非预期脚本。建议升级到 16.2.5 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在缓存跳转响应时可能没有正确区分请求上下文。攻击者可能让后续用户命中被污染的跳转结果。建议升级到 16.2.5 或更高版本。",
            html,
        )
        self.assertIn(
            "当前版本在校验 JWT 时间声明（exp、nbf、iat）时可能不够严格。过期或尚未生效的令牌可能被错误接受，需要结合使用方式复核影响。建议升级到 4.12.18 或更高版本。",
            html,
        )
        self.assertNotIn("服务器上不该公开的文件", html)
        self.assertNotIn("关键数据被覆盖", html)
        self.assertNotIn("当前版本命中已公开安全公告", html)

    def test_current_risk_table_shows_only_cve_and_higher_fixed_versions(self):
        data = {
            "generated_at": "2026-06-05 09:05:50",
            "project": {
                "name": "demo",
                "path": "/tmp/demo",
                "ecosystems": ["npm"],
                "total_packages": 2,
            },
            "scan_config": {"scan_mode": "full_dependency_scan"},
            "risk_summary": {
                "critical": 0,
                "high": 2,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [
                {
                    "package": "next",
                    "version": "16.2.4",
                    "severity": "high",
                    "fixed_versions": ["15.5.16", "16.2.5"],
                    "advisory_id": "GHSA-c4j6-fc7j-m34r",
                    "cve_id": "CVE-2026-44578",
                    "summary": "Next.js vulnerable to server-side request forgery in applications using WebSocket upgrades",
                },
                {
                    "package": "ghsa-only-lib",
                    "version": "1.2.3",
                    "severity": "high",
                    "fixed_versions": ["1.2.4"],
                    "advisory_id": "GHSA-only-test-id",
                    "summary": "Package has an advisory without a CVE identifier",
                },
            ],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        next_row = html.split('title="next"', 1)[1].split("</tr>", 1)[0]
        self.assertIn("CVE-2026-44578", next_row)
        self.assertNotIn("GHSA-c4j6-fc7j-m34r", next_row)
        self.assertIn('<span class="fixed-chip">16.2.5</span>', next_row)
        self.assertNotIn("15.5.16", next_row)

        ghsa_only_row = html.split('title="ghsa-only-lib"', 1)[1].split("</tr>", 1)[0]
        self.assertIn('<span style="color:var(--sub)">-</span>', ghsa_only_row)
        self.assertNotIn("GHSA-only-test-id", ghsa_only_row)

    def test_html_report_assets_only_ship_secret_evidence_copy_handler(self):
        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()

        self.assertIn("function copySecretEvidence(button)", js)
        self.assertIn("navigator.clipboard.writeText", js)
        self.assertIn("secret-copy-btn", js)
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
        self.assertIn("border: 1px solid #cbd5e1;", tooltip_css)
        self.assertIn("background: #ffffff;", tooltip_css)
        self.assertIn("color: #1f2937;", tooltip_css)
        self.assertNotIn("rgba(8, 13, 18", tooltip_css)
        signal_css = css.split("/* ---- Signal tags", 1)[1]
        dark_css = signal_css.split("@media (prefers-color-scheme: dark)", 1)[1]
        dark_tooltip_css = dark_css.split(".report-tooltip {", 1)[1].split("}", 1)[0]
        self.assertIn("background: rgba(8, 13, 18, 0.96);", dark_tooltip_css)
        self.assertIn("color: #ecfdf5;", dark_tooltip_css)
        self.assertIn("    .sig-tag,\n    .cvss-tag,\n    .cia-tag {", dark_css)
        dark_base_tag_css = dark_css.split(
            "    .sig-tag,\n    .cvss-tag,\n    .cia-tag {", 1
        )[1].split("}", 1)[0]
        self.assertIn("rgba(255, 255, 255, 0.12)", dark_base_tag_css)
        dark_epss_css = dark_css.split("    .sig-epss {", 1)[1].split("}", 1)[0]
        self.assertIn("border-color: rgba(196, 181, 253, 0.56);", dark_epss_css)
        self.assertIn("background: rgba(124, 58, 237, 0.34);", dark_epss_css)
        self.assertIn("color: #f5f3ff;", dark_epss_css)
        dark_cvss_tag_css = dark_css.split("    .cvss-tag {", 1)[1].split("}", 1)[0]
        self.assertIn("border-color: rgba(96, 165, 250, 0.58);", dark_cvss_tag_css)
        self.assertIn("background: rgba(37, 99, 235, 0.32);", dark_cvss_tag_css)
        self.assertIn("color: #eff6ff;", dark_cvss_tag_css)
        dark_neutral_css = dark_css.split("    .sig-cwe,\n    .sig-age,\n    .sig-old {", 1)[1].split("}", 1)[0]
        self.assertIn("background: rgba(71, 85, 105, 0.42);", dark_neutral_css)
        self.assertIn("color: #f8fafc;", dark_neutral_css)
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
        split_css = css.split(".detail-dossier-split {", 1)[1].split("}", 1)[0]
        self.assertIn('grid-template-areas:', split_css)
        self.assertIn('"story facts"', split_css)
        self.assertIn('"action bottom"', split_css)
        self.assertIn("row-gap: 0;", split_css)
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
        self.assertIn(".detail-dossier-split > .detail-facts-bottom::before", css)
        self.assertIn(".detail-facts::before", css)
        mobile_facts_line_css = css.split(
            "    .detail-facts::before,\n    .detail-facts-bottom::before {",
            1,
        )[1].split("}", 1)[0]
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
        reduced_motion_css = css.split("@media (prefers-reduced-motion: reduce)", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn(".bar::after", reduced_motion_css)
        self.assertIn("animation: none !important;", reduced_motion_css)

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
                for idx in range(15)
            ],
        }

        html = self._render_html(data)

        self.assertIn(
            '<button type="button" class="fix-btn open table-toggle-btn" aria-expanded="false" onclick="toggleVulns(this)">余下 1 项</button>',
            html,
        )
        self.assertIn(
            '<button type="button" class="fix-btn open outdated-toggle-btn" aria-expanded="false" onclick="toggleOutdated(this)"><span class="outdated-toggle-label outdated-toggle-label-desktop">余下 1 项</span><span class="outdated-toggle-label outdated-toggle-label-mobile">余下 8 项</span><span class="outdated-toggle-label outdated-toggle-label-expanded">收起</span></button>',
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
        self.assertIn("function toggleOutdated", js)
        self.assertIn("window.toggleOutdated", js)

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

    def test_html_renders_secret_code_context_with_line_numbers(self):
        key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
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
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": ".env.example",
                        "line": 17,
                        "type": "openai_key",
                        "confidence": "high",
                        "preview": key,
                        "code_context": [
                            {"line": 15, "content": "APP_URL=http://localhost:3000"},
                            {"line": 16, "content": "FEATURE_FLAG=true"},
                            {
                                "line": 17,
                                "content": f'OPENAI_API_KEY="{key}"',
                                "match": True,
                            },
                            {"line": 18, "content": "LOG_LEVEL=debug"},
                            {"line": 19, "content": "TIMEOUT=30"},
                        ],
                    }
                ]
            },
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn('class="secret-evidence"', html)
        self.assertIn('<span class="secret-code-lang">ENV</span>', html)
        self.assertIn('class="secret-copy-btn"', html)
        self.assertIn('onclick="copySecretEvidence(this)"', html)
        self.assertIn('class="secret-code-line is-hit"', html)
        self.assertIn('<span class="secret-code-no">15</span>', html)
        self.assertIn('<span class="secret-code-no">19</span>', html)
        self.assertIn(f'OPENAI_API_KEY=&quot;{key}&quot;', html)
        self.assertNotIn("<span>代码位置</span>", html)

    def test_html_renders_secret_code_context_in_yellow_card(self):
        key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
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
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "yellow": [
                {
                    "name": "疑似硬编码凭证：.env.example:17",
                    "type": "secret_exposure",
                    "severity": "medium",
                    "path": ".env.example",
                    "preview": key,
                    "why_manual": "扫描在 .env.example:17 发现 LLM/API 密钥特征。",
                    "risk": "如果该凭证真实可用，泄露后可能造成未授权访问。",
                    "disposal": "先确认是否真实有效。",
                    "code_context": [
                        {"line": 15, "content": "APP_URL=http://localhost:3000"},
                        {"line": 16, "content": "FEATURE_FLAG=true"},
                        {
                            "line": 17,
                            "content": f'OPENAI_API_KEY="{key}"',
                            "match": True,
                        },
                        {"line": 18, "content": "LOG_LEVEL=debug"},
                        {"line": 19, "content": "TIMEOUT=30"},
                    ],
                }
            ],
            "hygiene": {},
            "outdated": [],
        }

        html = self._render_html(data)

        title_pos = html.index("疑似硬编码凭证：.env.example:17")
        evidence_pos = html.index('class="secret-evidence"', title_pos)
        self.assertGreater(evidence_pos, title_pos)
        self.assertIn('<span class="secret-code-lang">ENV</span>', html[evidence_pos:])
        self.assertIn('class="secret-copy-btn"', html[evidence_pos:])
        self.assertIn('class="secret-code-line is-hit"', html[evidence_pos:])
        self.assertIn(f'OPENAI_API_KEY=&quot;{key}&quot;', html[evidence_pos:])
        self.assertNotIn('<div class="label">为什么要关注</div>', html)
        self.assertNotIn('<div class="label">可能影响</div>', html)
        self.assertNotIn('<div class="label">建议动作</div>', html)

    def test_html_moves_secret_yellow_items_into_hygiene_credentials(self):
        key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        context = [
            {"line": 15, "content": "APP_URL=http://localhost:3000"},
            {"line": 16, "content": "FEATURE_FLAG=true"},
            {
                "line": 17,
                "content": f'OPENAI_API_KEY="{key}"',
                "match": True,
            },
            {"line": 18, "content": ""},
            {"line": 19, "content": ""},
        ]
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
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": ".env.example",
                        "line": 17,
                        "type": "openai_key",
                        "confidence": "high",
                        "preview": key,
                        "code_context": context,
                    }
                ]
            },
            "yellow": [
                {
                    "name": "疑似硬编码凭证：.env.example:17",
                    "type": "secret_exposure",
                    "severity": "medium",
                    "path": ".env.example",
                    "preview": key,
                    "code_context": context,
                }
            ],
            "outdated": [],
        }

        html = self._render_html(data)

        hygiene_pos = html.index('section-title">仓库安检')
        credentials_pos = html.index("凭证与敏感文件", hygiene_pos)
        title_pos = html.index("疑似硬编码凭证：.env.example:17", credentials_pos)
        evidence_pos = html.index('class="secret-evidence"', title_pos)
        self.assertGreater(title_pos, credentials_pos)
        self.assertGreater(evidence_pos, title_pos)
        self.assertIn('class="hygiene-secret-review item yellow"', html)
        self.assertNotIn('class="hygiene-secret-review item yellow open"', html)
        self.assertNotIn('<span class="chev">▶</span>', html)
        self.assertIn('<span class="secret-code-lang">ENV</span>', html[evidence_pos:])
        self.assertIn(f'OPENAI_API_KEY=&quot;{key}&quot;', html[evidence_pos:])
        self.assertNotIn('<span class="mini-label">硬编码密钥</span>', html)
        self.assertNotIn("发现 1 处疑似明文凭证，需要研发确认是否是真实可用的密钥。", html)
        self.assertNotIn('section-title">待确认事项', html)

    def test_html_keeps_non_secret_yellow_items_in_review_section(self):
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
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "summary": {"tldr": "demo", "detail": "demo", "priority": []},
            "top_issues": [],
            "hygiene": {
                "tracked_secrets": [
                    {
                        "file": ".env.example",
                        "line": 17,
                        "type": "openai_key",
                        "confidence": "high",
                    }
                ]
            },
            "yellow": [
                {
                    "name": ".gitignore 缺少敏感规则",
                    "type": "gitignore_missing",
                    "severity": "low",
                    "path": ".gitignore",
                    "why_manual": ".env 未加入忽略规则。",
                    "risk": "后续可能误提交本地密钥文件。",
                    "disposal": "补充 .env* 等忽略规则。",
                }
            ],
            "outdated": [],
        }

        html = self._render_html(data)

        self.assertIn('section-title">待确认事项', html)
        self.assertIn(".gitignore 缺少敏感规则", html)

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

    def test_html_omits_outdated_section_without_outdated_items(self):
        cases = [
            ("full scan", {"scan_mode": "full_dependency_scan"}),
            ("skipped outdated", {"scan_mode": "full_dependency_scan", "skip_outdated": True}),
            ("hygiene only", {"scan_mode": "hygiene_only"}),
        ]
        for _label, scan_config in cases:
            with self.subTest(_label):
                data = {
                    "generated_at": "2026-06-05 09:05:50",
                    "project": {
                        "name": "demo",
                        "path": "/tmp/demo",
                        "ecosystems": ["npm"],
                    },
                    "scan_config": scan_config,
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

                self.assertNotIn('section-title">过期依赖', html)
                self.assertNotIn("本次为了提速跳过了过期依赖检查", html)
                self.assertNotIn("没有检测到明确的过期依赖", html)
                self.assertNotIn("本次未执行依赖版本维护检查", html)


if __name__ == "__main__":
    unittest.main()
