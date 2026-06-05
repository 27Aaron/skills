import json
import os
import shutil
import subprocess
import textwrap
import unittest

from butian.scripts import report

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORT_CSS = os.path.join(ROOT, "butian", "static", "report.css")
REPORT_JS = os.path.join(ROOT, "butian", "static", "report.js")


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
        self.assertNotIn("未命中已确认的依赖漏洞。", markdown)

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
        self.assertNotIn("未命中已确认的依赖漏洞", html)

    def test_fixed_versions_render_as_wrapping_chips(self):
        if not shutil.which("node"):
            self.skipTest("node is required for report asset rendering tests")

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
            "hono 当前版本为 4.12.14，建议升级到最新版本 4.12.21。",
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
        self.assertNotIn("border-left-width: 4px", css)
        self.assertNotIn("border-left-color: var(--warning-ink)", css)

    def test_html_report_assets_do_not_ship_copy_command_handlers(self):
        with open(REPORT_JS, "r", encoding="utf-8") as handle:
            js = handle.read()

        self.assertNotIn("navigator.clipboard", js)
        self.assertNotIn('class="copy"', js)
        self.assertNotIn("function copyBtn", js)
        self.assertNotIn("function cmdBlock", js)


if __name__ == "__main__":
    unittest.main()
