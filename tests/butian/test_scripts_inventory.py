"""Repository-level coverage guardrails for scripts, tests, and docs."""

import glob
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT_DIR = os.path.join(ROOT, "butian", "scripts")
TEST_DIR = os.path.join(ROOT, "tests", "butian")
DOC_DIR = os.path.join(ROOT, "docs", "butian")
SKILL_PATH = os.path.join(ROOT, "butian", "SKILL.md")
REFERENCE_DIR = os.path.join(ROOT, "butian", "references")

SCRIPT_TEST_FILES = {
    "__init__.py": ["test_scripts_inventory.py"],
    "analyze.py": ["test_analyze.py"],
    "cache.py": ["test_cache.py"],
    "dependency_parsers.py": ["test_scan.py"],
    "detect.py": ["test_detect.py"],
    "finding_utils.py": ["test_finding_utils.py", "test_repo_checks.py"],
    "fix.py": ["test_fix.py"],
    "iac_checks.py": ["test_iac_checks.py"],
    "labels.py": ["test_labels.py"],
    "repo_checks.py": ["test_repo_checks.py"],
    "report.py": ["test_report.py", "test_report_assets.py"],
    "run_audit.py": ["test_run_audit.py"],
    "scan.py": ["test_scan.py", "test_scan_helpers.py", "test_cache.py"],
    "server_analyze.py": ["test_server_analyze.py"],
    "server_collect.py": ["test_server_collect.py"],
    "server_inventory.py": ["test_server_inventory.py"],
    "server_match.py": ["test_server_match.py"],
    "visualize.py": ["test_visualize.py", "test_report_assets.py"],
    "vulnerability_sources.py": ["test_scan.py", "test_server_match.py"],
    "workspace.py": ["test_scan_helpers.py", "test_detect.py"],
    "workflow_checks.py": ["test_workflow_checks.py"],
}

SCRIPT_DOC_FILES = {
    "analyze.py": "analyze.md",
    "cache.py": "cache.md",
    "dependency_parsers.py": "dependency_parsers.md",
    "detect.py": "detect.md",
    "finding_utils.py": "finding_utils.md",
    "fix.py": "fix.md",
    "iac_checks.py": "iac_checks.md",
    "labels.py": "labels.md",
    "repo_checks.py": "repo_checks.md",
    "report.py": "report.md",
    "run_audit.py": "run_audit.md",
    "scan.py": "scan.md",
    "server_analyze.py": "server_analyze.md",
    "server_collect.py": "server_collect.md",
    "server_inventory.py": "server_inventory.md",
    "server_match.py": "server_match.md",
    "visualize.py": "visualize.md",
    "vulnerability_sources.py": "vulnerability_sources.md",
    "workspace.py": "workspace.md",
    "workflow_checks.py": "workflow_checks.md",
}


class ScriptInventoryTests(unittest.TestCase):
    def test_every_python_script_has_declared_test_files(self):
        scripts = sorted(
            name for name in os.listdir(SCRIPT_DIR) if name.endswith(".py")
        )
        self.assertEqual(set(scripts), set(SCRIPT_TEST_FILES))
        for script, test_files in SCRIPT_TEST_FILES.items():
            with self.subTest(script=script):
                self.assertGreater(len(test_files), 0)
                for test_file in test_files:
                    self.assertTrue(
                        os.path.isfile(os.path.join(TEST_DIR, test_file)),
                        f"{script} maps to missing test file {test_file}",
                    )

    def test_every_behavior_script_has_docs_page(self):
        scripts = sorted(
            name
            for name in os.listdir(SCRIPT_DIR)
            if name.endswith(".py") and name != "__init__.py"
        )
        self.assertEqual(set(scripts), set(SCRIPT_DOC_FILES))
        for script, doc_file in SCRIPT_DOC_FILES.items():
            with self.subTest(script=script):
                doc_path = os.path.join(DOC_DIR, doc_file)
                self.assertTrue(
                    os.path.isfile(doc_path), f"missing docs page {doc_file}"
                )
                with open(doc_path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                self.assertIn(script, text)
                self.assertIn("##", text)

    def test_docs_include_index_and_testing_matrix(self):
        for doc_file in ("index.md", "testing-matrix.md"):
            with self.subTest(doc_file=doc_file):
                doc_path = os.path.join(DOC_DIR, doc_file)
                self.assertTrue(os.path.isfile(doc_path), f"missing {doc_file}")
                with open(doc_path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                self.assertIn("butian", text.lower())

    def test_run_audit_docs_explain_explicit_server_scan_args(self):
        with open(
            os.path.join(DOC_DIR, "run_audit.md"), "r", encoding="utf-8"
        ) as handle:
            text = handle.read()

        self.assertIn("服务器扫描入口", text)
        self.assertNotIn("显式要求", text)
        self.assertIn("默认项目扫描不会连接服务器", text)
        self.assertIn("--server", text)
        self.assertIn("--server-only", text)
        self.assertIn("--server-inventory", text)
        self.assertNotIn("user@example.com", text)
        self.assertIn("--server user@203.0.113.10", text)
        self.assertIn("--server <ssh_target>", text)
        self.assertIn("--ssh-config", text)
        self.assertIn(".ssh/config", text)
        self.assertNotIn("用户明确要求", text)
        self.assertNotIn("Agent 工作流", text)

    def test_public_docs_do_not_contain_generated_security_reports(self):
        result = subprocess.run(
            ["git", "ls-files", "docs/butian/security-report-*.md"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        tracked_reports = [line for line in result.stdout.splitlines() if line]
        self.assertEqual(
            tracked_reports,
            [],
            "Generated security reports belong in ignored runtime artifacts, not tracked public docs",
        )

    def test_skill_declares_post_cancel_manual_confirmations(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        project_path = os.path.join(REFERENCE_DIR, "project-scan.md")
        with open(project_path, "r", encoding="utf-8") as handle:
            project_text = handle.read()

        self.assertIn("references/project-scan.md", text)
        self.assertNotIn("references/repair-flow.md", text)
        self.assertFalse(
            os.path.exists(os.path.join(REFERENCE_DIR, "repair-flow.md")),
            "AskUserQuestion 契约应合并回项目扫描 reference，避免拆分过碎",
        )
        self.assertIn("待确认动作队列", project_text)
        self.assertIn("硬编码凭证占位符", project_text)
        self.assertIn("创建 Dependabot 配置", project_text)
        self.assertIn("更新过期依赖", project_text)
        self.assertIn("处理凭证占位符", project_text)
        self.assertIn("多选 AskUserQuestion", text)
        self.assertIn("取消/暂不处理", project_text)
        self.assertIn("建议优先处理本次发现的已确认风险项", project_text)
        self.assertIn("建议优先选择改动较小的修复方式", project_text)
        self.assertIn("建议顺手处理下面这些维护动作", project_text)
        self.assertIn("Dependabot 是 GitHub 的依赖更新助手", project_text)
        self.assertIn("建议现在运行项目构建或测试", project_text)
        self.assertIn("开始修复", project_text)
        self.assertIn("先不修复", project_text)
        self.assertIn("升级到修复版本", project_text)
        self.assertIn("全部升级到最新版", project_text)
        self.assertIn("运行验证", project_text)
        self.assertNotIn("AskUserQuestion 单独确认", project_text)
        self.assertIn("用户选择暂不处理", project_text)
        self.assertIn("升级父依赖并重新扫描", project_text)
        self.assertIn("不弹出待确认动作队列", project_text)

    def test_run_audit_docs_delegate_repair_contract_to_reference(self):
        with open(
            os.path.join(DOC_DIR, "run_audit.md"), "r", encoding="utf-8"
        ) as handle:
            text = handle.read()

        self.assertIn(
            "完整修复交互契约以 `butian/references/project-scan.md` 为准", text
        )
        self.assertNotIn("建议顺手处理下面这些维护动作", text)
        self.assertNotIn("Dependabot 是 GitHub 的依赖更新助手", text)

    def test_public_docs_avoid_known_readability_typos(self):
        paths = [
            SKILL_PATH,
            *glob.glob(os.path.join(REFERENCE_DIR, "*.md")),
            *glob.glob(os.path.join(DOC_DIR, "*.md")),
        ]
        for path in paths:
            with self.subTest(path=os.path.relpath(path, ROOT)):
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                self.assertNotIn("stdout供", text)
                self.assertNotIn("最终Markdown", text)
                self.assertNotIn("HTML报告", text)

    def test_fix_docs_do_not_claim_system_pip_fallback(self):
        with open(os.path.join(DOC_DIR, "fix.md"), "r", encoding="utf-8") as handle:
            text = handle.read()

        self.assertIn("不回退到系统 pip", text)
        self.assertNotIn('"pypi":      lambda pkg, ver', text)
        self.assertNotIn("| pip    | 默认", text)

    def test_scan_docs_document_secret_fixture_marker(self):
        with open(os.path.join(DOC_DIR, "scan.md"), "r", encoding="utf-8") as handle:
            text = handle.read()

        self.assertIn("butian: allow-secret-fixtures", text)
        self.assertIn("只用于测试夹具", text)

    def test_skill_links_scenario_references(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        for reference in (
            "references/project-scan.md",
            "references/server-scan.md",
        ):
            with self.subTest(reference=reference):
                self.assertIn(reference, text)
                self.assertTrue(
                    os.path.isfile(os.path.join(ROOT, "butian", reference)),
                    f"missing {reference}",
                )
        for reference in (
            "references/repair-flow.md",
            "references/sources-and-limits.md",
            "references/report-contract.md",
        ):
            with self.subTest(reference=reference):
                self.assertNotIn(reference, text)
                self.assertFalse(
                    os.path.exists(os.path.join(ROOT, "butian", reference)),
                    f"{reference} should be merged into project/server references",
                )

    def test_project_and_server_reference_boundaries(self):
        with open(
            os.path.join(REFERENCE_DIR, "project-scan.md"), "r", encoding="utf-8"
        ) as handle:
            project_text = handle.read()
        with open(
            os.path.join(REFERENCE_DIR, "server-scan.md"), "r", encoding="utf-8"
        ) as handle:
            server_text = handle.read()

        self.assertIn("不扫描系统 Python", project_text)
        self.assertIn("全局 npm", project_text)
        self.assertIn("全局 pnpm", project_text)
        self.assertIn("操作系统包", project_text)
        self.assertIn("系统服务", project_text)
        self.assertIn("数据库", project_text)
        self.assertIn("日志", project_text)
        self.assertIn("--server", server_text)
        self.assertIn("--server-inventory", server_text)
        self.assertIn("只读 SSH", server_text)
        self.assertIn("server-inventory.json", server_text)
        self.assertIn("唯一", server_text)
        self.assertIn("不采集 Docker", server_text)
        self.assertIn("不自动升级", server_text)

    def test_skill_keeps_detailed_entries_in_references(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            skill_text = handle.read()
        with open(
            os.path.join(REFERENCE_DIR, "project-scan.md"), "r", encoding="utf-8"
        ) as handle:
            project_text = handle.read()
        with open(
            os.path.join(REFERENCE_DIR, "server-scan.md"), "r", encoding="utf-8"
        ) as handle:
            server_text = handle.read()

        self.assertNotIn("## 服务器扫描入口", skill_text)
        self.assertNotIn("## 分步调试入口", skill_text)
        self.assertIn("## 分步调试入口", project_text)
        self.assertIn("## 服务器扫描入口", server_text)
        self.assertNotIn("user@example.com", skill_text)
        self.assertNotIn("user@example.com", server_text)
        self.assertIn("--server user@203.0.113.10", server_text)
        self.assertIn("--server <ssh_target>", server_text)
        self.assertIn(".ssh/config", server_text)

    def test_public_markdown_avoids_internal_routing_language(self):
        paths = [SKILL_PATH]
        paths.extend(glob.glob(os.path.join(REFERENCE_DIR, "*.md")))
        paths.extend(glob.glob(os.path.join(DOC_DIR, "*.md")))
        brand_cn = "\u8865\u5929"
        brand_en = "B" + "utian"
        empty_guidance = "命令" + "示例用于说明执行方式"
        manual_guidance = "不作为" + "必须手动"
        banned_patterns = {
            "internal reference routing": r"读 `references|不要在主流程",
            "explicit-user-requirement phrasing": r"显式要求|用户明确|用户点头|用户明确要求|只有用户明确要求|除非用户明确要求|必须由用户明确要求",
            "agent-facing wording": r"(?<!User-)\b[Aa]gent\b",
            "forced branding": "|".join(
                [
                    brand_cn + r"脚本",
                    brand_cn + r"扫描",
                    brand_cn + r"支持",
                    brand_cn + r"通用",
                    brand_cn + r"会",
                    brand_en + r" 安全",
                    brand_en + r" 本地",
                    brand_en + r" 的",
                    r"HTML 是 " + brand_en,
                    brand_en + r" 同时",
                ]
            ),
            "empty command guidance": empty_guidance + "|" + manual_guidance,
        }

        for path in sorted(paths):
            with self.subTest(path=os.path.relpath(path, ROOT)):
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                if path != SKILL_PATH:
                    self.assertIsNone(
                        re.search(brand_cn + r"|\b" + brand_en + r"\b", text),
                        f"brand term appears in {path}",
                    )
                for label, pattern in banned_patterns.items():
                    self.assertIsNone(
                        re.search(pattern, text),
                        f"{label} appears in {path}",
                    )

    def test_user_visible_strings_avoid_forced_branding(self):
        paths = glob.glob(os.path.join(SCRIPT_DIR, "*.py"))
        paths.extend(glob.glob(os.path.join(ROOT, "butian", "templates", "*.js")))
        brand_cn = "\u8865\u5929"
        brand_en = "B" + "utian"
        empty_guidance = "命令" + "示例用于说明执行方式"
        manual_guidance = "不作为" + "必须手动"
        banned_patterns = {
            "forced branding": "|".join(
                [
                    brand_cn + r"脚本",
                    brand_cn + r"扫描",
                    brand_cn + r"支持",
                    brand_cn + r"通用",
                    brand_cn + r"会",
                    brand_en + r" 安全",
                    brand_en + r" 本地",
                    brand_en + r" 的",
                    r"HTML 是 " + brand_en,
                    brand_en + r" 同时",
                    brand_en + r" local workspace",
                ]
            ),
            "empty command guidance": empty_guidance + "|" + manual_guidance,
        }

        for path in sorted(paths):
            with self.subTest(path=os.path.relpath(path, ROOT)):
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                self.assertIsNone(
                    re.search(brand_cn + r"|\b" + brand_en + r"\b", text),
                    f"brand term appears in {path}",
                )
                for label, pattern in banned_patterns.items():
                    self.assertIsNone(
                        re.search(pattern, text),
                        f"{label} appears in {path}",
                    )

    def test_scan_comments_describe_current_module_boundaries(self):
        with open(os.path.join(SCRIPT_DIR, "scan.py"), "r", encoding="utf-8") as handle:
            scan_text = handle.read()

        self.assertIn("仓库安检、漏洞和过期依赖检查", scan_text)
        self.assertIn("Packagist", scan_text)
        self.assertIn("RubyGems", scan_text)
        self.assertIn("NuGet", scan_text)
        self.assertIn("Maven", scan_text)

        for script in ("scan.py", "dependency_parsers.py", "vulnerability_sources.py"):
            with self.subTest(script=script):
                with open(
                    os.path.join(SCRIPT_DIR, script), "r", encoding="utf-8"
                ) as handle:
                    text = handle.read()
                self.assertIsNone(
                    re.search(r"^\s*# Step \d+:", text, flags=re.MULTILINE),
                    f"{script} should use capability section names, not pipeline Step labels",
                )

    def test_secret_scan_comments_explain_why_boundaries_exist(self):
        with open(os.path.join(SCRIPT_DIR, "scan.py"), "r", encoding="utf-8") as handle:
            scan_text = handle.read()

        self.assertIn("密钥扫描文件选择", scan_text)
        self.assertIn("熵值是未知 token 格式的兜底信号", scan_text)
        self.assertIn("模板文件保留可定位证据", scan_text)
        self.assertIn("正则命中优先于熵值命中", scan_text)

    def test_run_audit_comments_use_pipeline_contract_names(self):
        with open(
            os.path.join(SCRIPT_DIR, "run_audit.py"), "r", encoding="utf-8"
        ) as handle:
            text = handle.read()

        self.assertIsNone(
            re.search(r"^\s*# Step \d+:", text, flags=re.MULTILINE),
            "run_audit.py should use pipeline contract names, not numeric Step labels",
        )
        for phrase in (
            "预检先固定本次运行工作区",
            "服务器扫描保持显式启用",
            "中间修复复扫跳过 Markdown",
            "项目 HTML 每次都重新生成",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_server_scan_comments_preserve_safety_boundaries(self):
        expectations = {
            "server_collect.py": "只读 SSH 采集绝不能安装",
            "server_inventory.py": "不支持或为空的 inventory 保留为覆盖缺口",
            "server_match.py": "不支持的服务器生态是覆盖缺口",
            "run_audit.py": "服务器 identity 路径属于报告敏感信息",
        }
        for script, phrase in expectations.items():
            with self.subTest(script=script):
                with open(
                    os.path.join(SCRIPT_DIR, script), "r", encoding="utf-8"
                ) as handle:
                    text = handle.read()
                self.assertIn(phrase, text)

    def test_analyze_comments_preserve_report_contract_boundaries(self):
        with open(
            os.path.join(SCRIPT_DIR, "analyze.py"), "r", encoding="utf-8"
        ) as handle:
            text = handle.read()

        for phrase in (
            "红黄绿分组是报告契约",
            "fix_config 是 fix.py 消费的机器契约",
            "服务器已确认风险和维护建议必须分开",
            "过期依赖是维护信号",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_fix_comments_preserve_repair_safety_boundaries(self):
        with open(os.path.join(SCRIPT_DIR, "fix.py"), "r", encoding="utf-8") as handle:
            text = handle.read()

        for phrase in (
            "latest 策略刻意保持宽泛",
            "parent-upgrade 是第二轮修复",
            "force-residual 会写入持久 npm 策略",
            "dry-run 是独立 CLI 的安全边界",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_report_comments_preserve_rendering_contract_boundaries(self):
        with open(
            os.path.join(SCRIPT_DIR, "report.py"), "r", encoding="utf-8"
        ) as handle:
            text = handle.read()

        for phrase in (
            "Markdown helper 是最后一层转义",
            "安全编号必须保持可点击",
            "低证据服务器线索不进入人工 finding",
            "模板占位符是渲染器契约",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
