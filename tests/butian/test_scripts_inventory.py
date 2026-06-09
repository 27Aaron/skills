"""Repository-level coverage guardrails for Butian scripts, tests, and docs."""

import os
import re
import glob
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


class ButianScriptInventoryTests(unittest.TestCase):
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
        with open(os.path.join(DOC_DIR, "run_audit.md"), "r", encoding="utf-8") as handle:
            text = handle.read()

        self.assertIn("服务器扫描，仅显式要求时使用", text)
        self.assertIn("默认项目扫描不会连接服务器", text)
        self.assertIn("--server", text)
        self.assertIn("--server-only", text)
        self.assertIn("--server-inventory", text)

    def test_public_docs_do_not_contain_generated_security_reports(self):
        generated_reports = sorted(
            os.path.basename(path)
            for path in glob.glob(os.path.join(DOC_DIR, "security-report-*.md"))
        )
        self.assertEqual(
            generated_reports,
            [],
            "Generated security reports belong in ignored runtime artifacts, not public docs",
        )

    def test_skill_declares_post_cancel_manual_confirmations(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        repair_path = os.path.join(REFERENCE_DIR, "repair-flow.md")
        with open(repair_path, "r", encoding="utf-8") as handle:
            repair_text = handle.read()

        self.assertIn("references/repair-flow.md", text)
        self.assertIn("待确认动作队列", repair_text)
        self.assertIn("硬编码凭证占位符", repair_text)
        self.assertIn("创建 Dependabot 配置", repair_text)
        self.assertIn("更新过期依赖", repair_text)
        self.assertIn("处理凭证占位符", repair_text)
        self.assertIn("多选 AskUserQuestion", text)
        self.assertIn("取消/暂不处理", repair_text)
        self.assertIn("建议优先处理本次发现的已确认风险项", repair_text)
        self.assertIn("建议优先选择改动较小的修复方式", repair_text)
        self.assertIn("建议顺手处理下面这些维护动作", repair_text)
        self.assertIn("Dependabot 是 GitHub 的依赖更新助手", repair_text)
        self.assertIn("建议现在运行项目构建或测试", repair_text)
        self.assertIn("开始修复", repair_text)
        self.assertIn("先不修复", repair_text)
        self.assertIn("升级到修复版本", repair_text)
        self.assertIn("全部升级到最新版", repair_text)
        self.assertIn("运行验证", repair_text)
        self.assertNotIn("AskUserQuestion 单独确认", repair_text)
        self.assertIn("用户选择暂不处理", repair_text)
        self.assertIn("升级父依赖并重新扫描", repair_text)
        self.assertIn("不弹出待确认动作队列", repair_text)

    def test_skill_links_scenario_references(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        for reference in (
            "references/project-scan.md",
            "references/server-scan.md",
            "references/repair-flow.md",
            "references/sources-and-limits.md",
            "references/report-contract.md",
        ):
            with self.subTest(reference=reference):
                self.assertIn(reference, text)
                self.assertTrue(
                    os.path.isfile(os.path.join(ROOT, "butian", reference)),
                    f"missing {reference}",
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

    def test_scan_comments_describe_current_module_boundaries(self):
        with open(os.path.join(SCRIPT_DIR, "scan.py"), "r", encoding="utf-8") as handle:
            scan_text = handle.read()

        self.assertIn(
            "Repository hygiene, vulnerability, and outdated checks", scan_text
        )
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

        self.assertIn("Secret scan file selection", scan_text)
        self.assertIn("Entropy is a fallback signal", scan_text)
        self.assertIn("Template files keep evidence locatable", scan_text)
        self.assertIn("Regex findings take precedence over entropy", scan_text)

    def test_server_scan_comments_preserve_safety_boundaries(self):
        expectations = {
            "server_collect.py": "Read-only SSH collection must never install",
            "server_inventory.py": "Unsupported or empty inventories preserve gaps",
            "server_match.py": "Unsupported server ecosystems are coverage gaps",
            "run_audit.py": "Server identity paths are report secrets",
        }
        for script, phrase in expectations.items():
            with self.subTest(script=script):
                with open(
                    os.path.join(SCRIPT_DIR, script), "r", encoding="utf-8"
                ) as handle:
                    text = handle.read()
                self.assertIn(phrase, text)

    def test_analyze_comments_preserve_report_contract_boundaries(self):
        with open(os.path.join(SCRIPT_DIR, "analyze.py"), "r", encoding="utf-8") as handle:
            text = handle.read()

        for phrase in (
            "The red/yellow/green buckets are a report contract",
            "fix_config is the machine contract consumed by fix.py",
            "Server confirmed issues are separate from maintenance advice",
            "Outdated dependencies are maintenance signals",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
