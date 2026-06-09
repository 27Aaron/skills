"""Repository-level coverage guardrails for Butian scripts, tests, and docs."""

import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT_DIR = os.path.join(ROOT, "butian", "scripts")
TEST_DIR = os.path.join(ROOT, "tests", "butian")
DOC_DIR = os.path.join(ROOT, "docs", "butian")
SKILL_PATH = os.path.join(ROOT, "butian", "SKILL.md")

SCRIPT_TEST_FILES = {
    "__init__.py": ["test_scripts_inventory.py"],
    "analyze.py": ["test_analyze.py"],
    "detect.py": ["test_detect.py"],
    "finding_utils.py": ["test_finding_utils.py", "test_repo_checks.py"],
    "fix.py": ["test_fix.py"],
    "iac_checks.py": ["test_iac_checks.py"],
    "labels.py": ["test_labels.py"],
    "repo_checks.py": ["test_repo_checks.py"],
    "report.py": ["test_report.py", "test_report_assets.py"],
    "run_audit.py": ["test_run_audit.py"],
    "scan.py": ["test_scan.py", "test_scan_helpers.py", "test_cache.py"],
    "visualize.py": ["test_visualize.py", "test_report_assets.py"],
    "workflow_checks.py": ["test_workflow_checks.py"],
}

SCRIPT_DOC_FILES = {
    "analyze.py": "analyze.md",
    "detect.py": "detect.md",
    "finding_utils.py": "finding_utils.md",
    "fix.py": "fix.md",
    "iac_checks.py": "iac_checks.md",
    "labels.py": "labels.md",
    "repo_checks.py": "repo_checks.md",
    "report.py": "report.md",
    "run_audit.py": "run_audit.md",
    "scan.py": "scan.md",
    "visualize.py": "visualize.md",
    "workflow_checks.py": "workflow_checks.md",
}


class ButianScriptInventoryTests(unittest.TestCase):
    def test_every_python_script_has_declared_test_files(self):
        scripts = sorted(name for name in os.listdir(SCRIPT_DIR) if name.endswith(".py"))
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
                self.assertTrue(os.path.isfile(doc_path), f"missing docs page {doc_file}")
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

    def test_skill_declares_post_cancel_manual_confirmations(self):
        with open(SKILL_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()

        self.assertIn("待确认动作队列", text)
        self.assertIn("硬编码凭证占位符", text)
        self.assertIn("创建 Dependabot 配置", text)
        self.assertIn("更新过期依赖", text)
        self.assertIn("多选 AskUserQuestion", text)
        self.assertIn("取消/暂不处理", text)
        self.assertIn("建议优先处理本次发现的已确认风险项", text)
        self.assertIn("建议优先选择改动较小的修复方式", text)
        self.assertIn("建议顺手处理下面这些维护动作", text)
        self.assertIn("Dependabot 是 GitHub 的依赖更新助手", text)
        self.assertIn("建议现在运行项目构建或测试", text)
        self.assertIn("开始修复", text)
        self.assertIn("先不修复", text)
        self.assertIn("升级到修复版本", text)
        self.assertIn("全部升级到最新版", text)
        self.assertIn("运行验证", text)
        self.assertNotIn("AskUserQuestion 单独确认", text)
        self.assertIn("用户选择暂不处理", text)
        self.assertIn("升级父依赖并重新扫描", text)
        self.assertIn("不弹出待确认动作队列", text)


if __name__ == "__main__":
    unittest.main()
