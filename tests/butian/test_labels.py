"""Detailed unit tests for shared Butian display labels."""

import re
import unittest

from butian.scripts import analyze, labels, report, scan


class SharedLabelTests(unittest.TestCase):
    def test_secret_labels_cover_every_scanner_secret_type(self):
        scanner_types = {secret_type for secret_type, _pattern in scan.SECRET_REGEXES}
        missing = scanner_types - set(labels.SECRET_TYPE_LABELS)
        self.assertEqual(missing, set())

    def test_sensitive_labels_cover_every_scanner_sensitive_file_type(self):
        scanner_types = {
            file_type for file_type, _patterns in scan.SENSITIVE_FILE_PATTERNS
        }
        missing = scanner_types - set(labels.SENSITIVE_TYPE_LABELS)
        self.assertEqual(missing, set())

    def test_labels_are_non_empty_human_readable_strings(self):
        for mapping in (labels.SECRET_TYPE_LABELS, labels.SENSITIVE_TYPE_LABELS):
            self.assertGreater(len(mapping), 0)
            for key, value in mapping.items():
                self.assertIsInstance(key, str)
                self.assertIsInstance(value, str)
                self.assertTrue(key.strip())
                self.assertTrue(value.strip())
                self.assertNotEqual(key, value)

    def test_label_keys_use_lowercase_machine_identifiers(self):
        key_pattern = re.compile(r"^[a-z0-9][a-z0-9_/-]*[a-z0-9]$")
        for key in list(labels.SECRET_TYPE_LABELS) + list(labels.SENSITIVE_TYPE_LABELS):
            self.assertRegex(key, key_pattern)
            self.assertEqual(key, key.lower())
            self.assertNotIn(" ", key)

    def test_report_and_analyze_use_the_shared_label_tables(self):
        self.assertIs(analyze.SECRET_TYPE_LABELS, labels.SECRET_TYPE_LABELS)
        self.assertIs(analyze.SENSITIVE_TYPE_LABELS, labels.SENSITIVE_TYPE_LABELS)
        self.assertIs(report.SECRET_TYPE_LABELS, labels.SECRET_TYPE_LABELS)
        self.assertIs(report.SENSITIVE_TYPE_LABELS, labels.SENSITIVE_TYPE_LABELS)

    def test_newly_added_secret_types_have_expected_display_names(self):
        expected = {
            "aws_session_token": "AWS 临时会话 Token",
            "gcp_oauth_token": "GCP OAuth Token",
            "mongodb_connection": "MongoDB 连接字符串",
            "base64_secret": "疑似 Base64 编码密钥",
        }
        for key, label_text in expected.items():
            self.assertEqual(labels.SECRET_TYPE_LABELS[key], label_text)

    def test_newly_added_sensitive_types_have_expected_display_names(self):
        expected = {
            "terraform_state": "Terraform 状态文件",
            "kubeconfig": "Kubernetes kubeconfig",
            "docker_cfg": "Docker 凭据配置",
            "history": "命令历史文件",
        }
        for key, label_text in expected.items():
            self.assertEqual(labels.SENSITIVE_TYPE_LABELS[key], label_text)

    def test_report_label_helpers_hide_raw_type_when_label_exists(self):
        self.assertEqual(report.secret_type_label("openai_key"), "OpenAI API Key")
        self.assertEqual(report.sensitive_type_label("env_file"), "环境变量文件")

    def test_report_label_helpers_fallback_to_raw_type_for_unknown_values(self):
        self.assertEqual(report.secret_type_label("custom_secret"), "custom_secret")
        self.assertEqual(report.sensitive_type_label("custom_file"), "custom_file")
        self.assertEqual(report.secret_type_label(""), "密钥")
        self.assertEqual(report.sensitive_type_label(""), "敏感文件")


if __name__ == "__main__":
    unittest.main()
