import unittest

from butian.scripts import server_analyze


class ServerAnalyzeTests(unittest.TestCase):
    def test_build_server_analysis_keeps_confirmed_and_maintenance(self):
        assets = {
            "distro": {
                "id": "ubuntu",
                "version_id": "24.04",
                "ecosystem": "Ubuntu:24.04:LTS",
            },
            "packages": [{"name": "nginx"}, {"name": "openssl"}],
            "kernel": {"name": "linux-image-6.8.0-53-generic", "queryable": True},
            "ports": [
                {
                    "address": "0.0.0.0",
                    "port": 6379,
                    "process": "redis-server",
                    "public": True,
                    "raw": "redis raw",
                }
            ],
            "ssh": {"available": False, "options": {}},
            "firewall": {"has_active_firewall": True, "tools": {}},
            "docker": {
                "containers": [
                    {
                        "name": "web",
                        "image": "nginx:1.18",
                        "image_name": "nginx",
                        "image_tag": "1.18",
                        "explicit_old_tag": True,
                    }
                ]
            },
            "errors": [],
        }
        matched = {
            "confirmed_issues": [
                {"package": "nginx", "severity": "high", "confidence": "confirmed"},
                {"package": "nginx", "severity": "medium", "confidence": "cpe_only"},
            ],
            "errors": [],
        }

        result = server_analyze.build_server_analysis(assets, matched)

        self.assertEqual(result["summary"]["package_count"], 2)
        self.assertEqual(len(result["confirmed_issues"]), 1)
        self.assertEqual(len(result["maintenance_items"]), 2)
        self.assertIn("Docker 容器", result["maintenance_items"][0]["title"])
        self.assertIn("不扫描容器内部", result["maintenance_items"][0]["summary"])
        self.assertTrue(
            all(
                item["confidence"] == "maintenance"
                for item in result["maintenance_items"]
            )
        )

    def test_docker_latest_custom_and_unparseable_are_filtered(self):
        assets = {
            "distro": {},
            "packages": [],
            "kernel": {},
            "ports": [],
            "docker": {
                "containers": [
                    {
                        "name": "app",
                        "image": "private/app:latest",
                        "image_name": "app",
                        "image_tag": "latest",
                        "explicit_old_tag": False,
                    },
                    {
                        "name": "custom",
                        "image": "nginx:company-build",
                        "image_name": "nginx",
                        "image_tag": "company-build",
                        "explicit_old_tag": False,
                    },
                    {
                        "name": "untagged",
                        "image": "nginx",
                        "image_name": "nginx",
                        "image_tag": "",
                        "explicit_old_tag": False,
                    },
                ]
            },
            "errors": [],
        }

        result = server_analyze.build_server_analysis(
            assets, {"confirmed_issues": [], "errors": []}
        )

        self.assertEqual(result["maintenance_items"], [])

    def test_public_sensitive_process_names_are_normalized(self):
        ports = [
            {
                "address": "0.0.0.0",
                "port": 6379,
                "process": "redis-server",
                "public": True,
            },
            {"address": "0.0.0.0", "port": 3306, "process": "mysqld", "public": True},
            {
                "address": "127.0.0.1",
                "port": 5432,
                "process": "postgres",
                "public": False,
            },
            {"address": "0.0.0.0", "port": 80, "process": "nginx", "public": True},
        ]

        items = server_analyze.public_service_maintenance_items(ports)

        self.assertEqual([item["service"] for item in items], ["redis", "mysql"])
        self.assertIn("服务对公网监听", items[0]["title"])
        self.assertTrue(all(item["confidence"] == "maintenance" for item in items))

    def test_ssh_maintenance_items_are_advice_not_confirmed_vulnerabilities(self):
        assets = {
            "distro": {},
            "packages": [],
            "kernel": {},
            "ports": [
                {
                    "address": "0.0.0.0",
                    "port": 22,
                    "process": "sshd",
                    "public": True,
                    "raw": "sshd public",
                }
            ],
            "ssh": {
                "available": True,
                "options": {
                    "PasswordAuthentication": "yes",
                    "KbdInteractiveAuthentication": "yes",
                    "PubkeyAuthentication": "no",
                    "PermitRootLogin": "yes",
                    "PermitEmptyPasswords": "yes",
                },
            },
            "firewall": {"has_active_firewall": True, "tools": {}},
            "docker": {"containers": []},
            "errors": [],
        }

        result = server_analyze.build_server_analysis(
            assets, {"confirmed_issues": [], "errors": []}
        )

        titles = "\n".join(item["title"] for item in result["maintenance_items"])
        self.assertIn("SSH 允许密码登录", titles)
        self.assertIn("SSH 未启用密钥登录", titles)
        self.assertIn("root 账号允许直接 SSH 登录", titles)
        self.assertIn("SSH 允许空密码登录", titles)
        self.assertEqual(result["confirmed_issues"], [])
        self.assertTrue(
            all(item["confidence"] == "maintenance" for item in result["maintenance_items"])
        )

    def test_firewall_maintenance_item_when_public_ports_lack_firewall(self):
        assets = {
            "distro": {},
            "packages": [],
            "kernel": {},
            "ports": [
                {
                    "address": "0.0.0.0",
                    "port": 443,
                    "process": "nginx",
                    "public": True,
                    "raw": "nginx public",
                }
            ],
            "ssh": {"available": False, "options": {}},
            "firewall": {
                "has_active_firewall": False,
                "tools": {"ufw": {"available": True, "active": False}},
            },
            "docker": {"containers": []},
            "errors": [],
        }

        result = server_analyze.build_server_analysis(
            assets, {"confirmed_issues": [], "errors": []}
        )

        self.assertTrue(
            any(
                item["category"] == "firewall_posture"
                and "防火墙" in item["title"]
                for item in result["maintenance_items"]
            )
        )

    def test_native_security_updates_and_unlinked_service_versions_are_maintenance(self):
        assets = {
            "distro": {},
            "packages": [],
            "kernel": {},
            "ports": [],
            "services": [{"name": "nginx.service"}],
            "ssh": {"available": False, "options": {}},
            "firewall": {"has_active_firewall": True, "tools": {}},
            "docker": {"containers": []},
            "native_security_updates": [
                {
                    "manager": "apt",
                    "name": "openssl",
                    "current_version": "3.0.13-0ubuntu3.5",
                    "fixed_version": "3.0.13-0ubuntu3.6",
                }
            ],
            "software_versions": [
                {
                    "name": "nginx",
                    "version": "1.24.0",
                    "source": "nginx -v",
                    "linked_package": {},
                }
            ],
            "errors": [],
        }

        result = server_analyze.build_server_analysis(
            assets, {"confirmed_issues": [], "errors": []}
        )

        titles = "\n".join(item["title"] for item in result["maintenance_items"])
        self.assertIn("系统安全更新可用：openssl", titles)
        self.assertIn("nginx 版本无法关联发行版包", titles)
        self.assertEqual(result["confirmed_issues"], [])
        self.assertEqual(result["summary"]["service_count"], 1)
        self.assertEqual(result["services"][0]["name"], "nginx.service")

    def test_asset_and_match_errors_are_preserved(self):
        result = server_analyze.build_server_analysis(
            {
                "distro": {},
                "packages": [],
                "kernel": {},
                "ports": [],
                "docker": {"containers": []},
                "errors": [{"step": "server_inventory", "message": "unsupported"}],
            },
            {
                "confirmed_issues": [],
                "errors": [{"step": "vulnerability_check", "message": "OSV"}],
            },
        )

        self.assertEqual(len(result["errors"]), 2)


if __name__ == "__main__":
    unittest.main()
