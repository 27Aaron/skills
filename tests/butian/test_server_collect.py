import os
import tempfile
import unittest
from unittest import mock

from butian.scripts import server_collect


class CommandPlanTests(unittest.TestCase):
    def test_default_commands_are_read_only(self):
        commands = server_collect.command_plan(include_docker_metadata=False)
        joined = "\n".join(cmd["command"] for cmd in commands)

        self.assertIn("cat /etc/os-release", joined)
        self.assertIn("uname -r", joined)
        self.assertNotIn(" apt install ", joined)
        self.assertNotIn(" apt upgrade ", joined)
        self.assertNotIn(" dnf install ", joined)
        self.assertNotIn(" yum install ", joined)
        self.assertNotIn(" apk add ", joined)
        self.assertNotIn(" sudo ", joined)
        self.assertNotIn("|| true", joined)

    def test_package_manager_commands_cover_supported_linux_families(self):
        joined = "\n".join(
            cmd["command"]
            for cmd in server_collect.command_plan(include_docker_metadata=False)
        )

        self.assertIn("dpkg-query -W", joined)
        self.assertIn("rpm -qa", joined)
        self.assertIn("apk info -vv", joined)
        self.assertIn("apt list --upgradable", joined)
        self.assertIn("dnf updateinfo list security", joined)
        self.assertIn("yum updateinfo list security", joined)
        self.assertIn(
            "zypper --non-interactive list-patches --category security", joined
        )

    def test_security_posture_commands_cover_ssh_and_firewalls(self):
        commands = server_collect.command_plan(include_docker_metadata=False)
        ids = {cmd["id"] for cmd in commands}
        joined = "\n".join(cmd["command"] for cmd in commands)

        self.assertIn("sshd_config", ids)
        self.assertIn("ufw_status", ids)
        self.assertIn("firewalld_status", ids)
        self.assertIn("nft_rules", ids)
        self.assertIn("iptables_rules", ids)
        self.assertIn("ip6tables_rules", ids)
        self.assertIn("sshd -T", joined)
        self.assertIn("ufw status", joined)
        self.assertIn("firewall-cmd", joined)
        self.assertIn("nft list ruleset", joined)
        self.assertIn("iptables -S", joined)
        self.assertNotIn(" sudo ", joined)
        self.assertNotIn("systemctl restart", joined)

    def test_common_software_version_commands_are_read_only(self):
        commands = server_collect.command_plan(include_docker_metadata=False)
        ids = {cmd["id"] for cmd in commands}
        joined = "\n".join(cmd["command"] for cmd in commands)

        expected_ids = {
            "apache_v",
            "caddy_v",
            "tomcat_v",
            "gnutls_v",
            "mysql_v",
            "postgres_v",
            "redis_v",
            "containerd_v",
            "node_v",
            "java_v",
            "rabbitmq_v",
            "haproxy_v",
            "grafana_v",
            "prometheus_v",
            "git_v",
            "curl_v",
            "wget_v",
            "systemd_v",
        }
        self.assertTrue(expected_ids.issubset(ids))
        self.assertIn("apache2 -v", joined)
        self.assertIn("httpd -v", joined)
        self.assertIn("docker --version", joined)
        self.assertIn("node --version", joined)
        self.assertIn("java -version", joined)
        self.assertNotIn("docker exec", joined)
        self.assertNotIn("systemctl restart", joined)

    def test_docker_container_metadata_is_optional(self):
        without_docker_ids = "\n".join(
            cmd["id"]
            for cmd in server_collect.command_plan(include_docker_metadata=False)
        )
        with_docker_ids = "\n".join(
            cmd["id"]
            for cmd in server_collect.command_plan(include_docker_metadata=True)
        )
        without_docker_commands = "\n".join(
            cmd["command"]
            for cmd in server_collect.command_plan(include_docker_metadata=False)
        )

        self.assertIn("docker_version", without_docker_ids)
        self.assertNotIn("docker_ps", without_docker_ids)
        self.assertIn("docker --version", without_docker_commands)
        self.assertNotIn("docker ps", without_docker_commands)
        self.assertIn("docker_ps", with_docker_ids)


class SshKeyPolicyTests(unittest.TestCase):
    def test_server_scan_accepts_ssh_config_alias_as_optional_convenience(self):
        config = """
Host prod-web
  HostName 203.0.113.10
  User deploy
  Port 2222
  IdentityFile ~/.ssh/prod-web_ed25519
  IdentitiesOnly yes
  PreferredAuthentications publickey
  PasswordAuthentication no
  PubkeyAuthentication yes
  BatchMode yes
"""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(config)
            handle.flush()

            policy = server_collect.resolve_ssh_policy(
                "prod-web", ssh_config=handle.name
            )

        self.assertEqual(policy["target"], "prod-web")
        self.assertIn("identityfile", policy["options"])

    def test_ssh_config_wildcard_identity_file_is_collected(self):
        config = """
Host *
  IdentityFile /tmp/id_shared
  BatchMode yes
"""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(config)
            handle.flush()

            policy = server_collect.resolve_ssh_policy(
                "prod-web", ssh_config=handle.name
            )

        self.assertIn("/tmp/id_shared", policy["options"].get("identityfile", []))
        self.assertIn("/tmp/id_shared", server_collect._identity_secret_values(policy))

    def test_server_scan_accepts_direct_user_ip_with_key_only_ssh_options(self):
        policy = server_collect.resolve_ssh_policy(
            "root@203.0.113.10", identity="/tmp/id_ed25519"
        )
        cmd = server_collect._ssh_base(
            "root@203.0.113.10", port=2222, identity="/tmp/id_ed25519"
        )

        self.assertEqual(policy["target"], "root@203.0.113.10")
        self.assertIn("-p", cmd)
        self.assertIn("2222", cmd)
        self.assertIn("-i", cmd)
        self.assertIn("/tmp/id_ed25519", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("PasswordAuthentication=no", cmd)
        self.assertIn("KbdInteractiveAuthentication=no", cmd)
        self.assertIn("PubkeyAuthentication=yes", cmd)
        self.assertIn("PreferredAuthentications=publickey", cmd)

    def test_ssh_base_can_use_config_file_without_requiring_it(self):
        cmd = server_collect._ssh_base("prod-web", ssh_config="/tmp/ssh_config")

        self.assertIn("-F", cmd)
        self.assertIn("/tmp/ssh_config", cmd)
        self.assertIn("prod-web", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("PasswordAuthentication=no", cmd)

    def test_server_scan_rejects_unsafe_target_shape(self):
        with self.assertRaisesRegex(ValueError, "SSH 目标"):
            server_collect.resolve_ssh_policy("-oProxyCommand=bad")

        with self.assertRaisesRegex(ValueError, "SSH 目标"):
            server_collect.resolve_ssh_policy("root@host whoami")

    def test_server_scan_rejects_invalid_port_range(self):
        for port in (0, -1, 70000):
            with self.subTest(port=port):
                with self.assertRaisesRegex(ValueError, "SSH 端口"):
                    server_collect.resolve_ssh_policy("root@203.0.113.10", port=port)


class CollectServerInventoryTests(unittest.TestCase):
    def test_collect_records_outputs_without_installing_tools(self):
        def fake_run(target, command, **kwargs):
            if "cat /etc/os-release" in command:
                return {
                    "command": command,
                    "returncode": 0,
                    "stdout": "ID=ubuntu\nVERSION_ID=24.04\n",
                    "stderr": "",
                }
            return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}

        with (
            mock.patch.object(server_collect, "run_ssh_command", side_effect=fake_run),
            mock.patch.object(
                server_collect,
                "resolve_ssh_policy",
                return_value={"target": "root@203.0.113.10", "options": {}},
            ),
        ):
            inventory = server_collect.collect_server_inventory("root@203.0.113.10")

        self.assertEqual(inventory["collection_mode"], "ssh")
        self.assertIn("os_release", inventory["outputs"])
        self.assertEqual(inventory["errors"], [])
        all_commands = "\n".join(
            item["command"] for item in inventory["outputs"].values()
        )
        self.assertNotIn("install", all_commands)

    def test_collect_uses_normalized_policy_target_and_port(self):
        calls = []

        def fake_run(target, command, **kwargs):
            calls.append((target, kwargs))
            return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}

        with (
            mock.patch.object(server_collect, "run_ssh_command", side_effect=fake_run),
            mock.patch.object(
                server_collect,
                "resolve_ssh_policy",
                return_value={
                    "target": "root@203.0.113.10",
                    "port": 2222,
                    "identity": "/tmp/id_ed25519",
                    "ssh_config": "/tmp/ssh_config",
                    "options": {},
                },
            ),
        ):
            server_collect.collect_server_inventory(" root@203.0.113.10 ")

        self.assertTrue(calls)
        self.assertTrue(all(target == "root@203.0.113.10" for target, _ in calls))
        self.assertTrue(all(kwargs["port"] == 2222 for _, kwargs in calls))
        self.assertTrue(
            all(kwargs["identity"] == "/tmp/id_ed25519" for _, kwargs in calls)
        )
        self.assertTrue(
            all(kwargs["ssh_config"] == "/tmp/ssh_config" for _, kwargs in calls)
        )

    def test_collect_keeps_command_errors(self):
        def fake_run(target, command, **kwargs):
            return {
                "command": command,
                "returncode": 1,
                "stdout": "",
                "stderr": "denied",
            }

        with (
            mock.patch.object(server_collect, "run_ssh_command", side_effect=fake_run),
            mock.patch.object(
                server_collect,
                "resolve_ssh_policy",
                return_value={"target": "root@203.0.113.10", "options": {}},
            ),
        ):
            inventory = server_collect.collect_server_inventory("root@203.0.113.10")

        self.assertGreater(len(inventory["errors"]), 0)
        self.assertEqual(inventory["errors"][0]["step"], "server_collect")

    def test_inventory_file_round_trip(self):
        payload = {"target": "root@example.test", "outputs": {}, "errors": []}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "server-inventory.json")
            server_collect.write_inventory(path, payload)
            result = server_collect.read_inventory_file(path)

        self.assertEqual(result, payload)


if __name__ == "__main__":
    unittest.main()
