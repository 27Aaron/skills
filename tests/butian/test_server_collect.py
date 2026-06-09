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

    def test_docker_commands_are_optional(self):
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

        self.assertNotIn("docker_ps", without_docker_ids)
        self.assertNotIn("docker ", without_docker_commands)
        self.assertIn("docker_ps", with_docker_ids)


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

        with mock.patch.object(server_collect, "run_ssh_command", side_effect=fake_run):
            inventory = server_collect.collect_server_inventory("root@example.test")

        self.assertEqual(inventory["collection_mode"], "ssh")
        self.assertIn("os_release", inventory["outputs"])
        self.assertEqual(inventory["errors"], [])
        all_commands = "\n".join(
            item["command"] for item in inventory["outputs"].values()
        )
        self.assertNotIn("install", all_commands)

    def test_collect_keeps_command_errors(self):
        def fake_run(target, command, **kwargs):
            return {
                "command": command,
                "returncode": 1,
                "stdout": "",
                "stderr": "denied",
            }

        with mock.patch.object(server_collect, "run_ssh_command", side_effect=fake_run):
            inventory = server_collect.collect_server_inventory("root@example.test")

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
