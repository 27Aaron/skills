import os
import tempfile
import unittest

from butian.scripts import iac_checks


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


class IacChecksTests(unittest.TestCase):
    def test_detects_dockerfile_latest_and_missing_user(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(os.path.join(root, "Dockerfile"), "FROM node:latest\nRUN npm ci\n")

            findings = iac_checks.scan_iac_checks(root)

            self.assertTrue(any(f["id"] == "iac.docker_latest_tag" for f in findings))
            self.assertTrue(any(f["id"] == "iac.docker_missing_user" for f in findings))

    def test_detects_dockerfile_named_variant(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(os.path.join(root, "Dockerfile.prod"), "FROM node:latest\nUSER app\n")

            findings = iac_checks.scan_iac_checks(root)

            self.assertTrue(any(f["file"] == "Dockerfile.prod" for f in findings))

    def test_detects_dockerfile_secret_env_and_remote_script(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(
                os.path.join(root, "Dockerfile"),
                "FROM python:3.12\nENV API_SECRET=abc123\nRUN curl https://x.test/i.sh | sh\nUSER app\n",
            )

            findings = iac_checks.scan_iac_checks(root)

            self.assertTrue(any(f["id"] == "iac.docker_secret_env" for f in findings))
            self.assertTrue(
                any(f["id"] == "iac.docker_remote_script_pipe" for f in findings)
            )

    def test_detects_compose_privileged_socket_and_public_database_port(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(
                os.path.join(root, "docker-compose.yml"),
                """
services:
  db:
    image: postgres:16
    privileged: true
    ports:
      - "0.0.0.0:5432:5432"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
            )

            findings = iac_checks.scan_iac_checks(root)

            ids = {f["id"] for f in findings}
            self.assertIn("iac.compose_privileged", ids)
            self.assertIn("iac.compose_docker_socket", ids)
            self.assertIn("iac.compose_public_database_port", ids)

    def test_detects_kubernetes_privileged_hostpath_and_secret_data(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(
                os.path.join(root, "deploy", "k8s.yml"),
                """
apiVersion: v1
kind: Secret
data:
  password: c2VjcmV0
---
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  volumes:
  - name: docker
    hostPath:
      path: /var/run/docker.sock
  containers:
  - name: app
    securityContext:
      privileged: true
      runAsUser: 0
""",
            )

            findings = iac_checks.scan_iac_checks(root)

            ids = {f["id"] for f in findings}
            self.assertIn("iac.k8s_secret_data", ids)
            self.assertIn("iac.k8s_privileged", ids)
            self.assertIn("iac.k8s_hostpath", ids)
            self.assertIn("iac.k8s_host_network", ids)
            self.assertIn("iac.k8s_run_as_root", ids)

    def test_detects_terraform_public_sensitive_port_and_state_files(self):
        with tempfile.TemporaryDirectory(prefix="butian-iac-") as root:
            write(
                os.path.join(root, "infra", "main.tf"),
                'cidr_blocks = ["0.0.0.0/0"]\nfrom_port = 22\nto_port = 22\n',
            )
            write(os.path.join(root, "infra", "terraform.tfvars"), 'token = "secret"\n')

            findings = iac_checks.scan_iac_checks(root)

            ids = {f["id"] for f in findings}
            self.assertIn("iac.terraform_public_sensitive_port", ids)
            self.assertIn("iac.terraform_sensitive_file", ids)


if __name__ == "__main__":
    unittest.main()
