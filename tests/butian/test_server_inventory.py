import unittest

from butian.scripts import server_inventory


class OsReleaseParsingTests(unittest.TestCase):
    def test_parse_ubuntu_os_release(self):
        raw = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "ubuntu")
        self.assertEqual(result["version_id"], "24.04")
        self.assertEqual(result["codename"], "noble")
        self.assertEqual(result["family"], "debian")
        self.assertEqual(result["package_type"], "deb")
        self.assertEqual(result["ecosystem"], "Ubuntu:24.04:LTS")
        self.assertTrue(result["supported"])

    def test_parse_debian_os_release(self):
        raw = (
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'
        )

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "debian")
        self.assertEqual(result["family"], "debian")
        self.assertEqual(result["package_type"], "deb")
        self.assertEqual(result["ecosystem"], "Debian:12")

    def test_parse_alpine_os_release(self):
        raw = 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.2\n'

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "alpine")
        self.assertEqual(result["family"], "alpine")
        self.assertEqual(result["package_type"], "apk")
        self.assertEqual(result["ecosystem"], "Alpine:v3.20")

    def test_parse_supported_rhel_family_os_release(self):
        cases = [
            ("rhel", "Red Hat Enterprise Linux:9"),
            ("rocky", "Rocky Linux:9"),
            ("almalinux", "AlmaLinux:9"),
        ]
        for distro_id, ecosystem in cases:
            with self.subTest(distro_id=distro_id):
                raw = (
                    f'NAME="{distro_id}"\nID="{distro_id}"\n'
                    'VERSION_ID="9.4"\nID_LIKE="rhel centos fedora"\n'
                )

                result = server_inventory.parse_os_release(raw)

                self.assertTrue(result["supported"])
                self.assertEqual(result["family"], "rhel")
                self.assertEqual(result["package_type"], "rpm")
                self.assertEqual(result["ecosystem"], ecosystem)

    def test_parse_centos_stream_os_release(self):
        raw = (
            'NAME="CentOS Stream"\nID="centos"\n'
            'VERSION_ID="9"\nPRETTY_NAME="CentOS Stream 9"\n'
        )

        result = server_inventory.parse_os_release(raw)

        self.assertTrue(result["supported"])
        self.assertEqual(result["family"], "rhel")
        self.assertEqual(result["ecosystem"], "CentOS Stream:9")

    def test_centos_linux_is_not_supported_as_centos_stream(self):
        raw = (
            'NAME="CentOS Linux"\nID="centos"\n'
            'VERSION_ID="7"\nPRETTY_NAME="CentOS Linux 7"\n'
        )

        result = server_inventory.parse_os_release(raw)

        self.assertFalse(result["supported"])
        self.assertEqual(result["family"], "unknown")
        self.assertEqual(result["ecosystem"], "")

    def test_parse_suse_and_opensuse_os_release(self):
        cases = [
            ("sles", "SUSE:15"),
            ("opensuse-leap", "SUSE:15"),
            ("opensuse-tumbleweed", "SUSE:Tumbleweed"),
        ]
        for distro_id, ecosystem in cases:
            with self.subTest(distro_id=distro_id):
                version = "20260601" if distro_id == "opensuse-tumbleweed" else "15.6"
                raw = (
                    f'NAME="{distro_id}"\nID="{distro_id}"\n'
                    f'VERSION_ID="{version}"\nID_LIKE="suse opensuse"\n'
                )

                result = server_inventory.parse_os_release(raw)

                self.assertTrue(result["supported"])
                self.assertEqual(result["family"], "suse")
                self.assertEqual(result["package_type"], "rpm")
                self.assertEqual(result["ecosystem"], ecosystem)

    def test_parse_amazon_linux_os_release(self):
        raw = 'NAME="Amazon Linux"\nID="amzn"\nVERSION_ID="2023"\nID_LIKE="fedora"\n'

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "amzn")
        self.assertEqual(result["family"], "amazon")
        self.assertEqual(result["package_type"], "rpm")
        self.assertEqual(result["ecosystem"], "Amazon Linux:2023")

    def test_parse_oracle_linux_os_release(self):
        raw = (
            'NAME="Oracle Linux Server"\nID="ol"\n'
            'VERSION_ID="9.4"\nID_LIKE="fedora rhel"\n'
        )

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "ol")
        self.assertEqual(result["family"], "oracle")
        self.assertEqual(result["package_type"], "rpm")
        self.assertEqual(result["ecosystem"], "Oracle Linux:9")

    def test_rhel_like_unlisted_distro_is_not_supported(self):
        raw = 'NAME="Anolis OS"\nID="anolis"\nVERSION_ID="8.9"\nID_LIKE="rhel fedora"\n'

        result = server_inventory.parse_os_release(raw)

        self.assertEqual(result["id"], "anolis")
        self.assertFalse(result["supported"])
        self.assertEqual(result["family"], "unknown")
        self.assertEqual(result["package_type"], "unknown")
        self.assertEqual(result["ecosystem"], "")


class PackageParsingTests(unittest.TestCase):
    def test_parse_dpkg_query_output(self):
        raw = (
            "nginx\t1.24.0-2ubuntu7.3\tamd64\tnginx\n"
            "linux-image-6.8.0-53-generic\t6.8.0-53.55\tamd64\tlinux\n"
        )
        distro = {
            "id": "ubuntu",
            "ecosystem": "Ubuntu:24.04:LTS",
            "package_type": "deb",
        }

        packages = server_inventory.parse_dpkg_packages(raw, distro)

        self.assertEqual(packages[0]["name"], "nginx")
        self.assertEqual(packages[0]["version"], "1.24.0-2ubuntu7.3")
        self.assertEqual(packages[0]["source_name"], "nginx")
        self.assertEqual(packages[0]["ecosystem"], "Ubuntu:24.04:LTS")
        self.assertEqual(packages[0]["package_type"], "deb")
        self.assertIn("pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.3", packages[0]["purl"])

    def test_parse_rpm_output(self):
        raw = (
            "nginx\t1.24.0-1.el9\tx86_64\nkernel-core\t5.14.0-427.13.1.el9_4\tx86_64\n"
        )
        distro = {
            "id": "rocky",
            "ecosystem": "Rocky Linux:9",
            "package_type": "rpm",
        }

        packages = server_inventory.parse_rpm_packages(raw, distro)

        self.assertEqual(packages[0]["name"], "nginx")
        self.assertEqual(packages[0]["version"], "1.24.0-1.el9")
        self.assertEqual(packages[0]["package_type"], "rpm")
        self.assertIn("pkg:rpm/rocky/nginx@1.24.0-1.el9", packages[0]["purl"])

    def test_parse_apk_output(self):
        raw = (
            "nginx-1.26.2-r0 - HTTP and reverse proxy server\n"
            "linux-lts-6.6.52-r0 - Linux lts kernel\n"
        )
        distro = {
            "id": "alpine",
            "ecosystem": "Alpine:v3.20",
            "package_type": "apk",
        }

        packages = server_inventory.parse_apk_packages(raw, distro)

        self.assertEqual(packages[0]["name"], "nginx")
        self.assertEqual(packages[0]["version"], "1.26.2-r0")
        self.assertEqual(packages[0]["package_type"], "apk")
        self.assertIn("pkg:apk/alpine/nginx@1.26.2-r0", packages[0]["purl"])


class KernelAssetTests(unittest.TestCase):
    def test_build_deb_kernel_asset_from_linux_image_package(self):
        packages = [
            {
                "name": "linux-image-6.8.0-53-generic",
                "version": "6.8.0-53.55",
                "package_type": "deb",
                "ecosystem": "Ubuntu:24.04:LTS",
            }
        ]

        asset = server_inventory.build_kernel_asset("6.8.0-53-generic", packages)

        self.assertEqual(asset["asset_type"], "kernel_package")
        self.assertEqual(asset["name"], "linux-image-6.8.0-53-generic")
        self.assertEqual(asset["version"], "6.8.0-53.55")
        self.assertTrue(asset["queryable"])

    def test_build_rpm_kernel_asset_from_kernel_core(self):
        packages = [
            {
                "name": "kernel-core",
                "version": "5.14.0-427.13.1.el9_4",
                "package_type": "rpm",
                "ecosystem": "Rocky Linux:9",
            }
        ]

        asset = server_inventory.build_kernel_asset(
            "5.14.0-427.13.1.el9_4.x86_64", packages
        )

        self.assertEqual(asset["name"], "kernel-core")
        self.assertTrue(asset["queryable"])

    def test_unmatched_kernel_is_not_queryable(self):
        asset = server_inventory.build_kernel_asset("6.6.52-0-lts", [])

        self.assertFalse(asset["queryable"])
        self.assertEqual(asset["version"], "6.6.52-0-lts")


class ExposureAndDockerTests(unittest.TestCase):
    def test_parse_ss_listening_ports(self):
        raw = (
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=123,fd=7))\n'
            'LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=55,fd=5))\n'
            'LISTEN 0 128 *:6379 *:* users:(("redis",pid=77,fd=8))\n'
        )

        ports = server_inventory.parse_listening_ports(raw)

        self.assertEqual(ports[0]["address"], "0.0.0.0")
        self.assertEqual(ports[0]["port"], 443)
        self.assertEqual(ports[0]["process"], "nginx")
        self.assertTrue(ports[0]["public"])
        self.assertFalse(ports[1]["public"])
        self.assertEqual(ports[2]["address"], "*")
        self.assertTrue(ports[2]["public"])

    def test_parse_ss_udp_unconn_ports(self):
        raw = 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=12,fd=4))\n'

        ports = server_inventory.parse_listening_ports(raw)

        self.assertEqual(ports[0]["address"], "0.0.0.0")
        self.assertEqual(ports[0]["port"], 53)
        self.assertEqual(ports[0]["process"], "named")
        self.assertTrue(ports[0]["public"])

    def test_parse_docker_ps_json_lines_only_keeps_metadata(self):
        raw = (
            '{"ID":"abc","Image":"nginx:1.18","Names":"web","Ports":"0.0.0.0:443->443/tcp"}\n'
            '{"ID":"def","Image":"private/app:latest","Names":"app","Ports":""}\n'
        )

        containers = server_inventory.parse_docker_ps(raw)

        self.assertEqual(containers[0]["image_name"], "nginx")
        self.assertEqual(containers[0]["image_tag"], "1.18")
        self.assertEqual(containers[0]["ports"], "0.0.0.0:443->443/tcp")
        self.assertTrue(containers[0]["explicit_old_tag"])
        self.assertNotIn("packages", containers[0])
        self.assertFalse(containers[1]["explicit_old_tag"])

    def test_major_only_docker_tags_are_compared_as_major_zero(self):
        self.assertFalse(server_inventory.is_explicit_old_image_tag("redis", "6"))
        self.assertFalse(server_inventory.is_explicit_old_image_tag("mysql", "8"))
        self.assertTrue(server_inventory.is_explicit_old_image_tag("redis", "5"))

    def test_old_image_version_uses_version_tuple_not_float(self):
        containers = server_inventory.parse_docker_ps(
            '{"ID":"abc","Image":"nginx:1.9","Names":"web","Ports":""}\n'
        )

        self.assertTrue(containers[0]["explicit_old_tag"])
        self.assertGreater(
            server_inventory.version_tuple("1.10"),
            server_inventory.version_tuple("1.9"),
        )

    def test_latest_custom_and_unparseable_image_tags_are_not_old(self):
        raw = (
            '{"Image":"nginx:latest","Names":"latest","Ports":""}\n'
            '{"Image":"nginx:company-build","Names":"custom","Ports":""}\n'
            '{"Image":"nginx","Names":"untagged","Ports":""}\n'
        )

        containers = server_inventory.parse_docker_ps(raw)

        self.assertEqual(
            [item["explicit_old_tag"] for item in containers], [False, False, False]
        )

    def test_build_server_assets_combines_packages_kernel_ports_and_docker(self):
        inventory = {
            "target": "root@example.test",
            "collection_mode": "ssh",
            "outputs": {
                "os_release": {"stdout": "ID=ubuntu\nVERSION_ID=24.04\n"},
                "uname_r": {"stdout": "6.8.0-53-generic\n"},
                "dpkg_packages": {
                    "stdout": (
                        "nginx\t1.24.0-2ubuntu7.3\tamd64\tnginx\n"
                        "linux-image-6.8.0-53-generic\t6.8.0-53.55\tamd64\tlinux\n"
                    )
                },
                "ports": {
                    "stdout": (
                        'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=123,fd=7))\n'
                    )
                },
                "docker_ps": {
                    "stdout": (
                        '{"ID":"abc","Image":"nginx:1.18","Names":"web","Ports":"0.0.0.0:8080->80/tcp"}\n'
                    )
                },
            },
            "errors": [],
        }

        assets = server_inventory.build_server_assets(inventory)

        self.assertEqual(assets["distro"]["id"], "ubuntu")
        self.assertEqual(len(assets["packages"]), 2)
        self.assertEqual(assets["kernel"]["asset_type"], "kernel_package")
        self.assertEqual(assets["ports"][0]["port"], 443)
        self.assertTrue(assets["docker"]["containers"][0]["explicit_old_tag"])
        self.assertEqual(assets["errors"], [])

    def test_build_server_assets_records_unsupported_distro_error(self):
        inventory = {
            "target": "root@example.test",
            "outputs": {
                "os_release": {
                    "stdout": 'ID=anolis\nVERSION_ID=8.9\nID_LIKE="rhel fedora"\n'
                }
            },
            "errors": [],
        }

        assets = server_inventory.build_server_assets(inventory)

        self.assertFalse(assets["distro"]["supported"])
        self.assertEqual(assets["packages"], [])
        self.assertTrue(
            any(item.get("code") == "unsupported_distro" for item in assets["errors"])
        )

    def test_build_server_assets_records_missing_package_output_error(self):
        inventory = {
            "target": "root@example.test",
            "outputs": {"os_release": {"stdout": "ID=ubuntu\nVERSION_ID=24.04\n"}},
            "errors": [],
        }

        assets = server_inventory.build_server_assets(inventory)

        self.assertEqual(assets["packages"], [])
        self.assertTrue(
            any(
                item.get("code") == "empty_package_inventory"
                for item in assets["errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()
