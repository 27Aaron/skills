import unittest
from unittest import mock

from butian.scripts import server_match


class ServerMatchTests(unittest.TestCase):
    def test_queryable_assets_include_system_packages_and_matched_kernel(self):
        assets = {
            "packages": [
                {
                    "asset_type": "system_package",
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "nginx",
                    "version": "1.24.0-2ubuntu7.3",
                    "package_type": "deb",
                }
            ],
            "kernel": {
                "asset_type": "kernel_package",
                "ecosystem": "Ubuntu:24.04:LTS",
                "name": "linux-image-6.8.0-53-generic",
                "version": "6.8.0-53.55",
                "queryable": True,
            },
        }

        queryable = server_match.queryable_assets(assets)

        self.assertEqual(
            [item["name"] for item in queryable],
            ["nginx", "linux-image-6.8.0-53-generic"],
        )

    def test_queryable_assets_use_source_package_when_available(self):
        assets = {
            "packages": [
                {
                    "asset_type": "system_package",
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "libssl3t64",
                    "source_name": "openssl",
                    "version": "3.0.13-0ubuntu3.5",
                    "package_type": "deb",
                }
            ],
            "kernel": {},
        }

        queryable = server_match.queryable_assets(assets)

        self.assertEqual(queryable[0]["name"], "openssl")
        self.assertEqual(queryable[0]["installed_name"], "libssl3t64")

    def test_queryable_assets_skip_unsupported_osv_ecosystem(self):
        assets = {
            "packages": [
                {
                    "asset_type": "system_package",
                    "ecosystem": "Rocky Linux:9",
                    "name": "nginx",
                    "version": "1.24.0-1.el9",
                    "package_type": "rpm",
                }
            ],
            "kernel": {},
        }

        self.assertEqual(server_match.queryable_assets(assets), [])

    def test_non_queryable_kernel_is_filtered(self):
        assets = {
            "packages": [],
            "kernel": {"name": "kernel", "version": "6.6.52", "queryable": False},
        }

        self.assertEqual(server_match.queryable_assets(assets), [])

    def test_osv_record_builds_confirmed_issue_and_nvd_enriches(self):
        asset = {
            "ecosystem": "Ubuntu:24.04:LTS",
            "name": "nginx",
            "version": "1.24.0-2ubuntu7.3",
            "package_type": "deb",
            "asset_type": "system_package",
        }
        osv_record = {
            "id": "UBUNTU-CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "summary": "nginx issue",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "nginx"}}
            ],
        }

        issue = server_match.build_confirmed_issue(
            asset,
            osv_record,
            {"CVE-2026-0001": [{"cvssScore": 8.2, "cwes": ["CWE-400"], "source": "nvd"}]},
        )

        self.assertEqual(issue["scope"], "server")
        self.assertEqual(issue["confidence"], "confirmed")
        self.assertEqual(issue["package"], "nginx")
        self.assertIn("CVE-2026-0001", issue["aliases"])
        self.assertEqual(issue["severity"], "high")
        self.assertEqual(issue["cwe"], ["CWE-400"])
        self.assertIn("发行版包坐标", issue["summary"])

    def test_cpe_only_candidate_is_not_reported(self):
        result = server_match.filter_reportable_issues(
            [
                {"confidence": "cpe_only", "package": "nginx"},
                {"confidence": "confirmed", "package": "openssl"},
            ]
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["package"], "openssl")


class ServerBatchQueryTests(unittest.TestCase):
    def test_match_server_vulnerabilities_reuses_scan_fetchers(self):
        assets = {
            "packages": [
                {
                    "asset_type": "system_package",
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "nginx",
                    "version": "1.24.0-2ubuntu7.3",
                    "package_type": "deb",
                }
            ],
            "kernel": {},
        }
        osv_response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "UBUNTU-CVE-2026-0001",
                        }
                    ]
                }
            ]
        }
        osv_detail = {
            "id": "UBUNTU-CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "summary": "nginx issue from detail",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "nginx"}}
            ],
        }
        fetch_osv = mock.Mock(return_value=osv_response)

        with (
            mock.patch.object(server_match.scan, "fetch_osv_querybatch", fetch_osv),
            mock.patch.object(
                server_match.scan,
                "fetch_osv_vulnerability",
                return_value=osv_detail,
            ) as fetch_detail,
            mock.patch.object(
                server_match.scan,
                "fetch_nvd_enrichments",
                return_value={"CVE-2026-0001": [{"cvssScore": 8.2}]},
            ) as fetch_nvd,
            mock.patch.object(
                server_match.scan,
                "fetch_cisa_kev_enrichments",
                return_value={},
            ) as fetch_kev,
            mock.patch.object(
                server_match.scan,
                "fetch_epss_enrichments",
                return_value={},
            ) as fetch_epss,
        ):
            result = server_match.match_server_vulnerabilities(
                assets, project_path="/tmp/demo"
            )

        fetch_osv.assert_called_once_with(assets["packages"])
        fetch_detail.assert_called_once_with("UBUNTU-CVE-2026-0001")
        fetch_nvd.assert_called_once_with(["CVE-2026-0001"], [])
        fetch_kev.assert_called_once_with(["CVE-2026-0001"], [], "/tmp/demo")
        fetch_epss.assert_called_once_with(["CVE-2026-0001"], [])
        self.assertEqual(len(result["confirmed_issues"]), 1)
        self.assertEqual(result["confirmed_issues"][0]["package"], "nginx")
        self.assertEqual(
            result["confirmed_issues"][0]["advisory_summary"],
            "nginx issue from detail",
        )
        self.assertEqual(result["errors"], [])

    def test_match_server_vulnerabilities_reports_source_package_match(self):
        assets = {
            "packages": [
                {
                    "asset_type": "system_package",
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "libssl3t64",
                    "source_name": "openssl",
                    "version": "3.0.13-0ubuntu3.5",
                    "package_type": "deb",
                }
            ],
            "kernel": {},
        }
        osv_response = {"results": [{"vulns": [{"id": "UBUNTU-CVE-2026-0002"}]}]}
        osv_detail = {
            "id": "UBUNTU-CVE-2026-0002",
            "aliases": ["CVE-2026-0002"],
            "summary": "openssl issue",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"}}
            ],
        }

        with (
            mock.patch.object(
                server_match.scan,
                "fetch_osv_querybatch",
                return_value=osv_response,
            ) as fetch_osv,
            mock.patch.object(
                server_match.scan,
                "fetch_osv_vulnerability",
                return_value=osv_detail,
            ),
            mock.patch.object(
                server_match.scan,
                "fetch_nvd_enrichments",
                return_value={"CVE-2026-0002": [{"cvssScore": 7.1}]},
            ),
            mock.patch.object(server_match.scan, "fetch_cisa_kev_enrichments", return_value={}),
            mock.patch.object(server_match.scan, "fetch_epss_enrichments", return_value={}),
        ):
            result = server_match.match_server_vulnerabilities(
                assets, project_path="/tmp/demo"
            )

        query = fetch_osv.call_args.args[0][0]
        self.assertEqual(query["name"], "openssl")
        issue = result["confirmed_issues"][0]
        self.assertEqual(issue["package"], "libssl3t64")
        self.assertEqual(issue["source_package"], "openssl")
        self.assertIn("源包 openssl", issue["summary"])

    def test_empty_osv_result_stays_empty_and_skips_enrichment(self):
        assets = {
            "packages": [
                {
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "nginx",
                    "version": "1",
                    "package_type": "deb",
                }
            ],
            "kernel": {},
        }

        with (
            mock.patch.object(
                server_match.scan,
                "fetch_osv_querybatch",
                return_value={"results": [{}]},
            ),
            mock.patch.object(
                server_match.scan, "fetch_osv_vulnerability"
            ) as fetch_detail,
            mock.patch.object(server_match.scan, "fetch_nvd_enrichments") as fetch_nvd,
            mock.patch.object(
                server_match.scan, "fetch_cisa_kev_enrichments"
            ) as fetch_kev,
            mock.patch.object(server_match.scan, "fetch_epss_enrichments") as fetch_epss,
        ):
            result = server_match.match_server_vulnerabilities(
                assets, project_path="/tmp/demo"
            )

        self.assertEqual(result["confirmed_issues"], [])
        fetch_detail.assert_not_called()
        fetch_nvd.assert_not_called()
        fetch_kev.assert_not_called()
        fetch_epss.assert_not_called()

    def test_osv_query_errors_are_returned_not_silenced_as_no_risk(self):
        assets = {
            "packages": [
                {
                    "ecosystem": "Ubuntu:24.04:LTS",
                    "name": "openssl",
                    "version": "3.0.13",
                    "package_type": "deb",
                }
            ],
            "kernel": {},
        }

        with mock.patch.object(
            server_match.scan, "fetch_osv_querybatch", side_effect=RuntimeError("boom")
        ):
            result = server_match.match_server_vulnerabilities(
                assets, project_path="/tmp/demo"
            )

        self.assertEqual(result["confirmed_issues"], [])
        self.assertTrue(result["errors"])
        self.assertIn("服务器包批量查询", result["errors"][0]["message"])

    def test_unsupported_osv_ecosystem_is_reported_without_querying(self):
        assets = {
            "packages": [
                {
                    "ecosystem": "Amazon Linux:2023",
                    "name": "openssl",
                    "version": "3.0.8-1.amzn2023",
                    "package_type": "rpm",
                }
            ],
            "kernel": {},
        }

        with mock.patch.object(server_match.scan, "fetch_osv_querybatch") as fetch_osv:
            result = server_match.match_server_vulnerabilities(
                assets, project_path="/tmp/demo"
            )

        fetch_osv.assert_not_called()
        self.assertEqual(result["confirmed_issues"], [])
        self.assertEqual(result["asset_count"], 0)
        self.assertTrue(result["errors"])
        self.assertIn("暂不支持服务器 ecosystem Amazon Linux:2023", result["errors"][0]["message"])


if __name__ == "__main__":
    unittest.main()
