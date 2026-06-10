# server_match.py 技术文档

> 源码路径：`butian/scripts/server_match.py`

## 概览

`server_match.py` 负责把 Linux 服务器系统包、可匹配的内核包和已关联包坐标的服务软件提交到官方漏洞源查询，并构造证据闭环的服务器风险项。

## 职责

| #   | 职责           | 说明                                                                                                |
| --- | -------------- | --------------------------------------------------------------------------------------------------- |
| 1   | 可查询资产筛选 | 只查询带有 OSV 支持的发行版 ecosystem、包名和版本的系统包或已匹配内核包                             |
| 2   | OSV 批量查询   | 复用 `scan.py` 的 `fetch_osv_querybatch` 获取漏洞 ID，再通过 `fetch_osv_vulnerability` 获取完整公告 |
| 3   | 漏洞富化       | 使用 NVD、CISA KEV、FIRST EPSS 对完整公告中的已确认 CVE 做补充信息，并把 `cve_enrichments` 保留到服务器风险项 |
| 4   | 低证据过滤     | 仅 `confidence=confirmed` 的结果进入报告风险项                                                      |

## 查询范围

- 当前漏洞匹配只对 OSV 可稳定识别的 `Ubuntu:*`、`Debian:*`、`Alpine:*` 发行版包坐标发起查询。
- Debian/Ubuntu 二进制包如果带 `source_name`，优先使用 source package 查询，例如 `libssl3t64` 使用 `openssl`，内核安装包使用 `linux`，报告仍保留实际安装包名。
- RHEL、Rocky、AlmaLinux、CentOS Stream、Amazon Linux、SUSE、Oracle Linux 等主流 Linux 发行版可以采集资产和输出覆盖说明；如 OSV 不支持对应 ecosystem，不会发起模糊查询，也不会把结果解释成没有漏洞。

## 输出口径

NVD/CPE、服务版本或自编译二进制线索不能单独生成服务器风险项；API 失败或 ecosystem 不支持进入 `errors`，不能解释成没有漏洞。
