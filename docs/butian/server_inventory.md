# server_inventory.py 技术文档

> 源码路径：`butian/scripts/server_inventory.py`

## 概览

`server_inventory.py` 将 `server_collect.py` 采集到的原始输出标准化为服务器资产。v1 inventory 使用顶层 `commands` 保存原始命令结果；解析器仍兼容旧版 `outputs` 字段，便于读取早期离线样本。默认资产范围包括 Linux 发行版、系统包、当前内核、常见软件版本、包管理器安全更新线索、运行中的 systemd service、监听端口、OpenSSH 登录配置和防火墙状态。

常见软件版本覆盖 Web 服务、远程访问、TLS/加密库、数据库、语言运行时、消息队列、反向代理/网关、运维工具和 CI/面板类组件。能安全执行轻量版本命令的组件会解析命令输出；Jenkins、GitLab、Nexus、Harbor、NSS、sudo 等不适合跑重管理命令的组件优先从系统包清单识别。

## 职责

| #   | 职责         | 说明                                                             |
| --- | ------------ | ---------------------------------------------------------------- |
| 1   | 发行版识别   | 解析 `/etc/os-release`，只支持明确列入矩阵的主流 Linux 发行版    |
| 2   | 系统包解析   | 解析 `dpkg-query`、`rpm -qa`、`apk info -vv` 输出                |
| 3   | 内核资产     | 将 `uname -r` 关联到包管理器中的内核包，关联失败时标记为不可查询 |
| 4   | 软件版本     | 解析常见服务器软件版本，并尽量关联发行版包坐标 |
| 5   | 安全更新     | 解析 apt/dnf/yum/zypper 返回的安全更新线索，作为维护建议输入     |
| 6   | 服务元数据   | 解析 `systemctl list-units` 中运行中的 `.service`                |
| 7   | 暴露面元数据 | 解析 `ss/netstat` 监听端口                                      |
| 8   | 登录与防火墙 | 解析 OpenSSH 关键配置和 ufw/firewalld/nftables/iptables 状态     |

## 证据规则

- `ID_LIKE=rhel` 或 `ID_LIKE=suse` 只能作为内部线索，不能自动放行未列入支持矩阵的发行版。
- 支持发行版但包清单为空时进入扫描错误，不能当作没有风险。
- 常见软件版本必须能关联到系统包坐标才可随包进入漏洞查询；仅有 banner 或命令输出时保留为覆盖缺口。
- 轻量命令覆盖 Nginx、Apache/httpd、Caddy、Tomcat、OpenSSL、GnuTLS、OpenSSH、MySQL、MariaDB、PostgreSQL、MongoDB、Redis、Elasticsearch、Node.js、Python、Java、PHP、Ruby、Go、RabbitMQ、Kafka、HAProxy、Envoy、Traefik、Git、curl、wget、cron、systemd、Grafana、Prometheus。
- 包清单兜底覆盖 libssl、NSS、sudo、Jenkins、GitLab、Nexus、Harbor 等常见组件。
- 包管理器安全更新线索进入 `native_security_updates`，不等同于已确认 CVE。
- `MaxAuthTries` 不进入资产输出；保持系统默认即可，避免把高级调优项误导成必须修复的问题。
- OpenSSH 和防火墙输出只作为维护建议证据，不进入已确认漏洞。
