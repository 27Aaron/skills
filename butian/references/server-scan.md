# 服务器的安全扫描

服务器扫描是项目扫描之外的可选能力。只有用户明确要求检查 Linux 服务器运行环境，并提供 SSH 目标或离线 inventory 时才启用。

服务器扫描只生成 Markdown 报告，不生成 HTML 展示页。OpenSSH 和防火墙相关结论默认作为“服务器维护建议”，用于告诉用户如何优化，不写成 confirmed CVE。

## 启用方式

```bash
python3 scripts/run_audit.py --server user@example.com
python3 scripts/run_audit.py --server-only --server user@example.com
python3 scripts/run_audit.py --server-inventory server-inventory.json
```

`--server-only` 必须搭配 `--server` 或 `--server-inventory`。没有服务器来源时不能启动服务器单独扫描。

## 只读边界

服务器采集只使用白名单内的只读 SSH 命令。它不安装 agent，不复制二进制，不使用 `sudo`，不升级软件，不重启服务，不修改服务器文件，不读取业务数据库，不读取应用日志。

允许采集的信息包括：

- Linux 发行版信息，例如 `/etc/os-release`
- 当前运行内核版本
- 系统包清单
- 重点运行服务和监听端口
- OpenSSH 服务端有效配置
- 主机防火墙状态和可读规则摘要
- 可选 Docker 元数据：容器名、镜像标签、端口映射

Docker 只读取宿主机可见元数据，不进入容器、不读取容器文件系统、不扫描镜像 layer。

## OpenSSH 建议项

OpenSSH 配置检查只输出建议，不自动修改服务器。重点关注：

- `PasswordAuthentication`：如果允许密码登录，建议关闭密码登录，改用密钥登录，降低弱密码和爆破风险。
- `KbdInteractiveAuthentication`：如果仍允许交互式认证，需要确认是否依赖 PAM/二次验证；没有明确需求时建议关闭。
- `PubkeyAuthentication`：如果未启用公钥认证，建议启用密钥登录。
- `PermitRootLogin`：如果允许 root 直接登录，尤其是 root 密码登录，建议改为普通用户登录后提权。
- `PermitEmptyPasswords`：如果允许空密码登录，必须建议关闭。

`MaxAuthTries` 保持系统默认即可，不作为主要建议项，避免给小白用户造成“输错几次会永久连不上”的误解。

## 防火墙建议项

防火墙检查只读取状态和规则摘要，不创建、删除或修改规则。优先识别：

- `ufw`
- `firewalld`
- `nftables`
- `iptables`
- `ip6tables`

输出原则：

- 如果能确认主机防火墙启用并存在规则，报告只摘要展示，不建议无意义调整。
- 如果存在公网监听端口，但没有发现可确认的主机防火墙状态，建议用户确认云安全组、主机防火墙和服务访问控制。
- 如果 SSH 对公网监听且允许密码登录，建议关闭密码登录并使用密钥登录。
- 如果采集命令不可用或权限不足，写成“检查不完整”，不能当作安全。

## 漏洞进入报告的条件

服务器风险项必须有证据闭环。只有发行版包坐标和版本能匹配官方漏洞源时，才进入服务器风险项。

这些低证据线索不能单独进入风险项：

- 仅 NVD/CPE 模糊匹配
- 服务版本 banner 推断
- 自编译二进制版本推断
- Docker `latest`、`custom` 或无法解析的镜像标签
- OpenSSH 配置建议
- 防火墙配置建议

低证据线索只能作为维护建议或扫描错误保留，不能写成已确认漏洞。

## 服务器报告契约

启用服务器扫描时，assets 目录会写出：

- `server-inventory.json`
- `server-assets.json`
- `server-vulns.json`
- `server-analysis.json`

最终 `analysis.json` 会合并：

- `server`
- `server_issues`
- `server_maintenance`
- `server_issue_count`

`server_issues` 只允许放证据闭环的 `confirmed` 风险；OpenSSH、防火墙、公网敏感端口、旧 Docker 镜像标签等只进入 `server_maintenance`。报告中单独展示“服务器运行环境”，不要和项目依赖漏洞混成一种风险。

Markdown 报告必须说明：

- 系统包数量
- 已确认服务器风险数量
- 服务器维护建议数量
- 对外监听端口
- OpenSSH 和防火墙建议的证据与处理方向
- 扫描错误和采集缺口

服务器扫描不生成 HTML 报告。终端和 Markdown 中必须清楚标注 Markdown 路径、analysis JSON 路径，以及服务器 assets 路径。

## 与项目扫描的关系

默认项目扫描不会扫描操作系统包或系统服务。服务器扫描和项目扫描都属于安全相关内容，但触发条件、数据来源和证据标准不同：项目扫描查仓库和应用依赖；服务器扫描查用户明确提供的 Linux 运行环境。

项目 + 服务器同时扫描时，应用依赖和仓库安检仍按项目规则输出；服务器内容只在“服务器运行环境”中单独展示。`--server-only` 时只做服务器运行环境扫描，并只生成 Markdown 报告。
