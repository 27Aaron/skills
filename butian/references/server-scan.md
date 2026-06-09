# 服务器的安全扫描

服务器扫描是项目扫描之外的可选能力，用于检查已提供 SSH 目标或离线 inventory 的 Linux 运行环境。

`--server-only` 只生成 Markdown 报告，不生成 HTML 展示页；项目 + 服务器混合扫描仍会生成项目 HTML，并在“服务器运行环境”章节展示服务器内容。OpenSSH 和防火墙相关结论默认作为“服务器维护建议”，用于告诉用户如何优化，不写成 confirmed CVE。

## 服务器扫描入口

服务器直连必须使用密钥登录，脚本会给 `ssh` 加上 `BatchMode=yes`、`PasswordAuthentication=no`、`KbdInteractiveAuthentication=no` 和 `PreferredAuthentications=publickey`，避免密码输入或交互式认证回退。

推荐做法是先准备 `~/.ssh/config`，把服务器地址、用户、端口和私钥路径放在本机 SSH 配置里：

```sshconfig
Host prod-web
  HostName 203.0.113.10
  User deploy
  Port 22
  IdentityFile ~/.ssh/prod-web_ed25519
  IdentitiesOnly yes
  PreferredAuthentications publickey
  PasswordAuthentication no
  PubkeyAuthentication yes
  BatchMode yes
```

验证密钥登录可用：

```bash
ssh prod-web
```

然后运行扫描。`<ssh_target>` 可以是 SSH config Host 别名，例如 `prod-web`；也可以是 `user@203.0.113.10` 这种直接 SSH 目标。`<project_path>` 是本次关联的项目目录，在项目根目录执行时可以省略。

```bash
# macOS / Linux
python3 scripts/run_audit.py --server <ssh_target> <project_path>
python3 scripts/run_audit.py --server-only --server <ssh_target> <project_path>
python3 scripts/run_audit.py --server prod-web --ssh-config ~/.ssh/config <project_path>
python3 scripts/run_audit.py --server user@203.0.113.10 --ssh-port 2222 --identity ~/.ssh/prod-web_ed25519 <project_path>
python3 scripts/run_audit.py --server-inventory <server_inventory_json> <project_path>

# Windows
py -3 scripts/run_audit.py --server <ssh_target> <project_path>
py -3 scripts/run_audit.py --server-only --server <ssh_target> <project_path>
py -3 scripts/run_audit.py --server prod-web --ssh-config %USERPROFILE%\.ssh\config <project_path>
py -3 scripts/run_audit.py --server user@203.0.113.10 --ssh-port 2222 --identity %USERPROFILE%\.ssh\prod-web_ed25519 <project_path>
py -3 scripts/run_audit.py --server-inventory <server_inventory_json> <project_path>
```

`--server-only` 必须搭配 `--server` 或 `--server-inventory`。没有服务器来源时不能启动服务器单独扫描。

Windows 上也可以运行服务器扫描；使用 `--server` 时本机需要可用的 OpenSSH `ssh` 命令。没有 SSH 客户端、跳板机策略较复杂或只想复现报告时，使用 `--server-inventory` 读取离线 inventory。

`--identity` 是可选项，只用于把私钥路径传给本机 `ssh`，写入报告前会脱敏；如果密钥已经通过 SSH config、默认私钥或 SSH 密钥代理生效，可以不传。

## 只读边界

服务器采集只使用白名单内的只读 SSH 命令。它不安装采集程序，不复制二进制，不使用 `sudo`，不升级软件，不重启服务，不修改服务器文件，不读取业务数据库，不读取应用日志。

允许采集的信息包括：

- Linux 发行版信息，例如 `/etc/os-release`
- 当前运行内核版本
- 系统包清单
- 包管理器返回的安全更新线索，例如 apt/dnf/yum/zypper
- 重点运行服务和监听端口
- 正在运行的 systemd service 摘要
- 常见软件版本命令输出，例如 Nginx、OpenSSL、OpenSSH、Docker daemon
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

服务器风险项必须有证据闭环。只有发行版包坐标、可关联的内核包坐标和版本能匹配官方漏洞源时，才进入服务器风险项。包管理器返回的安全更新线索会作为维护建议保留，帮助用户安排系统更新和复扫。

这些低证据线索不能单独进入风险项：

- 仅 NVD/CPE 模糊匹配
- 服务版本 banner 推断
- 自编译二进制版本推断
- Docker `latest`、`custom` 或无法解析的镜像标签
- OpenSSH 配置建议
- 防火墙配置建议

常见软件版本如果能关联到发行版包，会随包坐标进入漏洞查询；如果只能从 `nginx -v`、`openssl version`、`ssh -V` 或 `docker version` 看到版本，但无法关联包管理器坐标，只能作为维护建议或扫描错误保留，不能写成已确认漏洞。

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
- 当前内核包匹配状态
- 常见软件版本和包坐标关联状态
- 包管理器安全更新线索
- 正在运行的服务数量
- 已确认服务器风险数量
- 服务器维护建议数量
- 对外监听端口
- OpenSSH 和防火墙建议的证据与处理方向
- 扫描错误和采集缺口

`--server-only` 不生成 HTML 报告。终端和 Markdown 中必须清楚标注 Markdown 路径、analysis JSON 路径，以及服务器 assets 路径。项目 + 服务器混合扫描可以生成项目 HTML，服务器内容只放在独立的“服务器运行环境”章节。

## 与项目扫描的关系

默认项目扫描不会扫描操作系统包或系统服务。服务器扫描和项目扫描都属于安全相关内容，但触发条件、数据来源和证据标准不同：项目扫描查仓库和应用依赖；服务器扫描查已提供的 Linux 运行环境。

项目 + 服务器同时扫描时，应用依赖和仓库安检仍按项目规则输出；服务器内容只在“服务器运行环境”中单独展示。`--server-only` 时只做服务器运行环境扫描，并只生成 Markdown 报告。
