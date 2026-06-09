# server_collect.py 技术文档

> 源码路径：`butian/scripts/server_collect.py`

## 概览

`server_collect.py` 负责通过只读 SSH 命令采集 Linux 服务器 inventory，或读取已有的离线 `server-inventory.json`。SSH 采集可以使用本机 `.ssh/config` Host 别名，也可以直接传 `user@ip`；两种方式都必须使用密钥登录，脚本会禁用密码和键盘交互回退。它不安装采集程序，不复制二进制，不升级软件，不重启服务，也不使用 `sudo`。

macOS、Linux 和 Windows 都可以运行采集脚本；使用 SSH 采集时本机需要可用的 `ssh` 命令，并先用 `ssh <target>` 验证密钥登录。没有 SSH 客户端时，可以改用离线 inventory 流程。

## 职责

| #   | 职责          | 说明                                                                      |
| --- | ------------- | ------------------------------------------------------------------------- |
| 1   | 命令白名单    | 只运行查询类命令，例如 `/etc/os-release`、`uname`、包管理器清单、安全更新线索、常见软件版本、监听端口、OpenSSH 配置和防火墙状态 |
| 2   | 常见组件版本  | 轻量读取 Web、数据库、容器、语言运行时、消息队列、代理网关、运维工具和面板组件版本 |
| 3   | 错误保留      | 单条命令失败时记录到 `errors`，不把失败解释为没有风险                     |
| 4   | SSH 参数      | 支持 SSH config、端口和私钥路径透传，但始终禁用密码与键盘交互认证           |
| 5   | 离线输入      | 支持读取已有 inventory，便于复现和测试                                    |

## 安全边界

- 不执行安装、升级、重启或写入服务器文件的命令。
- `--server` 可以是 SSH config Host 别名或 `user@ip`；目标不能为空，不能以 `-` 开头，也不能包含空白、路径或通配符。
- `IdentityFile` 可以来自 SSH config，也可以通过 `--identity` 传给本机 `ssh`。
- 采集产物写入前会脱敏 IdentityFile / `--identity` 路径，避免报告暴露本地私钥材料位置。
- OpenSSH 只读取 `sshd -T` 或可读配置中的关键登录项，不修改 `sshd_config`，不重启 sshd。
- 防火墙只读取 `ufw`、`firewalld`、`nftables`、`iptables`、`ip6tables` 状态或规则摘要，不创建、删除或修改规则。
- Docker 版本默认采集；容器名、镜像标签和端口映射只在显式开启 Docker 元数据时采集。
- 不进入容器，不读取容器文件系统，不扫描镜像 layers。
