# server_collect.py 技术文档

> 源码路径：`butian/scripts/server_collect.py`

## 概览

`server_collect.py` 负责通过只读 SSH 命令采集 Linux 服务器 inventory，或读取已有的离线 `server-inventory.json`。它不安装 agent，不复制二进制，不升级软件，不重启服务，也不使用 `sudo`。

## 职责

| #   | 职责          | 说明                                                                      |
| --- | ------------- | ------------------------------------------------------------------------- |
| 1   | 命令白名单    | 只运行查询类命令，例如 `/etc/os-release`、`uname`、包管理器清单、监听端口、OpenSSH 配置和防火墙状态 |
| 2   | Docker 元数据 | 仅在显式开启时采集 `docker version` 和 `docker ps` 元数据                 |
| 3   | 错误保留      | 单条命令失败时记录到 `errors`，不把失败解释为没有风险                     |
| 4   | 离线输入      | 支持读取已有 inventory，便于复现和测试                                    |

## 安全边界

- 不执行安装、升级、重启或写入服务器文件的命令。
- OpenSSH 只读取 `sshd -T` 或可读配置中的关键登录项，不修改 `sshd_config`，不重启 sshd。
- 防火墙只读取 `ufw`、`firewalld`、`nftables`、`iptables`、`ip6tables` 状态或规则摘要，不创建、删除或修改规则。
- Docker 只采集宿主机可见的容器名、镜像标签和端口映射。
- 不进入容器，不读取容器文件系统，不扫描镜像 layers。
