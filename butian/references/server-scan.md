# Linux 服务器扫描参考

服务器扫描是项目扫描之外的可选能力。只有用户明确要求检查 Linux 服务器运行环境，并提供 SSH 目标或离线 inventory 时才启用。

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
- 可选 Docker 元数据：容器名、镜像标签、端口映射

Docker 只读取宿主机可见元数据，不进入容器、不读取容器文件系统、不扫描镜像 layer。

## 漏洞进入报告的条件

服务器风险项必须有证据闭环。只有发行版包坐标和版本能匹配官方漏洞源时，才进入服务器风险项。

这些低证据线索不能单独进入风险项：

- 仅 NVD/CPE 模糊匹配
- 服务版本 banner 推断
- 自编译二进制版本推断
- Docker `latest`、`custom` 或无法解析的镜像标签

低证据线索只能作为维护建议或扫描错误保留，不能写成已确认漏洞。

## 产物

启用服务器扫描时，assets 目录会写出：

- `server-inventory.json`
- `server-assets.json`
- `server-vulns.json`
- `server-analysis.json`

最终 `analysis.json` 会合并 `server`、`server_issues`、`server_maintenance` 和 `server_issue_count`，报告中单独展示“服务器运行环境”。

## 与项目扫描的关系

默认项目扫描不会扫描操作系统包或系统服务。服务器扫描和项目扫描都属于安全相关内容，但触发条件、数据来源和证据标准不同：项目扫描查仓库和应用依赖；服务器扫描查用户明确提供的 Linux 运行环境。

