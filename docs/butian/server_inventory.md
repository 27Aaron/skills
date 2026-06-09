# server_inventory.py 技术文档

> 源码路径：`butian/scripts/server_inventory.py`

## 概览

`server_inventory.py` 将 `server_collect.py` 采集到的原始输出标准化为服务器资产，包括 Linux 发行版、系统包、当前内核、监听端口和 Docker 容器元数据。

## 职责

| #   | 职责         | 说明                                                             |
| --- | ------------ | ---------------------------------------------------------------- |
| 1   | 发行版识别   | 解析 `/etc/os-release`，只支持明确列入矩阵的主流 Linux 发行版    |
| 2   | 系统包解析   | 解析 `dpkg-query`、`rpm -qa`、`apk info -vv` 输出                |
| 3   | 内核资产     | 将 `uname -r` 关联到包管理器中的内核包，关联失败时标记为不可查询 |
| 4   | 暴露面元数据 | 解析 `ss/netstat` 监听端口和 Docker `ps` JSON lines              |

## 证据规则

- `ID_LIKE=rhel` 或 `ID_LIKE=suse` 只能作为内部线索，不能自动放行未列入支持矩阵的发行版。
- 支持发行版但包清单为空时进入扫描错误，不能当作没有风险。
- Docker 旧标签只在镜像名和版本标签明确时作为维护建议线索。
