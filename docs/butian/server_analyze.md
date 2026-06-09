# server_analyze.py 技术文档

> 源码路径：`butian/scripts/server_analyze.py`

## 概览

`server_analyze.py` 将服务器漏洞匹配结果和运行态元数据合并为报告可消费的 `server` analysis。

## 职责

| # | 职责 | 说明 |
| --- | --- | --- |
| 1 | 已确认风险 | 保留 `server_match.py` 输出的 `confirmed_issues` |
| 2 | 维护建议 | 将明确旧 Docker 镜像标签和公开敏感服务端口转为 `maintenance_items` |
| 3 | 错误合并 | 合并采集、资产解析和漏洞源查询错误 |
| 4 | 摘要统计 | 输出系统包数量、已确认风险数量、维护建议数量、公开端口数量 |

## 报告边界

维护建议不等同于已确认 CVE。Docker `latest`、custom image、无法解析版本标签和服务版本推断不会进入服务器风险项。

