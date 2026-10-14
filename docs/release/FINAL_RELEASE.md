# Phase 6 final release

维护者已授权正式封存独立公开版本。原开发仓库继续私有；不改写原历史、不修改或导入其七个历史标签。公开版本的源码树、文件清单和新 Git 历史都独立生成。

## 最终验收条件

1. 公开 main 与本地审核工作副本为同一提交，工作区干净。
2. 常规 CI、Licensed custom CodeQL、Isolated passive ZAP 在该提交上全部成功；下载并复核实际结果、退出码和发布产物。
3. Apache-2.0 覆盖自有源码/查询，第三方通知保留；CodeQL 仅在官方开源许可依据成立时运行。
4. 文件清单、Git 提交/标签身份和公开产物隐私检查通过；不发布账户设置截图、个人邮箱、宿主路径、凭据或原始运维记录。
5. 状态文档发生变化后，必须提交并对新 SHA 重新执行三项远程验收。

条件全部满足后才能设置 `PHASE6_READY=true`，在已验收提交上创建 annotated tag `phase6-final-release`。Tagger 与提交身份均使用已核实的维护者 GitHub 用户名和实际 noreply。正式封存阶段只推送该标签，不推送原历史、其他分支或多余引用。

## 正式记录与可复现证据

[GitHub Release](https://github.com/ning18898-stack/java-devsecops-lab-public/releases/tag/phase6-final-release) 是正式发布入口，保存以下附件：

- `phase6-final-acceptance.json`：最终提交、PHASE6_READY、三项工作流 URL/实际退出码、许可和隐私结果，以及源码/证据 SHA256。
- `phase6-final-evidence.zip`：本提交三项工作流的脱敏 result.json、JUnit XML、Semgrep JSON、CodeQL SARIF 和 ZAP JSON，附逐文件 hash；不含原日志、数据库或工具。
- 独立源码包及 `SHA256SUMS`：只包含审核文件，不含 `.git`、原始提交/标签、运行数据或构建产物。

机器验收记录在本提交通过后生成并随 Release 保存，避免为写入自身提交 SHA 再次改变已验收源码。仓库内 `local-validation.json` 和首次准备文档是历史本地证据，其 `PHASE6_READY=false` 不代表正式 Release 的完成状态。

CodeQL SARIF 是自定义查询的验收产物；本工作流不宣称已导入 GitHub Security 告警页。漏洞版的预期教学结果与修复版结果须分列。ZAP 仅请求自建内部隔离目标，无主动扫描或爬虫。Dashboard GUI/HTTP 的本地验证须声明实际来源，不冒充托管执行。

自有内容采用 Apache-2.0；第三方依赖按原条款保留。JAR、工具或镜像的再分发不属于本次源码 Release。[CodeQL 官方许可条款](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
