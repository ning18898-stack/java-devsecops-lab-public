# Phase 4 本地检测编排

固定 Windows Python 3.11.9，编排代码仅使用标准库。复用 `scripts/verify-phase3.py` 中快照内现有的的 Semgrep / CodeQL 检测、查询测试、源码提取完整性和原应用回归逻辑，不重写检测规则。Semgrep CE 1.180.0、CodeQL 2.27.2、项目 Temurin 17.0.20.1+1、原有传递包 lock 保持不变。仅限当前项目的 CodeQL 教学演示授权，不扩展至私有生产仓库或 CI。

```powershell
python automation/setup_zap.py
python automation/scan.py preflight
python automation/scan.py boundary
python automation/scan.py --dry-run
python automation/scan.py --tool semgrep
python automation/scan.py --tool codeql
python automation/scan.py --tool zap
python automation/scan.py
python automation/scan.py --resume <run_id> --correlate-with <run_id>
python -m unittest discover -s automation/tests -v
python automation/verify_phase4.py
```


唯一目标标识为 `vulnerable-baseline`，没有任意 URL 或任意命令参数入口。ZAP 默认运行 Automation Framework 的 `passiveScan-config → requestor → passiveScan-wait → report`。它是固定请求集的 Baseline 被动扫描：5 个 GET、无 spider、无主动扫描、无登录或数据写入。路径、预算和排除项在 [扫描计划](../scanners/zap/plans/passive.json)。Docker 网络、应用身份及转发限制见 [ZAP 说明](../scanners/zap/README.md)。SQLi 和 IDOR 位于认证及 opt-in 实验入口，不宣称被动扫描能检出它们。

每次产生新的 `artifacts/phase4/<UTC时间-UUID>/`；report.json 是 [v1 JSON Schema](report.schema.json) 的机器报告。每一步独立记录 execution_status、execution_mode、finding_count、起止时间、实际命令退出码与证据；失败/未执行的 finding_count 是 null。整次状态为 COMPLETED / PARTIAL / FAILED / INTERRUPTED / NOT_EXECUTED；完成且零发现是有效结果。命令行真实失败退出 1；dry-run 验证成功退出 0，但 report 明确 NOT_EXECUTED。ZAP 的工具退出码另见 zap-execution.json，告警数量不会决定执行成功。

日志每次写新文件，失败历史写 events.jsonl。命令最多两次额外重试（默认一次），单命令最多 3600 秒，ZAP 最多 300 秒且范围/身份失败不盲目重试；健康启动最多 45 次有限轮询。超时终止本次子进程树；捕获中断后保留状态并清理本次容器。硬终止进程或 Docker 引擎崩溃可能遗留带本次 run_id 标签的临时容器/内部网络，须人工检查并定向清理；恢复不会认领其他容器。

完成每个工具后发布不可覆盖的 checkpoint-NNN.json。`--resume` 在无最终 report 时读取最后 checkpoint；有 report 时使用最终报告。它重新校验源码/配置指纹、工具版本、所有证据 SHA-256、报告结构、原始结果解析和观察项数量。每次恢复生成新的 run_id，静态完成项标记 historical-reuse，动态任务重新建立并验证目标；原运行不被覆盖。配置或工具版本改变、dry-run、证据损坏不能复用。CodeQL 历史数据库以封存 runner 的源码/工具/构建指纹核对、逐文件 SHA-256 留存，并复制成私有快照后执行本次真实查询；不把数据库复用记为历史结果复用。

fingerprint 使用工具、规则、逻辑应用源码位置或逻辑目标 URL，不含 run_id、时间及临时容器 IP。仅合并同一工具/规则/位置的重复观察项，保留 occurrences 和全部证据引用。跨次通过 `--correlate-with` 标记 previously-observed；未出现不自动解释为已修复。不同工具观察项仍分开保留，independent_vulnerability_count 始终 null。风险与置信度来自工具原始元数据：无法得到时给 null 和原因；CodeQL precision 保留为工具精度，不宣称等同实测概率。

原 JSON/SARIF 保留工具结构，敏感值明确替换为 `[REDACTED]`；日志先在临时句柄捕获，再脱敏保存。H2 专用随机口令仅通过环境变量注入。网关不转发 Cookie/Authorization、不保存完整响应体、审计仅记录固定路径/方法/状态。报告默认 finding_status=unreviewed，不能把工具告警自动当作真实漏洞；原始证据仅在忽略目录保留，公开前仍需审查。

全量验收包含原文件/五个标签一致性、单元与异常恢复测试、实际内部网关边界探测、dry-run、两种静态工具真实扫描、ZAP 真实被动扫描、恢复后再次 ZAP、历史不变/关联、两套原应用 clean package 和既有真实隔离 MySQL 测试、脱敏及 Git 差异检查。只输出机器报告及 CLI 摘要，不提供 Dashboard、CI、push 或主动扫描。将来主动模式需要单独授权和新的目标/请求策略，当前 CLI 不暴露此模式。
