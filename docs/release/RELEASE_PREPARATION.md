# 独立公开候选的本地准备

本页记录首次本地导出时的状态。公开仓库已按后续授权建立；后续托管验收和产物修复说明见 [HOSTED_VALIDATION.md](HOSTED_VALIDATION.md)。

原开发仓库保持私有；本候选是重新审核的源码导出，使用独立 Git 历史，不是 Fork，不携带原提交、历史标签或私有验收记录。新提交的 author/committer 使用维护者在 GitHub 设置截图中提供的实际 noreply 和 GitHub 用户名。

原七个历史标签被同一份完整 source-manifest.json 替代。CI、阶段保护和 hygiene 检查文件集合及规范 LF 的 SHA-256；snapshot 逐文件复制并 git init，任何分支都不克隆历史。Dashboard 演示片段引用由应用源码重新生成的独立 Git tree，新克隆也可生成该 tree，无需推送自定义 ref。它不是原始开发提交。

新 CI 的各 job 统一检出 PR 提交的 head，避免 GitHub 临时 merge commit 引入不同身份；push 时仍验收实际推送的 SHA。工作流保留最小权限、固定 Action SHA 和 CodeQL 人工许可门禁。新公开远端及其托管运行尚未创建/执行。

已实际运行的结果见 local-validation.json：Java quick/真实 MySQL 各81/41，Python83，FastAPI51，Vue7/build，Semgrep2/0，CodeQL3/0及查询测试，隔离ZAP5GET/0告警，Dashboard17HTTP/重启/3Edge。另在无历史工作副本安装新后端依赖并运行完整51项测试和文件保护。宿主JDK/Node/Python、扫描工具和下载缓存明确复用；源码构建、数据库、Python venv、node_modules及本次证据重新生成。

失败未删除：运维日志拒绝测试的占位文件扩展名、现有输入保护测试的 Git 前置操作，以及 Windows Git 长路径源码读取。保留断言后分别恢复生成的运维占位、延迟生成源码 tree、直接使用 cat-file blob 读取已验证仓库内对象，均重跑通过。

所有发布文件、Git 对象与配置经过隐私检查；合成实验邮箱、拒绝测试的假路径、第三方 npm 归属邮箱和已核实的 GitHub noreply 是有说明的保留值。公开截图来自本候选实际 Edge 测试，已视觉检查及文本/EXIF元数据检查；不包括账户设置截图。演示界面明确标注脱敏 fixture，替换的时间不是开发历史或新扫描证据。

自有内容已获维护者确认使用 Apache-2.0，LICENSE 为官方完整正文，NOTICE 保留项目署名和第三方说明。当前仅交付源码和脱敏示例；JAR、工具、数据库/镜像、Cookie、Session、原始日志和运行数据库不进入源码归档。未发现新的素材权属争议；若未来分发二进制须另审第三方义务。

后续须单独授权创建空的独立公开仓库和推送本候选 main，禁止 Fork 或推送原仓库历史。创建时不要由网页生成 README/LICENSE/gitignore。维护者账户的邮箱隐私开关在核实截图中为 Off，网页创建提交前应开启邮箱隐私，防止后续网页提交使用个人邮箱。此提示不改变账户设置或原仓库。

公开且正确识别 Apache-2.0 后，再由维护者审核设置 CODEQL_LICENSE_BASIS=open-source、手动运行托管 CodeQL 并保存对应SHA的实际证据。完整托管 Gate 前 PHASE6_READY=false；最终标签需要另行授权。当前 PUBLIC_RELEASE_CANDIDATE_READY 只代表本地公开候选准备。
