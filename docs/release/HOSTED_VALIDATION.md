# 公开仓库托管验收

公开仓库是独立源码导出，只有新的维护者 noreply 提交；不携带私有开发仓库历史或标签。

实际托管结果以各工作流的提交 SHA、Job、result.json 的实际退出码及扫描产物为准：

- [常规 CI](https://github.com/ning18898-stack/java-devsecops-lab-public/actions/workflows/ci.yml)
- [许可门禁与自定义 CodeQL](https://github.com/ning18898-stack/java-devsecops-lab-public/actions/workflows/codeql-licensed.yml)
- [隔离被动 ZAP](https://github.com/ning18898-stack/java-devsecops-lab-public/actions/workflows/zap-local.yml)

Apache-2.0 已由 GitHub 识别。在公开托管、维护且许可证覆盖源码和查询后，维护者核验设置 CODEQL_LICENSE_BASIS=open-source；私有开发仓库不使用此许可门禁。[官方 CodeQL 条款](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)

首次公开初始快照的常规 CI 7/7、隔离 ZAP 和 CodeQL 工作流均成功。下载复核发现 CodeQL 公开 result.json 中 Windows 引号转义被文本脱敏破坏；两份 SARIF 可解析，但该轮产物完整性验收不通过。修复为先解析 JSON/XML、脱敏值、再序列化，并新增 Windows 引号、嵌套值、XML 转义及运行属性排除回归。修复后的提交须重新实际验收，不能沿用首次绿色工作流作为证明。

首次结构化修复的 Java 测试全部通过，但 XML 发布失败：属性名的命名空间结构被改写，且旧路径表达式误匹配 HTTP(S) 地址。后续修复保留 XML 属性名，并限制 Windows 盘符匹配边界；回归要求真实 JUnit 命名空间、HTTP(S) schema URI 和带引号的 Windows 命令均保持可解析。失败工作流及产物保留，最终提交必须重新验收。

local-validation.json 与 RELEASE_PREPARATION.md 记录首次本地候选准备，不代表后续提交的托管 PASS。托管工作流上传脱敏 result/XML/SARIF 白名单，原日志、数据库和工具保持不公开；CodeQL SARIF 作为验收产物保存，本工作流没有导入 GitHub Security 告警页。

完整托管验收与最终发布封存是独立步骤；此处不设置 PHASE6_READY=true 或创建最终发布标签。
