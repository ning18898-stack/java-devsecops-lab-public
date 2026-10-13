# Public snapshot CI

三份工作流保持固定 Action SHA、contents:read、超时和脱敏白名单。
常规 CI 含 Java quick/真实 MySQL、两平台 Python、Windows FastAPI、Vue、Semgrep、文件清单和 actionlint。
隔离 ZAP 只手动运行，内部网络、自建目标、五条授权 GET，无主动扫描、爬虫或宿主端口。
CodeQL 仅 workflow_dispatch；公开仓库并具有覆盖源码/查询的 OSI 许可后，所有者审核并设置 CODEQL_LICENSE_BASIS=open-source。
首次本地准备时尚无公开远程或托管 PASS；后续公开托管状态见 [托管验收](../release/HOSTED_VALIDATION.md)，不得将本地演示许可推定为未开源私有 CI 许可。
工作流不要求任何原始历史标签。源文件由独立 source-manifest.json 保护。
