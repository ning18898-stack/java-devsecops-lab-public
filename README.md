# Java DevSecOps Lab — public source snapshot

本项目是从非公开开发工作区重新审核导出的独立源码快照，使用独立 Git 历史。
不携带原始提交、历史标签、身份信息、私有 CI 链接或原始运维证据；阶段编号仅说明教学模块，不能视为原始开发历史。

功能：Spring Boot/MyBatis/MySQL 安全基线、受控 SQLi/IDOR 及修复对照；Semgrep/CodeQL；隔离被动 ZAP；Python 编排；FastAPI/Vue/SQLite Dashboard。
主动验证仅针对本快照自建的本地 vulnerable-app。所有实验数据合成，默认回环访问，禁止公网扫描。

- [使用与验证](docs/delivery/README.md)
- [独立快照与文件完整性](docs/release/PROVENANCE.md)
- [CI 与 CodeQL 许可](docs/ci/README.md)
- [第三方许可审查](docs/release/THIRD_PARTY.md)

公开候选与托管最终验收是不同状态。此快照未创建远程仓库、未 push，PHASE6_READY=false。
自有内容采用 Apache-2.0（见 LICENSE/NOTICE）；第三方内容保留上游条款。新提交只使用已核实的 GitHub 用户名/noreply。
