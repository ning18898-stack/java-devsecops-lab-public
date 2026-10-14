# Java DevSecOps Lab — public source snapshot

本项目是从非公开开发工作区重新审核导出的独立源码快照，使用独立 Git 历史。
不携带原始提交、历史标签、身份信息、私有 CI 链接或原始运维证据；阶段编号仅说明教学模块，不能视为原始开发历史。

功能：Spring Boot/MyBatis/MySQL 安全基线、受控 SQLi/IDOR 及修复对照；Semgrep/CodeQL；隔离被动 ZAP；Python 编排；FastAPI/Vue/SQLite Dashboard。
主动验证仅针对本快照自建的本地 vulnerable-app。所有实验数据合成，默认回环访问，禁止公网扫描。

- [使用与验证](docs/delivery/README.md)
- [独立快照与文件完整性](docs/release/PROVENANCE.md)
- [CI 与 CodeQL 许可](docs/ci/README.md)
- [第三方许可审查](docs/release/THIRD_PARTY.md)
- [Phase 6 最终验收与正式发布](docs/release/FINAL_RELEASE.md)

独立公开仓库已建立并完成实际托管验收。任何后续完成状态文档提交也必须通过同一 SHA 的常规 CI、托管 CodeQL 与隔离 ZAP，才能正式封存。
正式封存状态以 [phase6-final-release](https://github.com/ning18898-stack/java-devsecops-lab-public/releases/tag/phase6-final-release) 的 `phase6-final-acceptance.json` 为准；该记录绑定最终通过验收的提交及三项工作流，全部条件满足后才设置 `PHASE6_READY=true`。
自有内容采用 Apache-2.0（见 LICENSE/NOTICE）；第三方内容保留上游条款。新提交只使用已核实的 GitHub 用户名/noreply。
