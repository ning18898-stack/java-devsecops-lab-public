# Secure Lab Implementations

Spring Boot / MyBatis / MySQL 修复应用，Java 17 和依赖版本与 Phase 1 相同。VULN-001 展示合成文章的参数化精确标题查询；VULN-002 增加专用 Spring Security 认证和文章 owner 授权对照。

构建入口在仓库根目录：`apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/secure-app/pom.xml package`。Ubuntu 对应 `sh apps/vulnerable-app/mvnw ...`，尚未实机验证。

仅在 `vuln001-local` profile 与 `VULN001_ENABLED=true` 同时满足时注册实验接口；默认无实验数据库连接或查询入口。服务默认绑定 `127.0.0.1:8081`，启用时拒绝非回环配置。查询仅访问独立 lab_vuln001 的只读合成表；`#{query}` 绑定所有标题输入。

VULN-001 本身没有登录业务，接口只展示固定合成数据；vulnerable-app 的 VULN-001 入口继续使用 Phase 1 Session 认证。对修复的注入回归通过自动测试执行，不扩展主动攻击目标。

完整环境、启动、MySQL/H2 测试和对应 PoC 见 [实验说明](../../labs/VULN-001-SQL-Injection/README.md)，源码差异见 [Source / Sink](../../labs/VULN-001-SQL-Injection/source-analysis.md)。

VULN-002 仅在 `vuln002-local` 和 `VULN002_ENABLED=true` 同时满足时启用。独立登录上下文、CSRF 和 `VULN002SECSESSION` 保持认证隔离；Service 校验可信 principal 的 owner ID，Mapper UPDATE 再约束 user_id。完整构建与真实 MySQL 测试需要专用容器和环境，推荐执行 `python labs/VULN-002-IDOR/acceptance.py`；快速 profile 中 VULN-002 测试仍使用 MySQL。启动、合成数据清理和限制见 [VULN-002 使用说明](../../labs/VULN-002-IDOR/README.md)。
