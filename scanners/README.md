# Phase 3 本地静态分析

范围：快照内现有的 Phase 2 的 SQL Injection / IDOR 对照。只扫描两套本地应用的 `src/main/java`；不启服务、不执行 HTTP 攻击、不使用云扫描、不启动 Phase 4。

## 固定环境与入口

Windows 11、Python 3.11.9、项目 Temurin 17.0.20.1+1、Maven Wrapper 3.3.4 / Maven 3.9.11、MyBatis 3.5.19（Starter 4.0.0）。Semgrep CE 1.180.0；Python 全部传递依赖见 `semgrep/requirements.lock.txt`。CodeQL CLI 2.27.2，官方发布 ZIP SHA-256：`6c90c8503af7b13827a151fbada959c1e5e4a49dd4ebad5bf0855f8a54404c1b`。查询依赖 `codeql/java-all` 9.3.1，所有传递包固定于 `codeql/codeql-pack.lock.yml`。

```powershell
python -u scripts/setup-phase3.py
python -u scripts/verify-phase3.py --stage semgrep
python -u scripts/verify-phase3.py --stage codeql
python -u scripts/verify-phase3.py --stage builds
python -u scripts/verify-phase3.py
```

构建测试复用 Phase 2 既有本地凭据与专用 MySQL 容器；不输出凭据、不删除 volume。完整入口执行构建、规则测试、查询测试、真实扫描、源码提取范围及保护文件检查。失败返回非零。`--rebuild-databases` 强制重新提取；默认只复用完成且源码/CLI/JDK/构建命令指纹一致的数据库。数据库不是跨工具版本可通用的缓存。


Ubuntu 尚未实机验证；本 Python bootstrap/验收入口当前仅支持 Windows。Ubuntu 可按官方说明安装同版本 Semgrep/CodeQL Linux CLI，配置 JDK 17，以 `sh apps/vulnerable-app/mvnw` 替换 Windows Wrapper 命令；不能把这段说明宣称为实测跨平台通过。

官方依据：[Semgrep 安装](https://docs.semgrep.dev/getting-started/quickstart)、[规则 validate/test](https://docs.semgrep.dev/writing-rules/testing-rules)、[CodeQL CLI 发布](https://github.com/github/codeql-cli-binaries/releases/tag/v2.27.2)、[Java 污点 API](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/)、[路径查询](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)。

## CodeQL 许可用途


条款同时限制其他非开源代码库分析和自动数据库生成用途。[GitHub 当前说明](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)列出的通常使用条件是公开 GitHub 仓库或符合条件的组织付费 Code Security。演示用途确认不是通用商业、私有生产仓库、CI 或第三方托管许可；任何后续使用必须重新核对适用依据。本阶段不推送、不上传结果、不实现 CI。

## 检测契约与边界

| 规则 / 查询 | 判定内容 | 预期漏洞位置 |
| --- | --- | --- |
| Semgrep java-sql-provider-concat | SQL 关键字开头的字符串字面量与非字面量拼接 | UnsafeSqlProvider.java 10–11 行 |
| Semgrep java-lab-idor-update-scope | lab_articles 的 id/run_id 参数化 UPDATE 没有 WHERE user_id 参数条件 | IdorMapper.java 10 行 |
| CodeQL java/lab-mybatis-provider-sqli | @RequestParam 经真实方法调用及 MyBatis 参数映射到 Provider SQL 返回文本 | UnsafeSqlProvider.java 10–11 行；保留 Controller 至 Provider 路径 |
| CodeQL java/lab-idor-update-owner | 实验 UPDATE 没有 owner 谓词 | IdorMapper.java 10 行 |
| CodeQL java/lab-idor-service-owner | 写调用不受已识别的拒绝型 owner 比较控制，或没有传入同一 principal.getId() | IdorService.java 15 行 |

规则本身不依赖应用名称、包路径、固定源码行号或固定类名。SQLi 样例改变 Mapper/Provider 类名、方法名、参数 key 与表名；IDOR 表名和 user_id/run_id 列是实验策略范围，不能推广为全项目通用授权检测。

Semgrep SQL 拼接是语法检查：可能把可信非字面量拼接视为风险；StringBuilder、间接赋值、XML SQL、其他框架不覆盖。IDOR 是数据库防御层检查，即使 Service 单独正确仍会报告缺少 UPDATE owner 条件；没有报告不证明 principal 来源可信，不能证明权限完备。SQL 文本中的复杂 OR、注释、动态 SQL 和等价谓词可能使文字匹配误判。边界样例明确保留，不用 TODO 注解跳过失败。

CodeQL SQLi 模型限定 `@SelectProvider(type=..., method=...)`、静态单 Map 参数 Provider、显式 `@Param` 与同 key `Map.get`。不建模 XML、provider instance/default method、嵌套 Map、动态 method 选择或未经注解绑定的参数别名；安全的 `#{...}` 固定 SQL 不产生污点。Provider 的 SQL 文本返回就是框架消费的 SQL sink，路径不会伪称追踪到 MyBatis 内部 JDBC 实现。

CodeQL IDOR Service 查询识别 `userId()!=getId()`、拒绝分支中的 throw，以及该比较的 false 分支控制写调用，检查传入身份来自同一变量。它不是完整策略证明：其他等价 guard、外部授权服务会误报；未证明被比较对象就是待写对象，也未证明 principal 的认证来源，可能漏报构造的无关对象比较或伪造身份。真实项目中的 owner 读取和 principal 可信性来自快照内现有的源码及 Phase 2 回归证据。查询测试包含缺少 guard、仅日志、写后 guard 和错误身份。

## MyBatis 模型依据与对照

MyBatis 3.5.19 的 [ParamNameResolver.getNamedParams](https://github.com/mybatis/mybatis-3/blob/mybatis-3.5.19/src/main/java/org/apache/ibatis/reflection/ParamNameResolver.java)按 @Param 建立 key/value Map；[ProviderSqlSource](https://github.com/mybatis/mybatis-3/blob/mybatis-3.5.19/src/main/java/org/apache/ibatis/builder/annotation/ProviderSqlSource.java)依据 type/method 选择 Provider 并反射调用，以返回文本创建 SQL。模型只在同一注解、同一参数 key、选中的方法及其参数 Map 查找结果之间增加流边。参数名不匹配、未选择的 Provider 和常量绑定 SQL 均作为阴性测试。

`diagnostics/SqlWithoutBridge.ql` 为相同 source/sink 去掉额外桥接的对照；真实运行结果及新增流边记录在验收文件。若对照没有结果，说明这条调用链缺少框架连接，不意味着无 SQL 注入。机器证据保留在忽略的 artifacts/phase3；受审查的精简结果将记录于验收文档。
