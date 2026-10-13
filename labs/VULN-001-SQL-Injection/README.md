# VULN-001: SQL Injection

## 实验目标与范围

观察 HTTP 标题输入成为 SQL 语法时如何绕过查询中的 public 条件，并用 MyBatis 参数绑定修复。仅使用本项目独立 MySQL 的三条合成记录，不访问真实数据，不进行破坏性操作或公网扫描。原 `/api/articles/search` 仍按字面量搜索，代码与 Phase 1 标签一致。

[源码分析](source-analysis.md)标记 Source、Propagation、Sink、Root Cause；[验收结果](validation.md)记录实际命令、结果与限制。

## 环境与隔离

Java 17 / Spring Boot 4.1.1 / MyBatis Starter 4.0.0 / MySQL 8.4.9；沿用 Maven Wrapper 3.3.4 / Maven 3.9.11。Windows 11 本地运行，Ubuntu 命令提供但 NOT_TESTED。

- vulnerable-app：`127.0.0.1:8080`，沿用 Session 登录；实验路径 `/api/labs/vuln001/articles/search?q=...`。
- secure-app：`127.0.0.1:8081`，只展示修复查询，不复制用户 CRUD；接口仅返回合成数据，无独立登录业务。
- 实验库：`127.0.0.1:13308/lab_vuln001`；账号 `vuln001_reader` 仅对 lab_articles 有 SELECT；不能访问 Phase 1 表。
- profile `vuln001-local` 与 `VULN001_ENABLED=true` 缺一不可。默认无实验 endpoint/pool；启用时启动校验显式回环绑定、固定连接 URL、MySQL 8.4、catalog 及账号 grants。
- JDBC 禁用多语句，查询超时 3 秒、返回 LIMIT 10。数据库只读权限是写入隔离边界；它不会修复 SELECT 中的注入。
- H2 仅用于测试 profile 与测试 classpath 的命名内存库，不进入生产 JAR。

## 合成数据

| ID | 标题 | visibility |
| --- | --- | --- |
| 1 | Alpha public article | public |
| 2 | Beta public article | public |
| 3 | Synthetic draft article | draft |

表只含 id/title/visibility，无密码、用户信息或秘密。正常精确标题查询仍要求 visibility=public。初始化 SQL 可重复执行且不覆盖现有行；初始化只在新 volume 自动执行。修改 fixtures 后不能把重启当作迁移。

## Windows：准备与构建

以下命令均在仓库根目录执行。启动 Docker Linux Engine，使用项目 JDK 17：

```powershell
$env:JAVA_HOME = (Resolve-Path '.tools/jdk17/jdk-17.0.20.1+1').Path
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
java -version
python labs/VULN-001-SQL-Injection/init_env.py
. ./labs/VULN-001-SQL-Injection/use_env.ps1
. ./scripts/use-local-env.ps1

docker compose --profile test up -d --wait --wait-timeout 180
docker compose --env-file .env.vuln001 -f labs/VULN-001-SQL-Injection/compose.yml --profile vuln001 config --quiet
docker compose --env-file .env.vuln001 -f labs/VULN-001-SQL-Injection/compose.yml --profile vuln001 up -d --wait --wait-timeout 180
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml package
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/secure-app/pom.xml package
```

`.env` 与 `.env.vuln001` 均忽略；实验初始化脚本只生成缺失值，已有非空值不变，不打印值。`env.example` 为空值样例。修复应用复用已固定的 Wrapper 启动器，分别通过 `-f` 构建，不引入多模块依赖或新框架。

## 明确启用实验

在准备好的终端启动漏洞应用：

```powershell
$env:SPRING_PROFILES_ACTIVE = 'local,vuln001-local'
$env:VULN001_ENABLED = 'true'
java -jar apps/vulnerable-app/target/vulnerable-app-0.1.0-SNAPSHOT.jar
```

可在另一个同样加载实验环境的终端运行修复应用，仅做正常功能检查：

```powershell
$env:SPRING_PROFILES_ACTIVE = 'vuln001-local'
$env:VULN001_ENABLED = 'true'
java -jar apps/secure-app/target/secure-app-0.1.0-SNAPSHOT.jar
```

关闭漏洞应用时，将 profile 恢复为 `local`、开关设为 `false` 并重启。实验开关不动态改变正在运行的组件。默认模式中，已登录请求实验路径返回 404；匿名请求仍遵循原认证要求返回 401。

## 本地 PoC 与修复验证

```powershell
. ./labs/VULN-001-SQL-Injection/use_env.ps1
$env:VULN001_TEST_DB_URL = 'jdbc:mysql://127.0.0.1:13308/lab_vuln001?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true'
$env:VULN001_TEST_DB_USERNAME = 'vuln001_reader'
$env:VULN001_TEST_DB_PASSWORD = $env:VULN001_DB_PASSWORD
python labs/VULN-001-SQL-Injection/verify.py
```

脚本固定请求本项目 `127.0.0.1:8080`，不接受目标/载荷参数、禁用代理和重定向，核对实验身份。创建唯一合成账号并登录，验证正常标题、draft 隐藏、恒真与恒假条件，再检查原安全搜索保持字面量语义。随后调用 secure-app 的 `-Pmysql -Dtest=LabQueryTest test`，在同一只读数据库上以同样输入运行修复回归；不向 secure-app 发送攻击请求。

教学输入仅为 `' OR '1'='1`。它把原 `public AND title=...` 条件扩展成 `(... AND ...) OR TRUE`，漏洞版返回 `[1,2,3]`；安全版将整串输入绑定为一个值，返回 `[]`。这不是原业务的跨用户读取漏洞。

日志、退出码、运行标识及 JSON 摘要保存到忽略的 `artifacts/`。成功后登出；合成登录账号保留，查询不改变三条 fixtures。重复运行使用新账号；失败返回非零并记录 FAIL，重跑无需重置 volume，可能保留失败运行的合成账号。

## 完整测试与基线回归

准备同一终端的 JDK 与测试环境后：

```powershell
python -m unittest discover -s labs/VULN-001-SQL-Injection -p test_verify.py -v
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml test
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/secure-app/pom.xml test
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml -Pmysql test
apps/vulnerable-app/mvnw.cmd -B -ntp -f apps/secure-app/pom.xml -Pmysql test
python scripts/verify-baseline.py
```

默认测试使用 H2；`-Pmysql` 时必须提供上述 VULN001_TEST_DB_*，并通过原环境脚本加载 TEST_DB_PASSWORD。原 37 项测试仍只清理独立 lab_test；新实验测试不执行写入或清理实验 MySQL。

## Ubuntu（NOT_TESTED）

指定可信 JDK 17 的当前 shell JAVA_HOME/PATH；构建命令以 `sh apps/vulnerable-app/mvnw` 代替 `.cmd`，Python 使用 `python3`，Compose 命令相同。仅对本项目脚本生成的纯 hex 配置，可使用 `set -a; . ./.env; . ./.env.vuln001; set +a` 加载到当前 shell。导出同样的 SPRING_PROFILES_ACTIVE、VULN001_ENABLED、VULN001_TEST_DB_* 后运行 JAR/PoC/测试；不要 source 不可信配置。

## 停止与数据保留

两个 JAR 各使用 Ctrl+C 停止；保留 volume 的容器停止命令：

```powershell
docker compose --env-file .env.vuln001 -f labs/VULN-001-SQL-Injection/compose.yml --profile vuln001 down
docker compose --profile test down
```

本阶段没有删除任何既有 volume，也不提供自动破坏数据的重置步骤。后续需另行批准的实验与框架保持未开始，不自动提交 Git。
