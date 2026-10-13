# Secure Spring Boot Baseline

Phase 1 在 vulnerable-app 目录中实现安全的用户与文章 API，供后续实验对照。原业务仍保持安全基线；新增 [VULN-001](../../labs/VULN-001-SQL-Injection/README.md) 仅在显式实验 profile/开关下开放独立入口，使用独立只读合成库。所有请求和验证仅限本项目的本地应用。

[VULN-002 IDOR](../../labs/VULN-002-IDOR/README.md) 使用独立登录、专用 MySQL 和文章修改入口；漏洞仅放在新实验链路中。新增实验测试始终需要专用 MySQL（包括 Maven 默认 test profile），请用实验 acceptance.py 设置凭据与构建环境；原 37 项基线与 VULN-001 的源码/断言保持封存版本。

## 技术栈与环境

Java 17、Spring Boot 4.1.1、Maven 3.9.11 / Wrapper 3.3.4、MyBatis Starter 4.0.0、Spring Security Session、BCrypt、MySQL 8.4.9、JUnit / Spring Boot Test。精确版本见 [环境记录](../../docs/environment.md)。

Windows 11 需要 PowerShell、Python 3.11+ 和可用的 Docker Linux Engine；Ubuntu 需要 Python 3.11+、JDK 17、Docker Engine 及 Compose 插件。首次 Wrapper 执行需要访问 Maven Central。应用只监听 `127.0.0.1:8080`。


## Windows：指定项目专用 JDK 17

```powershell
python scripts/setup-jdk.py
$env:JAVA_HOME = (Resolve-Path '.tools/jdk17/jdk-17.0.20.1+1').Path
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
java -version
.\apps\vulnerable-app\mvnw.cmd -version
```

安装辅助脚本使用官方 Temurin Release，并检查官方 SHA-256；重复运行复用已校验的下载。它只支持 Windows x64。上述环境变量仅影响当前进程，不修改系统 PATH、全局 JAVA_HOME 或原有 Java 23。`.tools/` 不提交。

## 编译、自动测试与打包

```powershell
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml clean compile
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml test
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml package
```

Maven Enforcer 要求运行 JDK 为 17；Java 23 会被拒绝。默认测试使用隔离 H2 内存库、真实 Spring Security 过滤器及 MyBatis；没有跳过测试。H2 使用与 MySQL 相同的 `infra/mysql/init/001-schema.sql`，但不能代替 MySQL 集成验收。

## 无 Docker 的临时 HTTP 演示（已实测）

```powershell
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml -Ph2-demo spring-boot:run
```

在第二个终端执行：

```powershell
python scripts/verify-baseline.py
```

`h2-demo` 显式加入测试配置和测试依赖，不打入生产 JAR。数据库在停止进程后消失。验证脚本仅请求固定本地地址，使用随机密码和唯一运行标识，不打印凭据；成功后删除测试文章、登出，保留本次两个合成用户。失败可能留下本次合成数据，重新执行使用新标识，不修改其他用户。日志写入 `artifacts/`，失败退出码非零。

使用 Ctrl+C 停止应用。**此演示不满足 Docker/MySQL 最终 Gate。**

## MySQL 启动与初始化（Windows 本地运行）

先启动 Docker Desktop 的 Linux Engine，然后执行：

```powershell
python scripts/init-local-env.py
docker compose --profile test config --quiet
docker compose --profile test up -d --wait --wait-timeout 180
. ./scripts/use-local-env.ps1
```

凭据脚本只补齐 `.env` 中的缺失值，不覆盖现有非空值；不要打印或提交 `.env`。配置检查使用 `--quiet`，避免完整 Compose 输出包含凭据。

应用 MySQL 发布在 `127.0.0.1:13306`，测试 MySQL 在 `127.0.0.1:13307`；使用独立命名 volume，避免接触机器已有的默认 3306 实例。应用数据库为 `lab`，应用账号为 `lab`；测试库/账号为 `lab_test`。两个账号均不是 root。

MySQL 官方镜像仅在**新数据 volume** 上执行初始化 SQL；重启不会更新 schema。当前没有迁移历史，因此未引入 Flyway。修改 schema 后不得把重启当作迁移，须定义迁移或显式重置实验数据。

## MySQL 测试与应用启动（Windows 本地运行）

在已指定 JDK 17、已加载环境变量的终端执行：

```powershell
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml -Pmysql test
java -jar apps/vulnerable-app/target/vulnerable-app-0.1.0-SNAPSHOT.jar
```

测试会清理独立 `lab_test` 的用户和文章，不能指向应用库或已有业务库。允许通过 `TEST_DB_URL`、`TEST_DB_USERNAME` 配置连接，测试同时核验数据库类型和 catalog 为 `lab_test`。

应用连接可用 `DB_URL`、`DB_USERNAME` 覆盖，密码必须由 `DB_PASSWORD` 提供。启动之前先停止 H2 演示，避免端口冲突。在另一个终端检查并验证：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/actuator/health
python scripts/verify-baseline.py
.\apps\vulnerable-app\mvnw.cmd -B -ntp -f apps/vulnerable-app/pom.xml -Pmysql test
```

最后一次完整测试必须在真实 MySQL 的 HTTP 验证之后执行，才满足最终 Gate。直接 `spring-boot:run` 也可作为本地 MySQL 开发入口，但当前未实测。

## API 与示例请求

没有默认账号或管理员。注册仅创建 USER。ADMIN 暂无特殊管理接口，同样只能修改和删除自己的文章。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/auth/csrf` | 获取 Session CSRF token，无需认证 |
| POST | `/api/auth/register` | JSON：username/password/email；201 或重复 409 |
| POST | `/api/auth/login` | 表单 username/password；200 或失败 401 |
| POST | `/api/auth/logout` | 销毁 Session；200 |
| GET / PUT | `/api/users/me` | 查看 / 更新自身 username、email |
| POST | `/api/articles` | JSON title/content；owner 由服务端确定 |
| GET | `/api/articles` | 所有文章，page=0、size=20，size 上限 100 |
| GET | `/api/articles/{id}` | 所有已登录用户可读 |
| PUT / DELETE | `/api/articles/{id}` | 仅作者；更新 200，删除 204，越权 403 |
| GET | `/api/articles/search?q=...` | 字面量子串搜索，支持同样分页参数 |
| GET | `/actuator/health` | 仅健康状态，无数据库细节 |

写请求需要 Cookie 和 `X-CSRF-TOKEN`；登录会轮换 token，之后必须重新获取。完整请求示例已在 `scripts/verify-baseline.py` 中实际执行。下面是等价的 PowerShell 请求模式（使用已实测 H2 演示或就绪 MySQL 应用）：

```powershell
$labCsrf = Invoke-RestMethod http://127.0.0.1:8080/api/auth/csrf -SessionVariable labSession
$labPassword = [guid]::NewGuid().ToString()
$labName = 'demo_' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$labRegistration = @{username=$labName; password=$labPassword; email="$labName@example.test"} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8080/api/auth/register -Method Post -WebSession $labSession -Headers @{'X-CSRF-TOKEN'=$labCsrf.token} -ContentType 'application/json' -Body $labRegistration
Invoke-RestMethod http://127.0.0.1:8080/api/auth/login -Method Post -WebSession $labSession -Headers @{'X-CSRF-TOKEN'=$labCsrf.token} -ContentType 'application/x-www-form-urlencoded' -Body @{username=$labName; password=$labPassword}
$labCsrf = Invoke-RestMethod http://127.0.0.1:8080/api/auth/csrf -WebSession $labSession
Invoke-RestMethod http://127.0.0.1:8080/api/users/me -WebSession $labSession
Invoke-RestMethod http://127.0.0.1:8080/api/auth/logout -Method Post -WebSession $labSession -Headers @{'X-CSRF-TOKEN'=$labCsrf.token}
```

用户名为 3–32 个 ASCII 字母、数字或下划线；邮箱、用户名统一转小写。密码至少 12 字符且 UTF-8 不超过 72 字节。标题不得为空且最多 200 字符；内容不得为空、最多 20000 字符且 UTF-8 最多 60000 字节。未知 JSON 字段被拒绝。错误统一为 `timestamp/status/error/message/path`，不返回密码、SQL、内部类名或 stack trace。

## 停止与重置数据库（Windows 本地运行）

停止应用使用 Ctrl+C；保留数据库数据并停止容器：

```powershell
docker compose --profile test down
```

以下命令**删除本 Compose 项目两个数据库 volume 中的全部实验数据**，仅在确认需要重置本地实验时执行。凭据不变，重新创建时会重新执行初始化 SQL：

```powershell
docker compose --profile test down --volumes
docker compose --profile test up -d --wait --wait-timeout 180
```


## Ubuntu 对应命令（NOT_TESTED）

使用可信来源安装/解压的 Temurin JDK 17，指定当前 shell 的 JDK；不要用 Java 23 替代：

```bash
export JAVA_HOME=/absolute/path/to/temurin-17
export PATH="$JAVA_HOME/bin:$PATH"
java -version
sh apps/vulnerable-app/mvnw -version
sh apps/vulnerable-app/mvnw -B -ntp -f apps/vulnerable-app/pom.xml clean compile
sh apps/vulnerable-app/mvnw -B -ntp -f apps/vulnerable-app/pom.xml test
sh apps/vulnerable-app/mvnw -B -ntp -f apps/vulnerable-app/pom.xml package
python3 scripts/init-local-env.py
docker compose --profile test config --quiet
docker compose --profile test up -d --wait --wait-timeout 180
```

只对 `init-local-env.py` 生成的纯 `NAME=hex-value` 文件，可以执行 `set -a; . ./.env; set +a` 加载到当前 shell。不要 source 不可信配置文件。随后使用 `sh apps/vulnerable-app/mvnw -B -ntp -f apps/vulnerable-app/pom.xml -Pmysql test` 和相同的 `java -jar` 命令。H2 演示对应 `sh apps/vulnerable-app/mvnw -B -ntp -f apps/vulnerable-app/pom.xml -Ph2-demo spring-boot:run`，HTTP 检查为 `python3 scripts/verify-baseline.py`。
