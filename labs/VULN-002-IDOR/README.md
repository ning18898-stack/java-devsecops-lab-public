# VULN-002：IDOR / Broken Access Control


教学目标：区分身份认证、CSRF、对象引用与对象所有权授权。Bob 可以知道并读取 Alice 的文章 ID；只有 Alice 可以修改它。漏洞版保留真实登录、CSRF、输入验证和参数化 SQL，但遗漏 owner 校验，使 Bob 可以修改 Alice 的文章。

实验只使用本项目回环地址与合成数据。HTTP 越权 PoC 固定请求 vulnerable-app；修复比较在 secure-app 的 MySQL 自动回归测试中执行。不会向修复应用发送 HTTP 越权请求。

## 实现与修复

入口为 `GET/PUT /api/labs/vuln002/articles/{id}`；PUT 仅接受 `title` 和 `content`。登录后同一 run 的用户可读文章，仅 owner 可修改。其他 run 的对象返回 404；匿名请求在有合法 CSRF 时返回 401；缺少或无效 CSRF 的写请求返回 403。

- 漏洞版：Service 未比较 owner，Mapper 的 UPDATE 仅约束 `id` 和可信 `runId`。
- 修复版：Service 校验 `article.userId == principal.id`，Mapper 的 UPDATE 同时包含 `user_id=#{currentUserId}`。身份和 runId 均来自经 BCrypt 验证的数据库用户，不能由请求赋值。
- DTO 拒绝额外 owner、id、role、runId 字段。客户端身份 Header 和 query 参数无法改变 principal。标题上限 200 字符，正文上限 20000 个 Java UTF-16 code units，另设 UTF-8 60000 字节限制。
- 独立 MyBatis 会话显式提交成功更新，未提交更新在关闭时回滚。证据以新 reader 连接读取持久化行；安全拒绝要求包括时间戳的完整行保持不变。

完整调用链和两层修复分析见 [source-analysis.md](source-analysis.md)，实际结果及限制见 [validation.md](validation.md)。

## 隔离与前置条件

需要 Docker Linux Engine、Python 3.11、项目 JDK 17 与 Maven Wrapper；依赖版本沿用基线。Windows 已执行验证；Ubuntu 命令提供复现参考，未实机验收。

专用 Compose 项目 `java-devsecops-vuln002` 仅发布 `127.0.0.1:13309`。四个独立 schema 分别用于漏洞版、修复版及其测试：`lab_vuln002_{vulnerable,secure,vulnerable_test,secure_test}`。应用账号仅可读身份、用户、文章，且只可更新文章 `title/content/updated_at`；manager 可插入/删除本实验数据，reader 只可读取文章。启动校验固定 URL、MySQL 8.4、实验标识和精确 grants。

该专用容器还包含可丢弃的第五个 `lab_test` schema 和 `v002_regression` 账号，用于原基线的 MySQL/HTTP 回归；不会连接或清空 Phase 1 的旧 volume。历史回归仅清理此测试库。实验数据使用唯一 run_id；清理只删除该 run 的文章和用户，不重置 volume。

VULN-002 仅在 `vuln002-local` profile 与 `VULN002_ENABLED=true` 同时满足时启用；默认不注册其接口/数据库组件。vulnerable-app 保持 `JSESSIONID`，secure-app 在实验 profile 使用 `VULN002SECSESSION`。Cookie 按 host/path 而非端口分隔，真实共享 CookieJar 测试验证双方使用各自 cookie；实验 security context 和 CSRF token 也与基线分别保存。

## Windows：完整复现

从仓库根目录执行：

```powershell
python labs/VULN-002-IDOR/acceptance.py
$LASTEXITCODE
```

脚本先幂等初始化忽略的 `.env.vuln002`，启动专用 MySQL 并检查隔离，恢复 VULN-001 只读 fixture 容器（需要已存在的 `.env.vuln001`），再执行 Python 测试、两应用 clean package、默认及同时启用两实验的 JAR/HTTP 验证、两次 IDOR PoC、VULN-001 回归，最后执行两应用完整 MySQL 测试。仅为子进程设置项目 JDK 17 和环境变量，不修改全局 Java 配置。

快速构建中原测试使用 H2，VULN-002 的认证和文章测试始终使用真实 MySQL 8.4 的独立测试 schema，不能把该命令称为纯离线 H2 测试。VULN-002 单独测试也需要专用 MySQL。

完整验收会启动并停止两份 JAR，完成或失败后停止自己启动的 Java 子进程；两个 fixture 数据库保留运行，方便检查。原 HTTP 脚本留下合成基线用户，位于专用容器的可丢弃 lab_test；IDOR 本次 run 的用户/文章会清理，其他 run 的数据保持不变。失败返回非零；详细日志、JUnit 副本和脱敏数据库证据位于忽略的 `artifacts/vuln002-*`。

## Windows：分步运行

```powershell
python labs/VULN-002-IDOR/manage.py up
python -m unittest discover -s labs/VULN-002-IDOR -p 'test_*.py'

# 仅为本进程加载实验环境；不打印凭据。
$env:JAVA_HOME = (Resolve-Path '.tools/jdk17/jdk-17.0.20.1+1').Path
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
foreach ($line in Get-Content -LiteralPath '.env.vuln002') {
    if ($line -match '^VULN002_(ROOT|APP|MANAGER|READER)_PASSWORD=[a-f0-9]{48}$') {
        $pair = $line.Split('=', 2)
        [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'Process')
    }
}
# 项目子进程 helper 会加载 lab_test/VULN-001 回归环境并固定 JDK。
python -c "import sys; sys.path.insert(0,'labs/VULN-002-IDOR'); import runtime as r; r.maven('vulnerable','manual-vulnerable','test'); r.maven('secure','manual-secure','test')"
```

运行 HTTP PoC 前必须构建最新 JAR，并在两个终端加载对应数据库环境。推荐用受控 helper 启动两份 JAR并在结束后停止：

```powershell
python -c "import sys; sys.path.insert(0,'labs/VULN-002-IDOR'); import runtime as r, verify; exec('with r.Servers():\n    verify.verify()')"
```

PoC 不接受 URL 或 payload 参数。它建立 Alice/Bob 和隔离对照 run，以合法 Bob Session/CSRF 修改 Alice 的文章，验证已提交值、owner/id/created_at 不变、对照文章不变；随后运行修复版的相同输入 MySQL 回归。修复测试同时覆盖 Alice 正常更新、Bob 403、CSRF/匿名/额外字段拒绝、其他 run 404、原子 owner 谓词和回滚。

## Ubuntu 参考与停止

需将可信 JDK 17 放到脚本约定的 `.tools/jdk17/jdk-17.0.20.1+1`（或在引入不同平台路径前明确调整 runtime.py 的 JAVA_HOME）。Python 命令替换为 `python3`；runtime 自动使用 `sh apps/vulnerable-app/mvnw`。Docker Compose 命令相同。BCrypt helper 使用已解析到本地 Maven 缓存的固定 crypto/logging JAR。Ubuntu 未实测，不能宣称跨平台通过。

保留所有 volume，停止本实验数据库：

```powershell
python labs/VULN-002-IDOR/manage.py down
docker compose --env-file .env.vuln001 -f labs/VULN-001-SQL-Injection/compose.yml --profile vuln001 down
```

不提供自动删除 volume 的命令；需要重置数据时先明确受影响范围。本实验不新增扫描器、Dashboard、CI 或其他漏洞。
