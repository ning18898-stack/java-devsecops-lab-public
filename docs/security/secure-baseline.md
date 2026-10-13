# Phase 1 Secure Baseline

本文描述 `phase1-secure-baseline` 标签中的正常业务安全基线。当前 Phase 2 的独立 VULN-001 入口仅在显式实验模式开放，使用独立只读合成库；原用户/文章业务及测试保持此版本。实验说明见 [VULN-001](../../labs/VULN-001-SQL-Injection/README.md)，本文的 SQL 安全描述仅适用于原业务链路。

[VULN-002 IDOR](../../labs/VULN-002-IDOR/README.md) 是独立认证和专用数据库的文章修改教学入口；仅该漏洞版实验省略 owner 授权。原业务仍执行所有权检查，修复应用同时执行 Service 和 Mapper 授权。下文描述封存的原基线；当前新增 VULN-002 测试即使在快速 profile 中也需要真实 MySQL。

## Password Storage

注册密码仅经 Spring Security BCrypt（cost 12）存储，数据库只有 `password_hash`。要求 12–72 个字符且 UTF-8 编码不超过 72 字节，避免 BCrypt 截断或拒绝过长输入。密码不写入日志；认证完成后清除 principal 中的密码哈希。API 使用显式响应 DTO，实体哈希 getter 另有 `@JsonIgnore` 防护。

## Authentication

使用 Spring Security 标准表单认证过滤器和服务端 Session；登录请求为 `application/x-www-form-urlencoded`。通过参数化查询获取用户，再由标准认证提供者验证 BCrypt。错误密码与不存在账号均返回相同 401。没有默认账号、硬编码管理员密码、JWT 或 HTTP Basic 入口。

保留默认 Session fixation 防护和 CSRF 校验。先取得 `/api/auth/csrf` 和会话 Cookie，写请求携带 `X-CSRF-TOKEN`；登录后重新取得 token。登出为带 CSRF 的 POST，销毁会话并删除 Cookie。Session Cookie 为 HttpOnly、SameSite=Strict，30 分钟空闲超时。当前仅本机 HTTP，因此未开启 Secure Cookie；若以后引入 HTTPS，必须同步启用。

## Authorization

用户和文章资源仅允许已认证的 USER 或 ADMIN。注册角色固定为 USER；客户端角色字段被拒绝。ADMIN 当前没有特殊管理 API，也不能越过对象所有权约束；后续若引入管理行为，必须另行定义权限与审计。公开接口仅包含 CSRF 获取、注册、登录和无细节健康状态。

用户资料仅有 `/api/users/me`，不接收目标用户 ID。principal 使用不可变数据库 ID，因此修改用户名不会把身份绑定到另一个用户。

## Object Ownership

已登录用户可读取和搜索所有文章，这是正常业务语义。新增文章的 owner 从 principal 获取，客户端不能指定或转移 `userId`。修改、删除先检查文章存在及 owner，相应 SQL 再使用 `id AND user_id` 原子约束。非作者返回 403；不存在对象返回 404。ADMIN 同样遵守此规则。

## SQL Parameterization

MyBatis SQL 是固定模板，所有输入使用 `#{...}` 绑定；无 `${...}` 或用户输入拼接 SQL。搜索将 `%`、`_`、`!` 转义为 LIKE 字面量，用固定 `ESCAPE '!'` 匹配。分页参数受范围约束，排序字段固定，避免客户端影响 SQL 结构。

## Input Validation

服务器端 Bean Validation 校验用户名、邮箱、密码、文章标题和内容。用户名及邮箱统一转小写，数据库分别设置唯一约束；所有注册路径均执行唯一约束。文章内容按普通文本存储和返回 JSON，未来展示层必须按文本处理。

JSON 拒绝未声明字段，防止 `role`、`passwordHash`、`id` 和 `userId` 被批量赋值。标题上限 200 字符；内容上限 20000 字符且 UTF-8 不超过 60000 字节。列表每页最多 100 条，搜索词不超过 200 字符。

## Error Handling

控制器和 Security 过滤器统一返回 `timestamp/status/error/message/path`。校验、JSON 解析和数据转换异常仅返回通用 400；内部错误为通用 500，不携带 SQL、路径、类名、异常消息或 stack trace。应用异常处理器只记录异常类型，不记录数据库异常消息或请求凭据。Actuator 仅向客户端暴露 health 状态；框架内部日志不作为 API 响应公开。

## Secret Management

MySQL 密码通过环境变量注入，无默认真实密码。初始化脚本仅向忽略的本地 `.env` 生成随机值，已有非空值保持不变；`.env.example` 仅含空值。`.tools/`、日志和运行输出不提交。Compose 端口和应用监听均限制到 `127.0.0.1`，应用账号不是 MySQL root。

## 安全性质与验证边界

自动测试覆盖认证、CSRF、Session 轮换、资料隔离、文章所有权、角色注入拒绝、参数化搜索和错误脱敏。快速测试使用 H2 MySQL 模式及同一 schema；它不能替代 MySQL 8.4 验收。`-Pmysql test` 运行同一测试集且强制使用独立 `lab_test` 数据库，测试开始前清理实验数据。

真实执行证据、未测试项及最终 Gate 见 `docs/validation/phase1-validation.md`。本基线不宣称具备公网生产部署、限流或商业扫描器能力。
