# VULN-001 Source / Sink Analysis

## 漏洞调用链

HTTP GET `/api/labs/vuln001/articles/search?q=...` → LabController → LabService → LabDatabase → LabArticleMapper → UnsafeSqlProvider → MyBatis/JDBC → 只读 MySQL lab_articles。

| 标记 | 位置 | 数据流与作用 |
| --- | --- | --- |
| Source | [LabController](../../apps/vulnerable-app/src/main/java/com/example/devsecopslab/lab/vuln001/LabController.java)，29–30 行 | HTTP q 成为 query；仅校验非空和 200 字符上限，校验不赋予 SQL 安全性 |
| Propagation | [LabService](../../apps/vulnerable-app/src/main/java/com/example/devsecopslab/lab/vuln001/LabService.java)，10 行 | 原字符串传递给独立数据库组件 |
| Propagation | [LabDatabase](../../apps/vulnerable-app/src/main/java/com/example/devsecopslab/lab/vuln001/LabDatabase.java)，60–62 行 | 打开隔离只读 session，调用 mapper.search(query) |
| Root Cause | [UnsafeSqlProvider](../../apps/vulnerable-app/src/main/java/com/example/devsecopslab/lab/vuln001/UnsafeSqlProvider.java)，10–11 行 | 把 query 拼入引号中的 SQL 文本，数据和语法失去边界 |
| Sink | [LabArticleMapper](../../apps/vulnerable-app/src/main/java/com/example/devsecopslab/lab/vuln001/LabArticleMapper.java)，9–11 行 | SelectProvider 的完整 SQL 交给 MyBatis/JDBC 执行 SELECT；没有 query 参数绑定 |

## 查询语义

正常输入 `Alpha public article`：

```sql
SELECT id, title, visibility FROM lab_articles
WHERE visibility = 'public' AND title = 'Alpha public article'
ORDER BY id LIMIT 10;
```

教学输入 `' OR '1'='1`：

```sql
SELECT id, title, visibility FROM lab_articles
WHERE visibility = 'public' AND title = '' OR '1'='1'
ORDER BY id LIMIT 10;
```

AND 的优先级高于 OR，因此恒真分支返回包含合成 draft 的三行。只读账号和禁用多语句限制影响范围，不能阻止 SELECT 条件被改变。

## 修复调用链与参数化证据

secure-app 的 [LabController](../../apps/secure-app/src/main/java/com/example/securelab/vuln001/LabController.java) → [LabService](../../apps/secure-app/src/main/java/com/example/securelab/vuln001/LabService.java) → [LabDatabase](../../apps/secure-app/src/main/java/com/example/securelab/vuln001/LabDatabase.java) → [LabArticleMapper](../../apps/secure-app/src/main/java/com/example/securelab/vuln001/LabArticleMapper.java)（9 行）保留同样查询业务条件，仅使用 `title = #{query}`。

MyBatis BoundSql 为 `... title = ? ...`，parameterMappings 只有 query；输入始终作为一个字符串值，不能新增 OR 条件。测试实际执行正常输入与同一教学输入，分别得到 `[1]` 与 `[]`，并检查 SQL 中没有注入字符串。

两版都可能使用 JDBC PreparedStatement。漏洞版在创建 PreparedStatement 前已经拼接完 SQL，且没有参数映射；使用这个 API 本身并不保证输入被参数化。修复依据是固定 SQL 模板与值绑定，而不是过滤单引号或禁用关键字。[MyBatis 官方参数说明](https://mybatis.org/mybatis-3/sqlmap-xml.html#Parameters)解释了 `#{...}` 的绑定行为。

## 与 Phase 1 的关系

原 ArticleController/ArticleService/ArticleMapper 未修改；它们仍转义 LIKE 通配符并绑定所有输入。实验使用独立表、连接池和入口，默认不装配；默认与启用实验模式的原 HTTP 回归均已运行。Phase 1 标签及原测试断言作为安全对照保留。
