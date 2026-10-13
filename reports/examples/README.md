# 可公开报告资料

[phase4-reviewed](phase4-reviewed/manifest.json)为两次真实Phase 4运行的**经审查历史衍生包**。保留SQLi/IDOR的工具观察项、源码相对位置、CodeQL路径和ZAP零告警结构；移除本机绝对路径、命令列表和Docker/数据库/Session运维材料。保留的JSON/SARIF重新计算摘要；operational.txt只含“运维证据未公开”的说明，不是伪造运行日志。原始报告摘要另记录在manifest，原件仍位于ignored artifacts，不修改原件。

用于离线演示与CI导入契约测试，不是新环境当前扫描结果；第二run的静态历史复用标记保留。可以用ci.py fixtures校验并在干净检出中导入。第一次运行Semgrep 2、CodeQL 3、ZAP 0，独立漏洞数量未知；观察项不能简单相加认定5个漏洞。

SQL Injection来自HTTP参数进入MyBatis Provider拼接SQL文本；修复为固定SQL与参数绑定。IDOR来自未校验文章owner的UPDATE；修复以可信principal校验并在SQL加入owner条件。根因、真实MySQL复现及修复对照见[VULN-001](../../labs/VULN-001-SQL-Injection/README.md)与[VULN-002](../../labs/VULN-002-IDOR/README.md)。有限未登录被动ZAP未报告这两项认证实验，不代表无漏洞。

本包不包含凭据、Cookie、Token、个人账号、私有数据库、HAR、trace或宿主配置。仍仅用于隔离教学，不用于公网攻击。项目没有宣告开源许可证；可展示材料不等于为整个项目授予再许可。远程上传前需确认仓库授权与可见性。
