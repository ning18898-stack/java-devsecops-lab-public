# Independently reviewed release snapshot

这是从维护者非公开工作区的当前源码重新审核导出的公开候选，不是原仓库的 Fork，也不是原开发历史的重建。
原开发仓库保持私有、原历史/标签/验收证据不变；此处不披露其地址、原提交哈希或私有运行记录。
原七个历史标签只用于私有开发封存，不导入公开仓库，也不伪造七个阶段提交。

替代机制：source-manifest.json 精确列举审核文件及规范 LF 的 SHA-256；CI、Phase3/4/5保护和 Phase6 hygiene 使用同一独立清单。
Phase6 snapshot 只复制审核文件，重新 git init，无私有对象和 alternates。新的源码快照标识只在本仓库中生成。
无提交的本地候选使用独立 Git tree SHA 作为源码标识；它不是开发提交。核实实际 noreply 后才能创建新的公开初始提交。
Dashboard 使用该独立 tree/新公开 commit 读取片段，保留同样的证据校验、幂等性及追加审计规则。

release-example-001/002 是对私有实验结果重新处理的演示 fixture：删除私有来源元数据、运维内容和原运行标识，重新计算证据 hash。
它们不证明公开候选已经扫描通过，不冒充新的扫描。当前候选的 Java、静态/动态扫描和 Dashboard 测试必须另行实际执行。
原始报告、原始日志和数据库均不包含在源码交付中。第三方版权与许可通知按上游保留。
