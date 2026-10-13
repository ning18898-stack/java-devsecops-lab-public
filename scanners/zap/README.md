# 本地 ZAP 被动扫描

官方 ZAP 2.17.0、Temurin 17 JRE 和 Python 3.12.13 容器固定于 [镜像 digest](images.lock.json)，平台 linux/amd64；宿主 JDK 与 Python 使用项目已有版本。官方依据：[Docker 镜像](https://www.zaproxy.org/docs/docker/about/)、[Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)、[固定请求 job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/)、[被动设置](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanconf/)、[JSON 报告](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/)、[执行退出码](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-exitstatus/)。官方传统 Baseline 脚本会进行 spider；本项目选择无爬虫的固定请求 AF 计划以精确限制请求范围，仍只做被动分析。

`automation/scan.py --tool zap` 构建快照内现有的 vulnerable-app 的 test-profile classpath，复制 classes、测试资源和固定 Maven 依赖，记录运行内容 SHA-256，启动可丢弃 H2 应用。应用库初始为空，用户名 p4_synthetic，随机口令由 P4_H2_PASSWORD 注入；无实验登录、无生产数据、无旧 MySQL volume。SQLi / IDOR profile 默认关闭。server.address=0.0.0.0 只存在于无宿主端口映射的内部容器，原配置与 Java 源码不变。

每次建立两个专用 `--internal` bridge 网络：back 仅含 application 和 guard；scan 仅含 guard 和 ZAP。ZAP 只访问经 Docker inspect 验证的 guard IPv4，不使用容器 localhost 或 host.docker.internal。入口核对网络名称、项目/run 标签、内部标志、唯一 IPv4 subnet 和成员全集，核对容器运行状态、镜像 ID/digest、网络全集、只读根目录、只读内容 mount、应用启动命令/类/profile、运行内容 hash 和真实 health UP。不得将另一 Docker 容器仅按名字当作授权应用。所有本次容器结束后删除，本次网络删除，无端口发布，无 Docker socket mount。

网关仅接受 [预配置路径](plans/passive.json) 的精确 GET；拒绝未知 Host、协议/端口替换、查询/片段、编码、控制字符、规范化路径、写方法、CONNECT 和凭据头。上游 DNS 每次必须精确等于已检查的 application 地址，连接使用该固定 IP，返回重定向立即拒绝且不跟随。5 秒上游超时、1 MiB body 上限；只转发上游响应信息，不添加网关 Server 版本。ZAP context 同样限定精确路径，passive scan only in scope，规则告警上限 20，单任务 300 秒，ZAP 容器 2 CPU / 2 GiB / JVM 1 GiB、512 PID；应用/网关各 1 CPU / 1 GiB / 256 PID。没有 spider、AJAX、浏览器或主动 job。

工具执行、目标健康失败、超时、零告警分别记录；`zap-work/plan.yaml`、真实 JSON、脱敏 stdout/stderr、容器日志及网关请求审计保留。只有 AF 退出 0、JSON 可解析、未 OOM、审计恰为 5 个允许 GET 且无阻断，才记录 COMPLETED；告警数量不参与成功判定。实际结果不保证检出 SQLi / IDOR，未经登录的 JSON/错误响应被动覆盖有限。若目标行为变化产生重定向，本次任务失败并保留证据，需要审查目标变化后再运行，不扩展扫描范围。
