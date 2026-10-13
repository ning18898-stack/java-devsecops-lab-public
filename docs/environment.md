# Local reproducibility requirements

Windows x64、Docker Linux Engine/Compose、Python 3.11.9、Node 24.12.0、JDK 17、Edge。
Maven 3.9.11/Wrapper 3.3.4、Spring Boot 4.1.1、MySQL 8.4.9、Semgrep 1.180.0、CodeQL2.27.2、ZAP2.17.0。
版本依据为源码锁文件/校验和；不保留原开发机器路径、修复时间线或历史运行记录。
本地候选允许复用明确声明的宿主工具和下载缓存，但构建、数据库和测试输出在候选中重新生成。
完整后端Windows junction与Edge测试用Windows执行；Ubuntu适用项另测，不能外推。
