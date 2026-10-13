# Reproducible local delivery

Windows x64：JDK17、Python3.11.9、Node24.12.0、Docker Linux Engine/Compose、Edge。
使用锁定 POM/requirements/npm lock/CodeQL pack/ZAP digest；运行输出与凭据保持 ignored。

```powershell
python scripts/setup-jdk.py
$env:JAVA_HOME=(Resolve-Path '.tools/jdk17/jdk-17.0.20.1+1').Path
python scripts/phase6/bootstrap.py dashboard
python scripts/phase6/bootstrap.py semgrep
python scripts/phase6/bootstrap.py actionlint
python scripts/phase6/ci.py python
python scripts/phase6/ci.py java
dashboard/backend/.venv/Scripts/python.exe scripts/phase6/ci.py backend
python scripts/phase6/ci.py frontend
python scripts/phase6/ci.py semgrep
python scripts/phase6/ci.py hygiene
python scripts/phase6/ci.py workflows
```

Java Gate 使用独立随机凭据及本次专用数据库容器，quick 和 MySQL profile 各要求81/41测试无失败/跳过，13308/13309应空闲。
本地 CodeQL 教学演示：校验 CLI 2.27.2 官方 checksum 后运行 ci.py codeql，新建数据库、查询测试和3/0结果合同；托管许可另审核。
隔离被动动态验证：ci.py zap；Dashboard HTTP/重启/Edge：用后端 venv 执行 scripts/phase6/integration.py。
Ubuntu 用 sh apps/vulnerable-app/mvnw，Semgrep平台锁由 bootstrap 选择；原 Windows junction/Edge完整测试不能冒充Ubuntu实测。
python scripts/phase6/snapshot.py 导出不含历史的独立工作副本。新增LICENSE必须纳入独立清单，再取得新测试证据。
