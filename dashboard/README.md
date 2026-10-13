# Phase 5 安全观察台

FastAPI + Vue 3 + SQLite 的本机单用户平台，消费 Phase 4 JSON 1.0。没有执行扫描或任意命令的 HTTP 入口。仅供本地教学与演示，无生产身份认证、授权或多人隔离能力，不能部署到公网或通过反向代理/端口转发共享。

## 初始化与启动（Windows，已实际验证）

前提：Python 3.11.9、Node 24.12.0、npm 11.6.2。后端所有直接及传递依赖固定于 requirements.txt；前端由 package.json 和 package-lock.json 固定。后端采用标准库 sqlite3，无额外数据库服务。

```powershell
python -m venv dashboard/backend/.venv
dashboard/backend/.venv/Scripts/python.exe -m pip install -r dashboard/backend/requirements.txt
npm --prefix dashboard/frontend ci
python dashboard/manage.py start
```

访问 http://127.0.0.1:5173；后端默认 http://127.0.0.1:8000/api/health。当前机器 8000 被其他服务占用，使用 `python dashboard/manage.py start --port 18765`，后端为 http://127.0.0.1:18765/api/health。该参数仅改变回环端口。管理入口固定监听回环，禁止信任代理转发地址。后台进程隐藏启动；services.json 仅记录本项目进程，停止前校验 PID 与绝对脚本路径；每次服务日志使用新文件。初始化空库不自动插入任何扫描任务或漏洞。

总览中输入 Phase 4 run_id 导入，例如已验收的真实运行：

```text
release-example-001
```

默认只读导入目录 artifacts/phase4，默认数据库 artifacts/dashboard/dashboard.sqlite3。配置 DASHBOARD_IMPORT_ROOT 与 DASHBOARD_DB 可指定独立本地输入及数据库；只能由启动环境配置，不开放路径参数 API。全部运行输出与数据库置于忽略的 artifacts，禁止提交。原 Phase 4 JSON/扫描证据不会被改写。

HTTP 导入示例（与界面使用同一 API）：

```powershell
$session = Invoke-RestMethod http://127.0.0.1:8000/api/session
$headers = @{ 'X-Dashboard-Token' = $session.write_token }
Invoke-RestMethod http://127.0.0.1:8000/api/imports -Method Post -Headers $headers -ContentType application/json -Body '{"run_id":"release-example-001"}'
```

该令牌是本机浏览器跨站写入防护，不是用户身份认证。实际 TCP peer、Host、Origin 均校验；无/错误令牌不能写；外部 Origin、非回环 peer 和未知 Host 连只读接口也拒绝。不开放 CORS。只允许本机 5173 界面 Origin 和请求本身的后端 Origin；不信任 X-Forwarded-For。限制 JSON 写入和 1 MiB 请求体。

## 停止与重置

```powershell
python dashboard/manage.py stop
python dashboard/manage.py reset
```

使用自定义端口时，以 `python dashboard/manage.py reset --port 18765` 重置；stop 依据记录的 PID，与端口无关。reset 要求服务已停止且指定后端端口空闲，将默认数据库改名为带时间的 .sqlite3.backup，下一次 start 初始化空库。只操作默认 Dashboard 数据库，不删除扫描证据或其他项目数据；有自定义数据库时应停止服务后自行备份指定文件。当前 schema user_version=1；未来升级须提供显式迁移，未知版本拒绝启动。

手动前台启动和停止：分别在两个终端运行以下命令，Ctrl+C 停止。

```powershell
dashboard/backend/.venv/Scripts/python.exe dashboard/backend/serve.py
cd dashboard/frontend
npm run dev
```

生产静态构建的本地预览：npm run build，然后 npm run preview，仍由 /api 代理消费正在运行的 FastAPI。DASHBOARD_API 只配置本机后端，默认 8000。

Linux 命令参考（Ubuntu 宿主 NOT_TESTED）：python3 -m venv dashboard/backend/.venv；使用 .venv/bin/python 安装 requirements.txt 和运行 serve.py；前端 npm ci / npm run dev。SQLite、FastAPI、Vue 设计可移植；manage.py 与当前全量验收入口明确只在 Windows 验证，不能据此宣称 Ubuntu 验收通过。

## 验证

```powershell
dashboard/backend/.venv/Scripts/python.exe -m pytest dashboard/backend/tests -q
npm --prefix dashboard/frontend run test
npm --prefix dashboard/frontend run build
dashboard/backend/.venv/Scripts/python.exe dashboard/verify_phase5.py
```

完整 Gate 要求 5173、18765 未被占用，系统 Microsoft Edge、Docker Linux Engine、项目 JDK 17 及已有 VULN-002 MySQL 环境。Gate 的 API/浏览器测试使用唯一 artifacts/phase5/<run_id>/integration.sqlite3，真实数据只从 Phase 4 读取；测试状态变更、修复声明及未定复测不会污染演示库。单元测试的异常/未来复测输入明确标为 synthetic，位于 pytest 独立临时目录，不作为扫描事实、演示数据或真实修复结论。


模型、API、生命周期及限制见 [数据契约](docs/contract.md)，正式验收记录见 [Phase 5 验收](../docs/validation/phase5-validation.md)。
