"""Start/stop only this dashboard's recorded processes; reset requires stopped service."""
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/dashboard"
STATE = OUT / "services.json"
PYTHON = ROOT / "dashboard/backend/.venv/Scripts/python.exe"
VITE = ROOT / "dashboard/frontend/node_modules/vite/bin/vite.js"
BACKEND_PORT = 8000


def live(pid, script):
    # Validate the absolute executable/script command and PID before terminating anything.
    command = f"$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {int(pid)}'; if ($p) {{ $p.CommandLine }}"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("无法校验记录的进程；未终止任何进程")
    return str(script) in result.stdout


def stop():
    if not STATE.exists():
        print("Dashboard 没有记录的运行进程")
        return
    state = json.loads(STATE.read_text())
    expected = {"backend": ROOT / "dashboard/backend/serve.py", "frontend": VITE}
    for name, script in expected.items():
        if name not in state:
            continue
        pid = state[name]["pid"]
        if live(pid, script):
            # One shell end-to-end and validated recorded PID; no broad process matching.
            subprocess.run(["powershell.exe", "-NoProfile", "-Command", f"Stop-Process -Id {int(pid)} -ErrorAction Stop"], check=True)
            print(f"停止 {name} pid={pid}")
        else:
            print(f"{name} 已停止或 PID 不再属于 Dashboard，未执行终止")
    STATE.unlink()


def start():
    if STATE.exists():
        state = json.loads(STATE.read_text())
        scripts = {"backend": ROOT / "dashboard/backend/serve.py", "frontend": VITE}
        if any(live(v["pid"], scripts[name]) for name, v in state.items() if name in scripts):
            raise RuntimeError("Dashboard 已运行或仅部分运行，请先 stop")
    OUT.mkdir(parents=True, exist_ok=True)
    for port in (BACKEND_PORT, 5173):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    env = dict(os.environ, DASHBOARD_DB=str(OUT / "dashboard.sqlite3"),
               DASHBOARD_IMPORT_ROOT=str(ROOT / "artifacts/phase4"), DASHBOARD_API=f"http://127.0.0.1:{BACKEND_PORT}")
    commands = {"backend": [str(PYTHON), str(ROOT / "dashboard/backend/serve.py"), "--port", str(BACKEND_PORT)],
                "frontend": [shutil.which("node"), str(VITE), "--host", "127.0.0.1", "--port", "5173", "--strictPort"]}
    state = {}
    processes = []
    try:
        for name, command in commands.items():
            script = ROOT / "dashboard/backend/serve.py" if name == "backend" else VITE
            with (OUT / f"{name}-{stamp}.log").open("w", encoding="utf-8") as log:
                process = subprocess.Popen(command, cwd=ROOT if name == "backend" else ROOT / "dashboard/frontend",
                                           env=env, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                           creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
            state[name] = {"pid": process.pid, "script": str(script)}
            processes.append(process)
            STATE.write_text(json.dumps(state), encoding="utf-8")
        for url in (f"http://127.0.0.1:{BACKEND_PORT}/api/health", "http://127.0.0.1:5173/api/health"):
            for _ in range(100):
                try:
                    with urlopen(url, timeout=2) as response:
                        if json.load(response)["status"] == "UP":
                            if any(process.poll() is not None for process in processes):
                                raise RuntimeError("记录的服务进程已退出")
                            break
                except Exception:
                    pass
                time.sleep(.2)
            else:
                raise RuntimeError("服务启动失败，已保存日志")
        print(f"FastAPI http://127.0.0.1:{BACKEND_PORT} | Vue http://127.0.0.1:5173")
    except Exception:
        # Only recorded processes with exact script checks may be stopped.
        for name, entry in state.items():
            if live(entry["pid"], Path(entry["script"])):
                subprocess.run(["powershell.exe", "-NoProfile", "-Command", f"Stop-Process -Id {entry['pid']}"])
        STATE.unlink(missing_ok=True)
        raise


def reset():
    if STATE.exists():
        raise RuntimeError("先停止 Dashboard，再备份重置数据库")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", BACKEND_PORT))
    database = (OUT / "dashboard.sqlite3").resolve()
    if not database.is_relative_to(OUT.resolve()):
        raise RuntimeError("重置路径越界")
    if database.exists():
        if Path(str(database) + "-journal").exists():
            raise RuntimeError("数据库含未恢复的事务日志，请先正常启动并停止服务")
        destination = OUT / ("dashboard-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + ".sqlite3.backup")
        database.rename(destination)
        print("旧数据库已备份，下一次启动将初始化空库：" + str(destination))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start", "stop", "reset"])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        if not 1 <= args.port <= 65535:
            raise RuntimeError("端口必须为 1–65535")
        BACKEND_PORT = args.port
        if sys.platform != "win32":
            raise RuntimeError("进程管理入口目前只验证 Windows；Linux 请按 README 前台启动")
        {"start": start, "stop": stop, "reset": reset}[args.action]()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
