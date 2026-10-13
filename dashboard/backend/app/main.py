"""No command execution routes. Single-user, loopback-only local service."""
from ipaddress import ip_address
import secrets
import sqlite3
from typing import Annotated, Literal
from urllib.parse import urlsplit
import uuid
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from .config import Settings
from .database import Database
from .importer import import_run
from .models import Associate, ChangeStatus, ImportRun, Note, Repair, Status, Verify
from .service import Service

Page = Annotated[int, Query(ge=1, le=100000)]
PageSize = Annotated[int, Query(ge=1, le=100)]


def create_app(settings=None):
    settings = settings or Settings.local()
    app = FastAPI(title="Java DevSecOps 本地 Dashboard", version="1.0.0", docs_url=None, redoc_url=None)
    db = Database(settings.database)
    service = Service(db)
    app.state.database = db
    app.state.csrf_token = secrets.token_urlsafe(32)

    def failure(request, status, code, message):
        return JSONResponse(status_code=status, content={"error": {"code": code, "message": message,
                            "request_id": getattr(request.state, "request_id", "unknown")}})

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        try:
            local = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        host = request.headers.get("host", "")
        try:
            url = urlsplit("http://" + host)
            valid_host = url.hostname in ("127.0.0.1", "localhost", "::1") and url.username is None and url.path == ""
            _ = url.port
        except ValueError:
            valid_host = False
        origin = request.headers.get("origin")
        allowed_origins = {"http://127.0.0.1:5173", "http://localhost:5173", "http://" + host}
        if not local or not valid_host or (origin and origin not in allowed_origins):
            return failure(request, 403, "LOCAL_ONLY", "仅允许可信来源的本机访问")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not secrets.compare_digest(request.headers.get("x-dashboard-token", ""), app.state.csrf_token):
                return failure(request, 403, "WRITE_FORBIDDEN", "写操作需要本机请求令牌")
            if not request.headers.get("content-type", "").startswith("application/json"):
                return failure(request, 415, "JSON_REQUIRED", "仅接受 JSON 写请求")
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return failure(request, 400, "INVALID_LENGTH", "无效请求长度")
        if length > 1024 * 1024:
            return failure(request, 413, "TOO_LARGE", "请求过大")
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                return failure(request, 413, "TOO_LARGE", "请求过大")
        request._body = bytes(data)
        try:
            response = await call_next(request)
        except Exception:
            response = failure(request, 500, "INTERNAL_ERROR", "服务内部错误；请核对本地日志")
        response.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                                 "X-Request-ID": request.state.request_id,
                                 "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return failure(request, exc.status_code, "REQUEST_REJECTED", str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo request bodies, paths, credentials or Pydantic input values.
        return failure(request, 422, "VALIDATION_ERROR", "输入参数不符合 API 契约")

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return failure(request, 503, "DATABASE_ERROR", "本地数据库操作失败")

    @app.get("/api/health")
    def health():
        with db.connect() as connection:
            connection.execute("SELECT 1")
        return {"status": "UP", "mode": "single-user-loopback", "schema_version": 1}

    @app.get("/api/session")
    def session():
        return {"write_token": app.state.csrf_token, "mode": "single-user-loopback"}

    @app.get("/api/summary")
    def summary():
        return service.stats()

    @app.get("/api/lifecycle")
    def lifecycle():
        from .models import TRANSITIONS
        return {"transitions": TRANSITIONS, "close_requires": "本轮最新的有证据修复复测结论；人工说明覆盖范围"}

    @app.get("/api/runs")
    def runs(page: Page = 1, page_size: PageSize = 20):
        return service.runs(page, page_size)

    @app.get("/api/runs/{run_id}")
    def run(run_id: str):
        return service.run(run_id)

    @app.post("/api/imports")
    def imports(body: ImportRun):
        return import_run(db, settings, body.run_id)

    @app.get("/api/findings")
    def findings(tool: Literal["semgrep", "codeql", "zap"] | None = None,
                 severity: Literal["critical", "high", "medium", "low", "informational"] | None = None,
                 status: Status | None = None, query: Annotated[str | None, Query(max_length=200)] = None,
                 sort: Literal["created_at", "updated_at", "severity"] = "updated_at",
                 order: Literal["asc", "desc"] = "desc", page: Page = 1, page_size: PageSize = 20):
        return service.findings(tool, severity, status.value if status else None, query, sort, order, page, page_size)

    @app.get("/api/findings/{fid}")
    def finding(fid: int):
        return service.detail(fid)

    @app.post("/api/findings/{fid}/status")
    def status(fid: int, body: ChangeStatus):
        return service.status(fid, body)

    @app.post("/api/findings/{fid}/notes")
    def note(fid: int, body: Note):
        return service.note(fid, body)

    @app.post("/api/findings/{fid}/repairs")
    def repair(fid: int, body: Repair):
        return service.repair(fid, body)

    @app.post("/api/findings/{fid}/verifications")
    def verification(fid: int, body: Verify):
        return service.verify(fid, body)

    @app.post("/api/findings/{fid}/associations")
    def associate(fid: int, body: Associate):
        return service.associate(fid, body)

    @app.get("/api/evidence/{eid}")
    def evidence(eid: int):
        return service.evidence(eid)

    return app
