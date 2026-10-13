import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote
from fastapi import HTTPException
from labscan.core import credentials, redact


def error(code, message):
    raise HTTPException(code, message)


def safe_path(base: Path, name: str):
    decoded = unquote(name).replace("\\", "/")
    parts = PurePosixPath(decoded).parts
    if (decoded != name or not parts or decoded.startswith("/") or ":" in decoded
            or PurePosixPath(decoded).as_posix() != decoded
            or any(p in ("..", ".") or p.startswith(".") for p in parts)):
        error(422, "非法文件引用")
    root = base.resolve()
    path = (root / decoded).resolve()
    if not path.is_relative_to(root):
        error(422, "文件引用超出允许目录")
    return path


def sanitize(value):
    value = redact(value, credentials())
    if isinstance(value, str):
        value = re.sub(r'''(?i)((?:password|passwd|token|secret|session|api[_-]?key)\s*[=:]\s*)(["'])(.*?)\2''',
                       r"\1[REDACTED]", value)
        value = re.sub(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b", "[REDACTED]", value)
        value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", value)
        value = re.sub(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED]", value)
        value = re.sub(r"[A-Za-z]:[\\/](?:Users|home)[\\/][^\s\"<>]+", "[LOCAL PATH]", value)
        return value
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    return value


def preview(content):
    text = content.decode("utf-8", errors="replace")
    try:
        text = json.dumps(sanitize(json.loads(text)), ensure_ascii=False, indent=2)
    except (ValueError, RecursionError):
        text = sanitize(text)
    return text[:65536], len(text) > 65536
