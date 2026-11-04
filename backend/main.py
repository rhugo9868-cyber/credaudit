"""Серверная часть CredAudit (FastAPI).

Делает две вещи:
  1) POST /api/email — проверка e-mail по базам утечек (браузер не может ходить в эти сервисы сам из-за CORS
     и не должен: так можно ограничивать частоту запросов и кешировать ответы);
  2) раздаёт сам сайт (папка frontend), поэтому для запуска достаточно одного процесса.

Адрес e-mail не сохраняется и не пишется в журнал.
"""
from __future__ import annotations

import mimetypes
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .leaks import lookup, validate_email
from .ratelimit import KeyHasher, SlidingWindowLimiter, TTLCache

# На Windows реестр иногда сообщает для .js тип text/plain, и браузер отказывается грузить модули.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://api.pwnedpasswords.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class EmailIn(BaseModel):
    email: str = Field(max_length=254)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def create_app(
    rate_limit: Optional[int] = None,
    cache_ttl: Optional[int] = None,
    http_client: Optional[httpx.AsyncClient] = None,
    frontend_dir: Optional[Path] = None,
) -> FastAPI:
    rate_limit = rate_limit if rate_limit is not None else _env_int("CREDAUDIT_RATE_LIMIT_PER_MIN", 10)
    cache_ttl = cache_ttl if cache_ttl is not None else _env_int("CREDAUDIT_CACHE_TTL", 3600)
    trust_proxy = os.environ.get("CREDAUDIT_TRUST_PROXY") == "1"
    docs = os.environ.get("CREDAUDIT_DOCS") == "1"

    limiter = SlidingWindowLimiter(limit=rate_limit, window=60.0)
    cache = TTLCache(ttl=cache_ttl)
    hasher = KeyHasher()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owns_client = http_client is None
        app.state.http_client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(12.0), follow_redirects=False)
        try:
            yield
        finally:
            if owns_client:
                await app.state.http_client.aclose()

    app = FastAPI(
        title="CredAudit",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )

    origins = [o.strip() for o in os.environ.get("CREDAUDIT_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if origins:  # нужно только если сайт лежит на другом адресе, чем сервер
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def client_ip(request: Request) -> str:
        if trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def error(status: int, message: str, headers: Optional[dict] = None) -> JSONResponse:
        return JSONResponse({"status": "error", "message": message}, status_code=status, headers=headers)

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.post("/api/email")
    async def api_email(body: EmailIn, request: Request):
        allowed, retry_after = limiter.allow(client_ip(request))
        if not allowed:
            return error(429, "Слишком много запросов. Повторите через %d с." % retry_after, {"Retry-After": str(retry_after)})
        try:
            email = validate_email(body.email)
        except ValueError as e:
            return error(422, str(e))

        key = hasher(email)
        cached = cache.get(key)
        if cached is not None:
            return JSONResponse({**cached, "cached": True}, headers={"Cache-Control": "no-store"})

        result = await lookup(email, request.app.state.http_client)
        if result["status"] != "error":  # ошибки не кешируем, иначе сбой «залипнет»
            cache.set(key, result)
        return JSONResponse({**result, "cached": False}, headers={"Cache-Control": "no-store"})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):  # неверное тело запроса
        return error(422, "Некорректный запрос")

    site = frontend_dir or FRONTEND_DIR
    if site.is_dir():
        app.mount("/", StaticFiles(directory=str(site), html=True), name="site")
    return app


app = create_app()
