"""Тесты серверной части (модуль 2). Запуск: python -m pytest

Внешние сервисы подменяются через httpx.MockTransport, поэтому тесты не ходят в интернет.
Образцы ответов в tests/fixtures сняты с настоящих сервисов (список утечек сокращён).
"""
import json
import logging
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import leaks
from backend.main import create_app
from backend.ratelimit import KeyHasher, SlidingWindowLimiter, TTLCache

FIX = Path(__file__).parent / "fixtures"
SECRET_EMAIL = "very.secret.person@example.org"


def fx(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def make_client(handler):
    """httpx-клиент, который вместо сети вызывает handler(request) -> httpx.Response."""
    calls = []

    def wrapper(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(wrapper))
    client.calls = calls
    return client


def both_ok(xon="xon_found.json", lc="leakcheck_found.json"):
    def handler(request):
        if request.url.host == "api.xposedornot.com":
            return httpx.Response(200, json=fx(xon))
        return httpx.Response(200, json=fx(lc))
    return handler


# ---------- проверка адреса ----------
@pytest.mark.parametrize("raw,expected", [("  User@Example.COM ", "user@example.com"), ("a.b+c@sub.example.org", "a.b+c@sub.example.org")])
def test_validate_email_ok(raw, expected):
    assert leaks.validate_email(raw) == expected


@pytest.mark.parametrize("raw", ["", "no-at-sign", "a@b", "a@@b.com", "a b@c.com", "x@y.c", "a" * 300 + "@x.com", None])
def test_validate_email_bad(raw):
    with pytest.raises(ValueError):
        leaks.validate_email(raw)


# ---------- нормализация ответов ----------
def test_normalize_xon_found():
    r = leaks.normalize_xon(fx("xon_found.json"))
    assert r["status"] == "found" and r["source"] == "xposedornot" and r["count"] == 4
    assert [b["year"] for b in r["breaches"]] == [2026, 2026, 2016, 2011]  # новые сверху
    assert r["exposedPasswords"] is True and r["exposedPhones"] is True
    names = {c["name"] for c in r["dataClassCounts"]}
    assert {"Passwords", "Phone numbers", "Email addresses"} <= names
    web = next(b for b in r["breaches"] if b["name"] == "WebHostingTalk")
    assert "Passwords" in web["dataClasses"] and web["passwordRisk"] == "easytocrack"
    assert r["riskLabel"] == "Critical"


def test_normalize_xon_clean_when_fields_are_null():
    r = leaks.normalize_xon(fx("xon_clean.json"))
    assert r["status"] == "clean" and r["count"] == 0 and r["breaches"] == []
    assert r["exposedPasswords"] is False and r["exposedPhones"] is False


def test_normalize_leakcheck_found_and_clean():
    r = leaks.normalize_leakcheck(fx("leakcheck_found.json"))
    assert r["status"] == "found" and r["source"] == "leakcheck"
    assert r["count"] == 1648 and len(r["breaches"]) == 6  # count — всего, breaches — сколько прислано
    assert r["exposedPasswords"] is True and r["exposedPhones"] is True
    clean = leaks.normalize_leakcheck(fx("leakcheck_clean.json"))
    assert clean["status"] == "clean" and clean["count"] == 0


def test_normalize_leakcheck_real_error_is_not_clean():
    with pytest.raises(leaks.UpstreamError):
        leaks.normalize_leakcheck({"success": False, "error": "Limit reached"})


def test_breaches_are_capped():
    data = {"ExposedBreaches": {"breaches_details": [{"breach": f"B{i}", "xposed_date": "2020", "xposed_data": "Passwords"} for i in range(80)]}}
    r = leaks.normalize_xon(data)
    assert r["count"] == 80 and len(r["breaches"]) == leaks.MAX_BREACHES


# ---------- lookup: основной и резервный источник ----------
async def run(handler, email="a@example.com"):
    client = make_client(handler)
    result = await leaks.lookup(email, client)
    await client.aclose()
    return result, client.calls


@pytest.mark.anyio
async def test_lookup_uses_xon_and_skips_leakcheck_when_answered():
    result, calls = await run(both_ok())
    assert result["source"] == "xposedornot"
    assert len(calls) == 1 and "xposedornot" in calls[0]


@pytest.mark.anyio
async def test_lookup_clean_from_xon_does_not_query_second_service():
    result, calls = await run(both_ok(xon="xon_clean.json"))
    assert result["status"] == "clean" and len(calls) == 1


@pytest.mark.anyio
async def test_lookup_falls_back_to_leakcheck_on_429():
    def handler(request):
        if request.url.host == "api.xposedornot.com":
            return httpx.Response(429, json={"detail": "too many"})
        return httpx.Response(200, json=fx("leakcheck_found.json"))
    result, calls = await run(handler)
    assert result["source"] == "leakcheck" and result["status"] == "found" and len(calls) == 2


@pytest.mark.anyio
async def test_lookup_both_down_is_error_not_clean():
    def handler(request):
        raise httpx.ConnectError("offline")
    result, _ = await run(handler)
    assert result["status"] == "error" and result["count"] is None and result["message"]


@pytest.mark.anyio
async def test_lookup_garbage_json_is_error():
    result, _ = await run(lambda request: httpx.Response(200, content=b"<html>not json</html>"))
    assert result["status"] == "error"


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------- ограничитель и кеш ----------
def test_limiter_blocks_then_recovers():
    now = [0.0]
    lim = SlidingWindowLimiter(limit=3, window=60, clock=lambda: now[0])
    assert all(lim.allow("ip")[0] for _ in range(3))
    ok, retry = lim.allow("ip")
    assert not ok and 1 <= retry <= 61
    assert lim.allow("other")[0]  # другой ключ не затронут
    now[0] = 61
    assert lim.allow("ip")[0]


def test_ttl_cache_expires():
    now = [0.0]
    cache = TTLCache(ttl=10, clock=lambda: now[0])
    cache.set("k", {"v": 1})
    assert cache.get("k") == {"v": 1}
    now[0] = 11
    assert cache.get("k") is None


def test_key_hasher_is_stable_within_process_and_not_the_email():
    h = KeyHasher()
    assert h("a@b.com") == h("a@b.com") != h("c@d.com")
    assert "a@b.com" not in h("a@b.com")
    assert KeyHasher()("a@b.com") != h("a@b.com")  # новый секрет — новые ключи


# ---------- HTTP-интерфейс ----------
def make_app(handler=None, **kw):
    client = make_client(handler or both_ok())
    app = create_app(http_client=client, **kw)
    return app, client


def test_api_email_found_has_security_headers_and_no_store():
    app, upstream = make_app()
    with TestClient(app) as c:
        r = c.post("/api/email", json={"email": "someone@example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "found" and body["cached"] is False and body["exposedPasswords"] is True
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "someone@example.com" not in r.text  # адрес в ответе не повторяется


def test_api_email_second_request_comes_from_cache():
    app, upstream = make_app()
    with TestClient(app) as c:
        first = c.post("/api/email", json={"email": "cache@example.com"}).json()
        second = c.post("/api/email", json={"email": "CACHE@example.com "}).json()  # тот же адрес в другой записи
    assert first["cached"] is False and second["cached"] is True
    assert len(upstream.calls) == 1


def test_api_email_errors_are_not_cached():
    state = {"fail": True}

    def handler(request):
        if state["fail"]:
            raise httpx.ConnectError("offline")
        return httpx.Response(200, json=fx("xon_clean.json"))

    app, upstream = make_app(handler)
    with TestClient(app) as c:
        assert c.post("/api/email", json={"email": "x@example.com"}).json()["status"] == "error"
        state["fail"] = False
        assert c.post("/api/email", json={"email": "x@example.com"}).json()["status"] == "clean"


def test_api_email_validation():
    app, _ = make_app()
    with TestClient(app) as c:
        bad = c.post("/api/email", json={"email": "not-an-email"})
        assert bad.status_code == 422 and bad.json()["status"] == "error"
        assert c.post("/api/email", json={}).status_code == 422
        assert c.post("/api/email", json={"email": "a" * 400 + "@x.com"}).status_code == 422
        assert c.post("/api/email", content=b"garbage").status_code == 422


def test_api_email_rate_limit():
    app, _ = make_app(rate_limit=3)
    with TestClient(app) as c:
        codes = [c.post("/api/email", json={"email": f"u{i}@example.com"}).status_code for i in range(5)]
        last = c.post("/api/email", json={"email": "u9@example.com"})
    assert codes == [200, 200, 200, 429, 429]
    assert last.json()["status"] == "error" and "Retry-After" in last.headers


def test_email_is_never_written_to_logs(caplog):
    app, _ = make_app()
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as c:
            c.post("/api/email", json={"email": SECRET_EMAIL})
    assert SECRET_EMAIL not in caplog.text


def test_site_is_served_with_correct_mime_types():
    app, _ = make_app()
    with TestClient(app) as c:
        index = c.get("/")
        js = c.get("/js/app.js")
        css = c.get("/css/style.css")
        health = c.get("/api/health")
    assert index.status_code == 200 and "CredAudit" in index.text
    assert "javascript" in js.headers["content-type"]
    assert "text/css" in css.headers["content-type"]
    assert health.json() == {"status": "ok"}
    assert "content-security-policy" in index.headers
