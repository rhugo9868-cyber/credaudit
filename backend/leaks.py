"""Модуль 2. Проверка e-mail по базам утечек.

Основной источник — XposedOrNot (бесплатный API без ключа), резервный — LeakCheck Public API.
Оба ответа приводятся к одному формату (см. normalize_*), чтобы сайт не зависел от источника.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional

import httpx

XON_URL = "https://api.xposedornot.com/v1/breach-analytics"
LEAKCHECK_URL = "https://leakcheck.io/api/public"
USER_AGENT = "CredAudit/0.1 (student project)"
MAX_BREACHES = 50  # сколько утечек отдаём сайту; общее число передаётся в поле count

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,251}\.[^@\s.]{2,}$")


class UpstreamError(Exception):
    """Сервис утечек не ответил или ответил неожиданно. Текст можно показывать пользователю."""


def validate_email(raw: str) -> str:
    """Возвращает адрес в нижнем регистре или поднимает ValueError."""
    email = (raw or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise ValueError("Введите корректный адрес электронной почты")
    return email


def split_classes(value: Optional[str]) -> List[str]:
    """'Email addresses;Passwords' -> ['Email addresses', 'Passwords']"""
    return [x.strip() for x in (value or "").split(";") if x.strip()]


def _year(value: Any) -> Optional[int]:
    m = re.match(r"\s*(\d{4})", str(value or ""))
    return int(m.group(1)) if m else None


def _summary(breaches: List[Dict[str, Any]], total: int, source: str, classes: Counter, risk: Optional[str]) -> Dict[str, Any]:
    names = {name.lower() for name in classes}
    return {
        "status": "found" if total > 0 else "clean",
        "source": source,
        "count": total,
        "breaches": breaches[:MAX_BREACHES],
        "exposedPasswords": any("password" in n for n in names),
        "exposedPhones": any("phone" in n for n in names),
        "dataClassCounts": [{"name": n, "count": c} for n, c in classes.most_common(12)],
        "riskLabel": risk,
        "message": None,
    }


def normalize_xon(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ответ XposedOrNot breach-analytics. Если адрес не найден, поля равны null."""
    exposed = (data or {}).get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") or []
    breaches: List[Dict[str, Any]] = []
    classes: Counter = Counter()
    for item in details:
        cls = split_classes(item.get("xposed_data"))
        classes.update(cls)
        breaches.append(
            {
                "name": item.get("breach") or "Без названия",
                "year": _year(item.get("xposed_date")),
                "domain": item.get("domain") or None,
                "dataClasses": cls,
                "records": item.get("xposed_records"),
                "passwordRisk": (item.get("password_risk") or "").lower() or None,
            }
        )
    breaches.sort(key=lambda b: (b["year"] or 0), reverse=True)
    risk_list = ((data or {}).get("BreachMetrics") or {}).get("risk") or []
    risk = risk_list[0].get("risk_label") if risk_list else None
    return _summary(breaches, len(breaches), "xposedornot", classes, risk)


def normalize_leakcheck(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ответ LeakCheck Public API. Список полей общий для всех утечек, по каждой утечке он неизвестен."""
    data = data or {}
    if data.get("success") is False:
        if str(data.get("error", "")).lower() == "not found":
            return _summary([], 0, "leakcheck", Counter(), None)
        raise UpstreamError("Сервис LeakCheck вернул ошибку: %s" % (data.get("error") or "неизвестная ошибка"))
    sources = data.get("sources") or []
    breaches = [
        {
            "name": s.get("name") or "Без названия",
            "year": _year(s.get("date")),
            "domain": None,
            "dataClasses": [],
            "records": None,
            "passwordRisk": None,
        }
        for s in sources
    ]
    breaches.sort(key=lambda b: (b["year"] or 0), reverse=True)
    fields = Counter({str(f): 0 for f in (data.get("fields") or [])})
    total = int(data.get("found") or len(breaches))
    result = _summary(breaches, total, "leakcheck", fields, None)
    # по LeakCheck счётчики классов неизвестны, оставляем только названия
    result["dataClassCounts"] = [{"name": n, "count": None} for n in sorted(fields)]
    result["exposedPasswords"] = "password" in {f.lower() for f in fields}
    result["exposedPhones"] = "phone" in {f.lower() for f in fields}
    return result


async def _get_json(client: httpx.AsyncClient, url: str, params: Dict[str, str]) -> Dict[str, Any]:
    try:
        resp = await client.get(url, params=params, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    except httpx.TimeoutException:
        raise UpstreamError("Сервис проверки не ответил вовремя")
    except httpx.HTTPError:
        raise UpstreamError("Не удалось связаться с сервисом проверки")
    if resp.status_code == 429:
        raise UpstreamError("Достигнут лимит запросов к сервису проверки, повторите позже")
    if resp.status_code != 200:
        raise UpstreamError("Сервис проверки ответил кодом %d" % resp.status_code)
    try:
        payload = resp.json()
    except ValueError:
        raise UpstreamError("Сервис проверки вернул непонятный ответ")
    if not isinstance(payload, dict):
        raise UpstreamError("Сервис проверки вернул непонятный ответ")
    return payload


async def lookup(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Ищет адрес в XposedOrNot, при сбое — в LeakCheck. Возвращает нормализованный результат.

    Если не отвечают оба сервиса, возвращается status='error' (а не «чисто»: отсутствие ответа не значит отсутствие утечек).
    """
    errors: List[str] = []
    try:
        return normalize_xon(await _get_json(client, XON_URL, {"email": email}))
    except UpstreamError as e:
        errors.append(str(e))
    try:
        return normalize_leakcheck(await _get_json(client, LEAKCHECK_URL, {"check": email}))
    except UpstreamError as e:
        errors.append(str(e))
    return {
        "status": "error",
        "source": None,
        "count": None,
        "breaches": [],
        "exposedPasswords": False,
        "exposedPhones": False,
        "dataClassCounts": [],
        "riskLabel": None,
        "message": "Не удалось проверить адрес. " + errors[0],
    }
