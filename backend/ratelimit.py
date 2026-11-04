"""Защита сервиса от злоупотреблений: ограничение частоты запросов и короткий кеш результатов."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Deque, Dict, Optional, Tuple


class SlidingWindowLimiter:
    """Не более `limit` запросов за `window` секунд с одного ключа (например, IP-адреса)."""

    def __init__(self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.monotonic, max_keys: int = 5000):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.max_keys = max_keys
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()

    def allow(self, key: str) -> Tuple[bool, int]:
        """Возвращает (разрешено, через сколько секунд повторить)."""
        now = self.clock()
        hits = self._hits.get(key)
        if hits is None:
            hits = deque()
            self._hits[key] = hits
            while len(self._hits) > self.max_keys:  # память ограничена
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False, max(1, int(self.window - (now - hits[0])) + 1)
        hits.append(now)
        return True, 0


class TTLCache:
    """Небольшой кеш в памяти: бережёт лимиты внешнего сервиса (у XposedOrNot их всего 25 в час)."""

    def __init__(self, ttl: float, max_items: int = 500, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl
        self.max_items = max_items
        self.clock = clock
        self._data: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if self.clock() >= expires:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._data[key] = (self.clock() + self.ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)


class KeyHasher:
    """Ключ кеша — HMAC адреса со случайным секретом, созданным при запуске.

    Сам адрес в памяти и в логах не хранится; после перезапуска сервера прежние ключи не воспроизвести.
    """

    def __init__(self, secret: Optional[bytes] = None):
        self._secret = secret or os.urandom(32)

    def __call__(self, value: str) -> str:
        return hmac.new(self._secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
