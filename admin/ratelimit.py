"""登录防爆破：基于客户端 IP 的失败窗口计数 + 临时锁定。

- 优先用 Redis（多进程/多实例共享计数）；连不上则退回进程内内存计数。
- 支持反向代理：取 X-Forwarded-For 第一个 IP，否则取直连 IP。
- 超出阈值后锁定一段时间，期间直接返回 429（带 Retry-After）。
"""
from __future__ import annotations

import time
from threading import Lock
from typing import Optional

from admin.config import settings

try:
    import redis as _redis_mod

    _redis = _redis_mod.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    _redis.ping()
    _USE_REDIS = True
except Exception:  # pragma: no cover - 降级到内存
    _redis = None
    _USE_REDIS = False

_lock = Lock()
_memory_fails: dict[str, list[float]] = {}  # ip -> 失败时间戳列表
_memory_locked: dict[str, float] = {}       # ip -> 锁定到期时间戳


def get_client_ip(forwarded_for: Optional[str], direct_ip: Optional[str]) -> str:
    """取真实客户端 IP：反向代理场景用 X-Forwarded-For 首段。"""
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return direct_ip or "unknown"


def is_locked(ip: str) -> tuple[bool, int]:
    """返回 (是否处于锁定中, 还需等待的秒数)。"""
    if _USE_REDIS:
        ttl = _redis.ttl(f"wb:login:lock:{ip}")
        if ttl and ttl > 0:
            return True, int(ttl)
        return False, 0
    now = time.time()
    until = _memory_locked.get(ip, 0.0)
    if until > now:
        return True, int(until - now)
    return False, 0


def record_failure(ip: str) -> None:
    """记录一次失败登录；超过阈值则锁定。"""
    if _USE_REDIS:
        key = f"wb:login:fail:{ip}"
        cnt = _redis.incr(key)
        if cnt == 1:
            _redis.expire(key, settings.LOGIN_WINDOW_SECONDS)
        if cnt >= settings.LOGIN_MAX_ATTEMPTS:
            _redis.set(f"wb:login:lock:{ip}", "1", ex=settings.LOGIN_LOCK_SECONDS)
        return
    with _lock:
        now = time.time()
        fails = [t for t in _memory_fails.get(ip, []) if now - t < settings.LOGIN_WINDOW_SECONDS]
        fails.append(now)
        _memory_fails[ip] = fails
        if len(fails) >= settings.LOGIN_MAX_ATTEMPTS:
            _memory_locked[ip] = now + settings.LOGIN_LOCK_SECONDS


def clear_failures(ip: str) -> None:
    """登录成功后清空该 IP 的失败计数与锁定。"""
    if _USE_REDIS:
        _redis.delete(f"wb:login:fail:{ip}", f"wb:login:lock:{ip}")
        return
    with _lock:
        _memory_fails.pop(ip, None)
        _memory_locked.pop(ip, None)
