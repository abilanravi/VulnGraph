"""In-memory fixed-window rate limiting for sensitive endpoints (login, signup, scan triggers).

This is intentionally a plain in-process dict, appropriate for VulnGraph's current single-instance
MVP deployment. It does NOT coordinate across multiple backend processes/instances — a
horizontally scaled deployment would need a shared store (e.g. Redis) instead. That is out of
scope for this milestone (see project docs); documented here so the tradeoff is explicit rather
than silently wrong under scale-out.
"""

import threading
import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request, status

from app.api.deps import get_current_active_user
from app.db.models import User

_lock = threading.Lock()
_hits: dict[str, list[float]] = defaultdict(list)


def _client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


def reset_rate_limits() -> None:
    """Test-only helper to clear state between test cases."""
    with _lock:
        _hits.clear()


def rate_limit(name: str, limit: int, window_seconds: int, by_ip_and_body_field: str | None = None):
    """Returns a FastAPI dependency that raises 429 once `limit` calls happen within
    `window_seconds` for the same key. The key is the client IP by default; pass
    `by_ip_and_body_field` to also key on a JSON body field (e.g. "email") so one abusive IP
    cannot exhaust the budget for every account it tries.
    """

    async def _dependency(request: Request) -> None:
        key_parts = [name, _client_ip(request)]
        if by_ip_and_body_field:
            try:
                body = await request.json()
                key_parts.append(str(body.get(by_ip_and_body_field, "")))
            except Exception:
                pass
        key = "|".join(key_parts)

        now = time.monotonic()
        with _lock:
            recent = [t for t in _hits[key] if now - t < window_seconds]
            if len(recent) >= limit:
                _hits[key] = recent
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                )
            recent.append(now)
            _hits[key] = recent

    return _dependency


def _check_and_record(key: str, limit: int, window_seconds: int) -> None:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _hits[key] if now - t < window_seconds]
        if len(recent) >= limit:
            _hits[key] = recent
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        recent.append(now)
        _hits[key] = recent


def user_rate_limit(name: str, limit: int, window_seconds: int):
    """Like `rate_limit`, but keys on the authenticated user's id rather than IP — appropriate
    for endpoints reached only after authentication (e.g. triggering a scan), where per-user
    budgeting is more meaningful than per-IP (users behind a shared NAT/proxy shouldn't share a
    budget; a single user switching IPs shouldn't escape one)."""

    def _dependency(current_user: User = Depends(get_current_active_user)) -> None:
        _check_and_record(f"{name}|{current_user.id}", limit, window_seconds)

    return _dependency
