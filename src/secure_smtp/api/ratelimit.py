"""
Sliding-Window In-Memory Rate Limiting — Secure SMTP.

Provides high-performance, thread-safe rate limiting without external Redis dependencies.
Enforces per-endpoint and per-client request quotas with standard HTTP 429 and Retry-After headers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, Response, status

from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self, cleanup_interval: int = 300) -> None:
        self.cleanup_interval = cleanup_interval
        self._history: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

    def _get_client_key(self, request: Request, scope_name: str) -> str:
        """Derive rate-limit bucket key from client IP / X-Forwarded-For and endpoint scope."""
        # Uvicorn may normalize this via explicitly trusted proxies. Never parse
        # a raw forwarding header supplied by the caller here.
        ip = request.client.host if request.client else "unknown"

        return f"{ip}:{scope_name}"

    async def check(
        self,
        request: Request,
        scope_name: str,
        max_requests: Optional[int] = None,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, int]:
        """
        Evaluate if the incoming request is within quota.

        Returns:
            Tuple[bool, int, int]: (allowed, remaining_quota, retry_after_seconds)
        """
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return True, 9999, 0

        limit = max_requests if max_requests is not None else settings.rate_limit_rpm
        key = self._get_client_key(request, scope_name)
        now = time.monotonic()

        async with self._lock:
            # Perform periodic cleanup of stale buckets
            if now - self._last_cleanup > self.cleanup_interval:
                self._cleanup(now)
                self._last_cleanup = now

            timestamps = self._history[key]
            cutoff = now - window_seconds
            # Keep only hits within the active sliding window
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._history[key] = valid_timestamps

            if len(valid_timestamps) >= limit:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(window_seconds - (now - oldest)))
                return False, 0, retry_after

            # Register hit
            valid_timestamps.append(now)
            remaining = max(0, limit - len(valid_timestamps))
            return True, remaining, 0

    def _cleanup(self, now: float) -> None:
        """Purge idle keys older than 5 minutes to prevent memory leaks."""
        cutoff = now - 300.0
        stale_keys = [k for k, v in self._history.items() if not v or v[-1] < cutoff]
        for k in stale_keys:
            del self._history[k]

    def reset(self) -> None:
        """Clear all rate limiting history (used primarily for test isolation)."""
        self._history.clear()


_rate_limiter: Optional[SlidingWindowRateLimiter] = None


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Retrieve the global singleton rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = SlidingWindowRateLimiter()
    return _rate_limiter


def rate_limit(max_requests: int = 60, window_seconds: int = 60, scope: Optional[str] = None):
    """
    FastAPI dependency factory enforcing rate limits on specific endpoints.

    Attaches standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining)
    and raises HTTP 429 with Retry-After when quotas are breached.
    """
    async def dependency(request: Request, response: Response):
        scope_name = scope or request.url.path
        limiter = get_rate_limiter()
        allowed, remaining, retry_after = await limiter.check(
            request=request,
            scope_name=scope_name,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        if not allowed:
            response.headers["Retry-After"] = str(retry_after)
            logger.warning(
                "Rate limit exceeded for client %s on %s (limit: %d/%ds)",
                request.client.host if request.client else "unknown",
                scope_name,
                max_requests,
                window_seconds,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )

    return dependency
