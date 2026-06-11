"""Security middleware: CORS, rate limiting, API key auth, security headers."""

import os
import time
from collections import defaultdict
from collections.abc import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication middleware.

    If CVS_API_KEY environment variable is set, all /api/ endpoints
    (except /api/health) require the key in the X-API-Key header.
    When CVS_API_KEY is not set, auth is disabled (dev mode).
    """

    def __init__(self, app):
        super().__init__(app)
        self._api_key = os.environ.get("CVS_API_KEY", "")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._api_key:
            # No key configured — skip auth (dev mode)
            return await call_next(request)

        path = request.url.path
        # Skip auth for health, docs, and non-API paths
        if not path.startswith("/api/") or path == "/api/health":
            return await call_next(request)

        provided_key = request.headers.get("X-API-Key", "")
        if provided_key != self._api_key:
            return Response(
                content='{"detail": "Invalid or missing API key"}',
                status_code=401,
                media_type="application/json",
            )

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limiter per IP address with configurable limits."""

    def __init__(self, app, requests_per_minute: int = 30, scan_requests_per_minute: int = 5):
        super().__init__(app)
        self._requests_per_minute = requests_per_minute
        self._scan_rpm = scan_requests_per_minute
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._scan_requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60

        # Stricter limit for scan uploads
        if request.url.path == "/api/scan" and request.method == "POST":
            self._scan_requests[client_ip] = [
                t for t in self._scan_requests[client_ip] if t > window_start
            ]
            if len(self._scan_requests[client_ip]) >= self._scan_rpm:
                return Response(
                    content='{"detail": "Scan rate limit exceeded. Max 5 scans per minute."}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "60"},
                )
            self._scan_requests[client_ip].append(now)

        # General rate limit
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > window_start
        ]

        if len(self._requests[client_ip]) >= self._requests_per_minute:
            return Response(
                content='{"detail": "Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        self._requests[client_ip].append(now)
        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response


def setup_security(app: FastAPI, allowed_origins: list[str] | None = None) -> None:
    """Configure all security middleware on the FastAPI app."""
    origins = allowed_origins or ["http://localhost:5173", "http://localhost:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*", "X-API-Key"],
    )

    app.add_middleware(APIKeyMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=60, scan_requests_per_minute=5)
    app.add_middleware(SecurityHeadersMiddleware)
