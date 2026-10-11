"""CSRF protection middleware using the double-submit cookie pattern.

The middleware:
1. Sets a ``_csrf_token`` cookie containing a random token on every response.
2. Bootstraps a readable CSRF cookie on safe requests so JavaScript can echo it in a header.
3. Rejects missing or mismatched tokens for non-bearer state-changing requests.

CSRF tokens are accessible to same-origin JavaScript so that the SPA can send
them in a custom header. SameSite=Strict helps block cross-site requests; do
not use the token cookie as an authentication credential.

NOTE: This only protects state-changing HTTP methods (POST, PUT, DELETE,
PATCH).  Safe methods (GET, HEAD, OPTIONS) are not checked.
"""

from __future__ import annotations

import logging
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# Methods that change server state and must be protected.
_STATE_CHANGE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Exempt paths that should never require CSRF tokens (public APIs, health, etc.).
_CSRF_EXEMPT_PATHS = frozenset(
    {
        "/health",
        "/healthz",
        "/metrics-lite",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh",
        "/api/auth/forgot-access",
        "/ws/quotes",
        "/ws/alerts",
        "/ws/us-quotes",
        "/ws/depth",
    }
)


def _should_skip_csrf(path: str, method: str, has_api_key: bool = False) -> bool:
    """Return True if CSRF validation should be skipped for this request."""
    if method not in _STATE_CHANGE_METHODS:
        return True
    if path in _CSRF_EXEMPT_PATHS:
        return True
    # CSRF defends against ambient credentials (cookies) being replayed from a
    # third-party page. An X-API-Key header is never attached automatically by a
    # browser, so key-authenticated calls have nothing to forge.
    if has_api_key:
        return True
    return False


class CsrfProtectMiddleware(BaseHTTPMiddleware):
    """Double-submit CSRF cookie middleware."""

    # Cookie options -- Secure is appropriate for production; for development
    # on localhost we relax it so developers don't hit SSL issues.
    _COOKIE_NAME = "_csrf_token"
    _HEADER_NAME = "X-CSRF-Token"
    _COOKIE_MAX_AGE = 86400  # 24 hours

    async def dispatch(self, request: Request, call_next) -> Response:
        authorization = request.headers.get("Authorization", "")
        # Explicit Bearer or API-key credentials are not automatically attached
        # by browsers, unlike ambient cookie authentication.
        has_bearer = authorization.lower().startswith("bearer ")
        if _should_skip_csrf(
            request.url.path, request.method,
            bool(request.headers.get("X-API-Key")) or has_bearer,
        ):
            response = await call_next(request)
            # A safe request initializes the double-submit cookie before the
            # first protected write. The SPA reads it via document.cookie.
            if request.method in {"GET", "HEAD"} and not request.cookies.get(self._COOKIE_NAME):
                self._set_cookie(response)
            return response

        # Read the token from the header.
        header_token = request.headers.get(self._HEADER_NAME)

        # Read the token from the cookie.
        cookie_token = request.cookies.get(self._COOKIE_NAME)

        if not header_token or not cookie_token:
            logger.warning("CSRF token missing for %s %s", request.method, request.url.path)
            return JSONResponse({"detail": "CSRF token required"}, status_code=403)
        if not secrets.compare_digest(header_token, cookie_token):
            logger.warning("CSRF token mismatch for %s %s", request.method, request.url.path)
            return JSONResponse({"detail": "CSRF token mismatch"}, status_code=403)
        return await call_next(request)

    def _set_cookie(self, response: Response) -> None:
        response.set_cookie(
            key=self._COOKIE_NAME,
            value=secrets.token_hex(32),
            httponly=False,  # SPA must read the token to set X-CSRF-Token.
            samesite="strict",
            path="/",
            max_age=self._COOKIE_MAX_AGE,
            secure=os.getenv("OPENTERMINALUI_ENV", "").strip().lower() not in {
                "dev", "development", "local", "test", "testing"
            },
        )
