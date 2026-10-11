from __future__ import annotations

import secrets

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.auth.csrf import (
    CsrfProtectMiddleware,
    _CSRF_EXEMPT_PATHS,
    _STATE_CHANGE_METHODS,
    _should_skip_csrf,
)


def app_with_csrf() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CsrfProtectMiddleware)

    @app.get("/bootstrap")
    def bootstrap():
        return {"ok": True}

    @app.post("/write")
    def write():
        return {"ok": True}

    @app.post("/api/auth/login")
    def login():
        return {"ok": True}

    return app


def test_matching_tokens_pass():
    token = secrets.token_hex(32)
    client = TestClient(app_with_csrf())
    response = client.post("/write", headers={"X-CSRF-Token": token}, cookies={"_csrf_token": token})
    assert response.status_code == 200


def test_missing_header_is_rejected():
    client = TestClient(app_with_csrf())
    response = client.post("/write", cookies={"_csrf_token": "cookie"})
    assert response.status_code == 403


def test_missing_cookie_is_rejected():
    client = TestClient(app_with_csrf())
    response = client.post("/write", headers={"X-CSRF-Token": "header"})
    assert response.status_code == 403


def test_both_missing_are_rejected():
    client = TestClient(app_with_csrf())
    response = client.post("/write")
    assert response.status_code == 403


def test_mismatch_is_rejected():
    client = TestClient(app_with_csrf())
    response = client.post("/write", headers={"X-CSRF-Token": "wrong"}, cookies={"_csrf_token": "correct"})
    assert response.status_code == 403


def test_safe_request_bootstraps_cookie_and_write_works():
    client = TestClient(app_with_csrf())
    response = client.get("/bootstrap")
    assert response.status_code == 200
    token = client.cookies.get("_csrf_token")
    assert token
    assert "httponly" not in response.headers["set-cookie"].lower()
    write = client.post("/write", headers={"X-CSRF-Token": token})
    assert write.status_code == 200
    # Do not invalidate the cookie after every write; avoid breaking parallel SPA requests.
    assert client.cookies.get("_csrf_token") == token


def test_explicit_bearer_token_skips_csrf():
    client = TestClient(app_with_csrf())
    response = client.post("/write", headers={"Authorization": "Bearer example"})
    assert response.status_code == 200


def test_explicit_api_key_skips_csrf():
    client = TestClient(app_with_csrf())
    response = client.post("/write", headers={"X-API-Key": "example"})
    assert response.status_code == 200


def test_exempt_routes():
    client = TestClient(app_with_csrf())
    assert client.post("/api/auth/login").status_code == 200
    assert "/health" in _CSRF_EXEMPT_PATHS
    for method in ["GET", "HEAD", "OPTIONS"]:
        assert _should_skip_csrf("/api/test", method)
    for method in ["POST", "PUT", "DELETE", "PATCH"]:
        assert not _should_skip_csrf("/api/test", method)
    assert "GET" not in _STATE_CHANGE_METHODS
