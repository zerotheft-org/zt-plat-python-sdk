"""
C2 — Missing/invalid JWT → HTTP 403, zero DB calls (Integration)

This is the HTTP-level proof that the middleware short-circuits BEFORE any
DB interaction when authentication fails. Phase 1 tests this with mocks;
this module proves it against a live CRDB engine.

Setup:
  - Real FastAPI app with TenantRLSMiddleware + RLS listener registered
  - Real CRDB engine from conftest (app_service_dev connection)
  - SQLAlchemy event listener counts every query that reaches the DB

Assertions:
  - HTTP 403 returned
  - Response body has error code and trace_id
  - DB query counter stays at ZERO for the entire request

This module does NOT need Keycloak running — the token verifier is replaced
with a mock that either raises or returns failure, same as a real expired/
invalid token would.
"""
from __future__ import annotations

import threading
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from jwt import InvalidTokenError
from sqlalchemy import event

from sqlalchemy import event as sa_event

from common.rls_middleware import (
    DenialLogger,
    TenantRLSMiddleware,
    register_rls_listener,
)
from common.rls_middleware.infrastructure.keycloak_verifier import KeycloakTokenVerifier


# ---------------------------------------------------------------------------
# Query counter — proves zero DB calls
# ---------------------------------------------------------------------------

class _QueryCounter:
    """Thread-safe counter attached to a SQLAlchemy engine via event hook."""

    def __init__(self, engine):
        self._engine = engine
        self._count = 0
        self._lock = threading.Lock()
        event.listen(engine, "before_cursor_execute", self._on_execute)

    def _on_execute(self, conn, cursor, statement, parameters, context, executemany):
        with self._lock:
            self._count += 1

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def reset(self):
        with self._lock:
            self._count = 0

    def remove(self):
        event.remove(self._engine, "before_cursor_execute", self._on_execute)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def query_counter(test_engine):
    """
    Attach a query counter to the real CRDB engine for one test.
    Removed in teardown so it does not leak between tests.
    """
    counter = _QueryCounter(test_engine)
    yield counter
    counter.remove()


def _make_failing_verifier() -> KeycloakTokenVerifier:
    """Stub verifier that raises InvalidTokenError (simulates invalid token)."""
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.side_effect = InvalidTokenError("signature verification failed")
    return v


def _make_expired_verifier() -> KeycloakTokenVerifier:
    """Stub verifier that raises InvalidTokenError (simulates expired token)."""
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.side_effect = InvalidTokenError("Signature has expired")
    return v


@pytest.fixture()
def app_no_jwt(test_engine, app_user_session_factory):
    """
    FastAPI app wired to the real CRDB engine, with a failing verifier.
    The DenialLogger also writes to the real DB — proving that the only
    DB calls come from denial logging, not from the request processing path.
    """
    app = FastAPI()

    # Register the RLS listener on the real engine (same as production)
    listener_fn = register_rls_listener(test_engine)

    # DenialLogger uses fake factory to avoid DB write in these tests —
    # we specifically want to measure zero *request-path* DB calls.
    mock_denial_logger = MagicMock(spec=DenialLogger)

    app.add_middleware(
        TenantRLSMiddleware,
        token_verifier=_make_failing_verifier(),
        denial_logger=mock_denial_logger,
        enforcement_enabled=True,
    )

    @app.get("/api/projects")
    async def projects(request: Request):
        return {"data": "should never reach here"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.state.mock_denial_logger = mock_denial_logger
    yield app
    sa_event.remove(test_engine, "before_cursor_execute", listener_fn)


@pytest.fixture()
def app_expired_jwt(test_engine):
    """App with a verifier that rejects expired tokens."""
    app = FastAPI()
    listener_fn = register_rls_listener(test_engine)
    mock_denial_logger = MagicMock(spec=DenialLogger)

    app.add_middleware(
        TenantRLSMiddleware,
        token_verifier=_make_expired_verifier(),
        denial_logger=mock_denial_logger,
        enforcement_enabled=True,
    )

    @app.get("/api/projects")
    async def projects(request: Request):
        return {"data": "should never reach here"}

    app.state.mock_denial_logger = mock_denial_logger
    yield app
    sa_event.remove(test_engine, "before_cursor_execute", listener_fn)


# ---------------------------------------------------------------------------
# C2 Tests — Missing JWT
# ---------------------------------------------------------------------------

class TestMissingJwt:
    """No Authorization header at all → 403 immediately, zero DB queries."""

    def test_returns_403(self, app_no_jwt, query_counter):
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        resp = client.get("/api/projects")
        assert resp.status_code == 403

    def test_zero_db_queries(self, app_no_jwt, query_counter):
        """The real CRDB engine must see exactly 0 queries."""
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        query_counter.reset()
        client.get("/api/projects")
        assert query_counter.count == 0, (
            f"Expected 0 DB queries on missing JWT, got {query_counter.count}"
        )

    def test_response_body_has_error_code(self, app_no_jwt, query_counter):
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        body = client.get("/api/projects").json()
        assert body["error"] == "tenant_context_required"
        assert "trace_id" in body

    def test_denial_logger_called(self, app_no_jwt, query_counter):
        """Denial is logged (to the mock), proving the middleware ran."""
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        client.get("/api/projects")
        app_no_jwt.state.mock_denial_logger.log_denial.assert_called_once()

    def test_skip_path_still_works(self, app_no_jwt, query_counter):
        """Health endpoint bypasses auth — no 403, no DB calls."""
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        query_counter.reset()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert query_counter.count == 0


# ---------------------------------------------------------------------------
# C2 Tests — Invalid JWT (bad signature)
# ---------------------------------------------------------------------------

class TestInvalidJwt:
    """Malformed Bearer token → verifier raises InvalidTokenError → 403, no DB."""

    def test_returns_403(self, app_no_jwt, query_counter):
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        resp = client.get(
            "/api/projects",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert resp.status_code == 403

    def test_zero_db_queries(self, app_no_jwt, query_counter):
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        query_counter.reset()
        client.get(
            "/api/projects",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert query_counter.count == 0, (
            f"Expected 0 DB queries on invalid JWT, got {query_counter.count}"
        )

    def test_response_body_has_trace_id(self, app_no_jwt, query_counter):
        """Every 403 must include a trace_id for incident correlation."""
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        body = client.get(
            "/api/projects",
            headers={"Authorization": "Bearer bad"},
        ).json()
        assert "trace_id" in body
        # Verify trace_id is a valid UUID
        uuid.UUID(body["trace_id"])


# ---------------------------------------------------------------------------
# C2 Tests — Expired JWT
# ---------------------------------------------------------------------------

class TestExpiredJwt:
    """Expired token → InvalidTokenError → 403, zero DB calls."""

    def test_returns_403(self, app_expired_jwt, query_counter):
        client = TestClient(app_expired_jwt, raise_server_exceptions=False)
        resp = client.get(
            "/api/projects",
            headers={"Authorization": "Bearer expired.jwt.token"},
        )
        assert resp.status_code == 403

    def test_zero_db_queries(self, app_expired_jwt, query_counter):
        client = TestClient(app_expired_jwt, raise_server_exceptions=False)
        query_counter.reset()
        client.get(
            "/api/projects",
            headers={"Authorization": "Bearer expired.jwt.token"},
        )
        assert query_counter.count == 0


# ---------------------------------------------------------------------------
# C2 Tests — Malformed Authorization header
# ---------------------------------------------------------------------------

class TestMalformedAuthHeader:
    """Various malformed Authorization headers → 403, zero DB."""

    @pytest.mark.parametrize("auth_header", [
        "Basic dXNlcjpwYXNz",       # wrong scheme
        "Bearer",                     # no space + token
        "Bearer ",                    # space but empty token
        "token abc123",               # completely wrong format
    ])
    def test_malformed_auth_returns_403(
        self, app_no_jwt, query_counter, auth_header,
    ):
        client = TestClient(app_no_jwt, raise_server_exceptions=False)
        query_counter.reset()
        resp = client.get(
            "/api/projects",
            headers={"Authorization": auth_header},
        )
        assert resp.status_code == 403
        assert query_counter.count == 0, (
            f"Expected 0 DB queries for auth header '{auth_header}', "
            f"got {query_counter.count}"
        )
