"""
C1 — Tenant Context Propagation

Verifies that:
  - tenant_id flows from JWT claim → ContextVar → request.state
  - ContextVar is cleared after every request (no leakage to next request)
  - bypass_rls is stored in ContextVar but never sent to the DB session
"""
from __future__ import annotations

import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.application.context import get_tenant_id, get_bypass_rls
from tests.phase1.conftest import (
    ADMIN_USER,
    TENANT_A,
    make_app,
    make_verifier,
)


class TestTenantIdPropagation:

    def test_tenant_id_from_jwt_reaches_context_var(self):
        """
        Core Phase 1 test.
        tenant_id in JWT claim → set_tenant_context() → ContextVar.
        """
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        with patch("app.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={"Authorization": "Bearer valid.token"},
            )
            mock_set.assert_called_once()
            assert mock_set.call_args.kwargs["tenant_id"] == TENANT_A

    def test_tenant_id_available_on_request_state(self):
        """Route handlers can read tenant_id via request.state.tenant_context."""
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A

    def test_context_var_cleared_after_request(self):
        """
        After the request completes, ContextVar must be None.
        Prevents tenant context leaking to the next request on a reused
        connection or coroutine.
        """
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        # After request: ContextVar must be reset
        assert get_tenant_id() is None

    def test_context_var_cleared_even_after_route_handler_exception(self):
        """
        The finally block in dispatch() must clear context even when the
        route handler raises an unhandled exception.
        """
        from fastapi import FastAPI, Request
        from unittest.mock import MagicMock
        from app import TenantRLSMiddleware, DenialLogger
        import os

        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}

        app = FastAPI()
        with patch.dict(os.environ, {"RLS_ENFORCEMENT_ENABLED": "true"}):
            app.add_middleware(
                TenantRLSMiddleware,
                token_verifier=make_verifier(claims),
                denial_logger=MagicMock(spec=DenialLogger),
            )

        @app.get("/boom")
        async def boom():
            raise RuntimeError("route handler exploded")

        TestClient(app, raise_server_exceptions=False).get(
            "/boom",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert get_tenant_id() is None


class TestBypassRlsPropagation:

    def test_regular_user_bypass_rls_is_false(self):
        """Non-admin requests must have bypass_rls=False."""
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        with patch("app.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={"Authorization": "Bearer valid.token"},
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is False

    def test_admin_bypass_rls_reaches_context_var(self):
        """
        Admin sessions have bypass_rls=True in ContextVar.
        This is for application-layer use (PII masking) only.
        """
        target = str(uuid.uuid4())
        claims = {
            "sub": ADMIN_USER,
            "realm_access": {"roles": ["platform_admin"]},
            "permissions": ["tenant:investigate"],
        }
        app = make_app(make_verifier(claims))

        with patch("app.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is True

    def test_bypass_rls_absent_from_rls_listener(self):
        """
        The SQLAlchemy listener must ONLY call SET LOCAL app.current_tenant.
        SET LOCAL app.bypass_rls must never appear — it was removed from all
        CRDB RLS policies because it is self-escalatable via set_config().
        """
        from app.infrastructure.rls_listener import register_rls_listener
        import inspect

        source = inspect.getsource(register_rls_listener)
        assert "bypass_rls" not in source, (
            "rls_listener.py must not reference bypass_rls — "
            "that session variable was removed from CRDB RLS policies"
        )
        assert "app.bypass_rls" not in source
