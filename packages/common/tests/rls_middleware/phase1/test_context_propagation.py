from __future__ import annotations

import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

from common.rls_middleware.application.context import get_bypass_rls, get_tenant_id
from tests.rls_middleware.phase1.conftest import (
    ADMIN_USER,
    TENANT_A,
    make_app,
    make_verifier,
)


class TestTenantIdPropagation:
    def test_tenant_id_from_jwt_reaches_context_var(self):
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        with patch(
            "common.rls_middleware.interfaces.middleware.set_tenant_context"
        ) as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={"Authorization": "Bearer valid.token"},
            )
            mock_set.assert_called_once()
            assert mock_set.call_args.kwargs["tenant_id"] == TENANT_A

    def test_tenant_id_available_on_request_state(self):
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A

    def test_context_var_cleared_after_request(self):
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert get_tenant_id() is None

    def test_context_var_cleared_even_after_route_handler_exception(self):
        from fastapi import FastAPI
        from unittest.mock import MagicMock
        import os

        from common.rls_middleware import DenialLogger, TenantRLSMiddleware

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
        claims = {"sub": str(uuid.uuid4()), "tenant_id": TENANT_A}
        app = make_app(make_verifier(claims))

        with patch(
            "common.rls_middleware.interfaces.middleware.set_tenant_context"
        ) as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={"Authorization": "Bearer valid.token"},
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is False

    def test_admin_bypass_rls_reaches_context_var(self):
        target = str(uuid.uuid4())
        claims = {
            "sub": ADMIN_USER,
            "realm_access": {"roles": ["platform_admin"]},
            "permissions": ["tenant:investigate"],
        }
        app = make_app(make_verifier(claims))

        with patch(
            "common.rls_middleware.interfaces.middleware.set_tenant_context"
        ) as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is True

    def test_bypass_rls_absent_from_rls_listener(self):
        import inspect

        from common.rls_middleware.infrastructure.rls_listener import register_rls_listener

        source = inspect.getsource(register_rls_listener)
        assert "bypass_rls" not in source
        assert "app.bypass_rls" not in source
