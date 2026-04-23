from __future__ import annotations

import uuid
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from tests.rls_middleware.phase1.conftest import ADMIN_USER, TENANT_A, make_app, make_verifier


def _admin_claims(permissions: list, tenant_id: str | None = None) -> dict:
    claims = {
        "sub": ADMIN_USER,
        "realm_access": {"roles": ["platform_admin"]},
        "permissions": permissions,
    }
    if tenant_id:
        claims["tenant_id"] = tenant_id
    return claims


class TestValidAdminAccess:
    def test_valid_admin_gets_target_tenant_as_context(self):
        target = str(uuid.uuid4())
        app = make_app(make_verifier(_admin_claims(["tenant:investigate"])))

        with patch("common.rls_middleware.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["tenant_id"] == target

    def test_valid_admin_sets_bypass_rls_true_in_context_var(self):
        target = str(uuid.uuid4())
        app = make_app(make_verifier(_admin_claims(["tenant:investigate"])))

        with patch("common.rls_middleware.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is True

    def test_admin_context_is_platform_admin_true(self):
        from unittest.mock import MagicMock
        import os

        from common.rls_middleware import DenialLogger, TenantRLSMiddleware

        target = str(uuid.uuid4())
        captured = {}

        app = FastAPI()
        with patch.dict(os.environ, {"RLS_ENFORCEMENT_ENABLED": "true"}):
            app.add_middleware(
                TenantRLSMiddleware,
                token_verifier=make_verifier(_admin_claims(["tenant:investigate"])),
                denial_logger=MagicMock(spec=DenialLogger),
            )

        @app.get("/check")
        async def check(request: Request):
            ctx = request.state.tenant_context
            captured["is_admin"] = ctx.is_platform_admin
            captured["bypass_rls"] = ctx.bypass_rls
            return {}

        TestClient(app, raise_server_exceptions=False).get(
            "/check",
            headers={
                "Authorization": "Bearer admin.token",
                "X-Admin-Target-Tenant": target,
            },
        )
        assert captured["is_admin"] is True
        assert captured["bypass_rls"] is True


class TestAdminAccessRejections:
    def test_admin_role_without_permission_returns_403(self):
        target = str(uuid.uuid4())
        app = make_app(make_verifier(_admin_claims(permissions=[])))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={
                "Authorization": "Bearer admin.token",
                "X-Admin-Target-Tenant": target,
            },
        )
        assert r.status_code == 403

    def test_admin_invalid_target_uuid_returns_403(self):
        app = make_app(make_verifier(_admin_claims(["tenant:investigate"])))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={
                "Authorization": "Bearer admin.token",
                "X-Admin-Target-Tenant": "not-a-uuid",
            },
        )
        assert r.status_code == 403

    def test_admin_without_target_header_falls_through_to_user_context(self):
        claims = _admin_claims(["tenant:investigate"], tenant_id=TENANT_A)
        app = make_app(make_verifier(claims))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer admin.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A

    def test_permission_only_without_admin_role_gets_normal_context(self):
        claims = {
            "sub": str(uuid.uuid4()),
            "tenant_id": TENANT_A,
            "permissions": ["tenant:investigate"],
        }
        app = make_app(make_verifier(claims))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer some.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A
