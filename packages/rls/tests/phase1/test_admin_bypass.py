"""
C5 — Platform Admin Access

Verifies that:
  - Admin with role + permission + header gets target tenant context
  - bypass_rls=True is set (application layer only)
  - Role alone without permission is rejected
  - Permission alone without role falls through to normal user context
  - Invalid target UUID is rejected
  - Admin without X-Admin-Target-Tenant falls through to normal user context
"""
from __future__ import annotations

import uuid
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from tests.phase1.conftest import (
    ADMIN_USER,
    TENANT_A,
    make_app,
    make_verifier,
)


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
        """
        Admin with role + permission + header gets the target tenant UUID
        as their tenant context. The DB sees this as a normal tenant session.
        """
        target = str(uuid.uuid4())
        app = make_app(make_verifier(_admin_claims(["tenant:investigate"])))

        with patch("app.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["tenant_id"] == target

    def test_valid_admin_sets_bypass_rls_true_in_context_var(self):
        """bypass_rls=True reaches ContextVar for application-layer use."""
        target = str(uuid.uuid4())
        app = make_app(make_verifier(_admin_claims(["tenant:investigate"])))

        with patch("app.interfaces.middleware.set_tenant_context") as mock_set:
            TestClient(app, raise_server_exceptions=False).get(
                "/protected",
                headers={
                    "Authorization": "Bearer admin.token",
                    "X-Admin-Target-Tenant": target,
                },
            )
            assert mock_set.call_args.kwargs["bypass_rls"] is True

    def test_admin_context_is_platform_admin_true(self):
        """request.state.tenant_context.is_platform_admin must be True."""
        from fastapi import FastAPI, Request
        from unittest.mock import MagicMock
        from app import TenantRLSMiddleware, DenialLogger
        import os

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
        """
        platform_admin role alone is not sufficient.
        tenant:investigate permission is also required.
        """
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
        """X-Admin-Target-Tenant must be a valid UUID."""
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
        """
        Admin JWT with no X-Admin-Target-Tenant header falls through to
        normal _build_user_context. If the JWT has a tenant_id claim,
        the request proceeds normally as a tenant user.
        """
        claims = _admin_claims(["tenant:investigate"], tenant_id=TENANT_A)
        app = make_app(make_verifier(claims))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer admin.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A

    def test_permission_only_without_admin_role_gets_normal_context(self):
        """
        Having tenant:investigate permission but NOT platform_admin role
        falls through to normal user context (admin path not triggered).
        """
        claims = {
            "sub": str(uuid.uuid4()),
            "tenant_id": TENANT_A,
            "permissions": ["tenant:investigate"],
            # No realm_access.roles.platform_admin
        }
        app = make_app(make_verifier(claims))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer some.token"},
        )
        assert r.status_code == 200
        assert r.json()["tenant_id"] == TENANT_A
