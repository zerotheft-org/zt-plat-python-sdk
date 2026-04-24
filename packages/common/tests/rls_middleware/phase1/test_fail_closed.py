from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from jwt import ExpiredSignatureError, InvalidTokenError

from tests.rls_middleware.phase1.conftest import make_app, make_verifier, make_verifier_raising


class TestMissingOrMalformedToken:
    def test_no_auth_header_returns_403(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get("/protected")
        assert r.status_code == 403

    def test_no_auth_header_returns_correct_error_code(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get("/protected")
        assert r.json()["error"] == "tenant_context_required"

    def test_no_auth_header_response_contains_trace_id(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get("/protected")
        assert "trace_id" in r.json()
        assert r.json()["trace_id"] is not None

    def test_malformed_bearer_prefix_returns_403(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Token some.token"},
        )
        assert r.status_code == 403

    def test_bearer_with_no_token_returns_403(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer "},
        )
        assert r.status_code == 403


class TestJWTVerificationFailures:
    def test_expired_jwt_returns_403(self):
        app = make_app(make_verifier_raising(ExpiredSignatureError("expired")))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer expired.token"},
        )
        assert r.status_code == 403

    def test_invalid_signature_returns_403(self):
        app = make_app(make_verifier_raising(InvalidTokenError("signature mismatch")))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer forged.token"},
        )
        assert r.status_code == 403

    def test_missing_tenant_claim_returns_403(self):
        app = make_app(make_verifier({"sub": str(uuid.uuid4())}))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert r.status_code == 403

    def test_invalid_tenant_uuid_returns_403(self):
        app = make_app(make_verifier({"sub": str(uuid.uuid4()), "tenant_id": "not-a-uuid"}))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert r.status_code == 403

    def test_zero_uuid_tenant_returns_403(self):
        zero_uuid = "00000000-0000-0000-0000-000000000000"
        app = make_app(make_verifier({"sub": str(uuid.uuid4()), "tenant_id": zero_uuid}))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        assert r.status_code == 403


class TestUnexpectedCrash:
    def test_unexpected_exception_returns_403_never_500(self):
        app = make_app(make_verifier_raising(RuntimeError("unexpected crash")))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer any.token"},
        )
        assert r.status_code == 403
        assert r.json()["error"] == "tenant_context_error"

    def test_unexpected_crash_still_returns_trace_id(self):
        app = make_app(make_verifier_raising(RuntimeError("crash")))
        r = TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer any.token"},
        )
        assert "trace_id" in r.json()
