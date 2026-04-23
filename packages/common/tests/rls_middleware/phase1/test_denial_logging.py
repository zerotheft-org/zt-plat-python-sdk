from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from common.rls_middleware import DenialLogger, TenantRLSMiddleware
from tests.rls_middleware.phase1.conftest import make_verifier, make_verifier_raising


def _make_app_with_mock_logger(verifier) -> tuple[FastAPI, MagicMock]:
    app = FastAPI()
    mock_logger = MagicMock(spec=DenialLogger)

    with patch.dict(os.environ, {"RLS_ENFORCEMENT_ENABLED": "true"}):
        app.add_middleware(
            TenantRLSMiddleware,
            token_verifier=verifier,
            denial_logger=mock_logger,
        )

    @app.get("/protected")
    async def _():
        return {}

    return app, mock_logger


class TestDenialRecordOnRejection:
    def test_missing_jwt_writes_denial_record(self):
        app, mock_logger = _make_app_with_mock_logger(make_verifier({}))
        TestClient(app, raise_server_exceptions=False).get("/protected")
        mock_logger.log_denial.assert_called_once()

    def test_rejection_denial_action_is_middleware_reject(self):
        app, mock_logger = _make_app_with_mock_logger(make_verifier({}))
        TestClient(app, raise_server_exceptions=False).get("/protected")
        kwargs = mock_logger.log_denial.call_args.kwargs
        assert kwargs["action"] == "MIDDLEWARE_REJECT"

    def test_rejection_denial_has_trace_id(self):
        app, mock_logger = _make_app_with_mock_logger(make_verifier({}))
        TestClient(app, raise_server_exceptions=False).get("/protected")
        kwargs = mock_logger.log_denial.call_args.kwargs
        assert kwargs.get("trace_id") is not None

    def test_upstream_trace_id_propagated_to_denial(self):
        upstream_trace = str(uuid.uuid4())
        app, mock_logger = _make_app_with_mock_logger(make_verifier({}))
        TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"X-Request-ID": upstream_trace},
        )
        kwargs = mock_logger.log_denial.call_args.kwargs
        assert kwargs["trace_id"] == upstream_trace

    def test_denial_record_has_exact_schema_fields(self):
        app, mock_logger = _make_app_with_mock_logger(make_verifier({}))
        TestClient(app, raise_server_exceptions=False).get("/protected")
        kwargs = mock_logger.log_denial.call_args.kwargs
        assert set(kwargs.keys()) == {
            "trace_id",
            "tenant_id",
            "user_id",
            "action",
            "resource",
        }

    def test_middleware_error_writes_denial_with_middleware_error_action(self):
        app, mock_logger = _make_app_with_mock_logger(
            make_verifier_raising(RuntimeError("internal crash"))
        )
        TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer any.token"},
        )
        kwargs = mock_logger.log_denial.call_args.kwargs
        assert kwargs["action"] == "MIDDLEWARE_ERROR"

    def test_valid_request_writes_no_denial(self):
        valid_tenant = str(uuid.uuid4())
        claims = {"sub": str(uuid.uuid4()), "tenant_id": valid_tenant}
        app, mock_logger = _make_app_with_mock_logger(make_verifier(claims))
        TestClient(app, raise_server_exceptions=False).get(
            "/protected",
            headers={"Authorization": "Bearer valid.token"},
        )
        mock_logger.log_denial.assert_not_called()
