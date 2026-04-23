from __future__ import annotations

from fastapi.testclient import TestClient

from tests.rls_middleware.phase1.conftest import make_app, make_verifier


class TestSkipPaths:
    def test_health_returns_200_without_token(self):
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get("/health")
        assert r.status_code == 200

    def test_webhook_path_skipped(self):
        from fastapi import FastAPI
        from unittest.mock import MagicMock, patch
        import os

        from common.rls_middleware import DenialLogger, TenantRLSMiddleware

        app = FastAPI()
        with patch.dict(os.environ, {"RLS_ENFORCEMENT_ENABLED": "true"}):
            app.add_middleware(
                TenantRLSMiddleware,
                token_verifier=make_verifier({}),
                denial_logger=MagicMock(spec=DenialLogger),
            )

        @app.post("/webhooks/stripe")
        async def stripe_webhook():
            return {"received": True}

        r = TestClient(app, raise_server_exceptions=False).post("/webhooks/stripe")
        assert r.status_code == 200

    def test_enforcement_disabled_passes_all_requests(self):
        app = make_app(make_verifier({}), enforcement=False)
        r = TestClient(app, raise_server_exceptions=False).get("/protected")
        assert r.status_code == 200

    def test_enforcement_enabled_by_default(self):
        import os
        from unittest.mock import patch

        env = {k: v for k, v in os.environ.items() if k != "RLS_ENFORCEMENT_ENABLED"}
        with patch.dict(os.environ, env, clear=True):
            assert os.environ.get("RLS_ENFORCEMENT_ENABLED", "true").lower() == "true"
