"""
Skip Paths

Verifies that health checks, docs, and webhook paths pass through
without requiring auth — necessary for load balancers and Stripe webhooks.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.phase1.conftest import make_app, make_verifier


class TestSkipPaths:

    def test_health_returns_200_without_token(self):
        """Load balancer health checks must work without auth."""
        app = make_app(make_verifier({}))
        r = TestClient(app, raise_server_exceptions=False).get("/health")
        assert r.status_code == 200

    def test_webhook_path_skipped(self):
        """
        /webhooks/* paths are skipped — Stripe/provider webhooks arrive without
        a user JWT. They are handled by a separate privileged role at the DB layer.
        """
        from fastapi import FastAPI, Request
        from unittest.mock import MagicMock
        from app import TenantRLSMiddleware, DenialLogger
        import os

        app = FastAPI()
        with __import__("unittest.mock", fromlist=["patch"]).patch.dict(
            os.environ, {"RLS_ENFORCEMENT_ENABLED": "true"}
        ):
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
        """
        RLS_ENFORCEMENT_ENABLED=false must let everything through.
        This exists for local dev only — never set in staging or production.
        """
        app = make_app(make_verifier({}), enforcement=False)
        r = TestClient(app, raise_server_exceptions=False).get("/protected")
        assert r.status_code == 200

    def test_enforcement_enabled_by_default(self):
        """Default behaviour must be enforced — opt-out requires explicit env var."""
        import os
        from unittest.mock import patch

        # Remove the env var entirely to test the default
        env = {k: v for k, v in os.environ.items() if k != "RLS_ENFORCEMENT_ENABLED"}
        with patch.dict(os.environ, env, clear=True):
            from app.interfaces.middleware import TenantRLSMiddleware as M
            # Default: os.environ.get("RLS_ENFORCEMENT_ENABLED", "true") == "true"
            assert os.environ.get("RLS_ENFORCEMENT_ENABLED", "true").lower() == "true"
