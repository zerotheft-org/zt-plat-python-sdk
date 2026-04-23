from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

from fastapi import FastAPI, Request
from common.rls_middleware import DenialLogger, TenantRLSMiddleware
from common.rls_middleware.infrastructure.keycloak_verifier import KeycloakTokenVerifier


def make_verifier(claims: dict) -> KeycloakTokenVerifier:
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.return_value = claims
    return v


def make_verifier_raising(exc: Exception) -> KeycloakTokenVerifier:
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.side_effect = exc
    return v


def make_app(
    verifier: KeycloakTokenVerifier,
    enforcement: bool = True,
) -> FastAPI:
    app = FastAPI()
    mock_denial_logger = MagicMock(spec=DenialLogger)

    with patch.dict(
        os.environ,
        {"RLS_ENFORCEMENT_ENABLED": str(enforcement).lower()},
    ):
        app.add_middleware(
            TenantRLSMiddleware,
            token_verifier=verifier,
            denial_logger=mock_denial_logger,
            enforcement_enabled=enforcement,
        )

    @app.get("/protected")
    async def protected(request: Request):
        ctx = getattr(request.state, "tenant_context", None)
        return {"tenant_id": str(ctx.tenant_id) if ctx else None}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.state.mock_denial_logger = mock_denial_logger
    return app


TENANT_A = str(uuid.uuid4())
TENANT_B = str(uuid.uuid4())
ADMIN_USER = str(uuid.uuid4())
REGULAR_USER = str(uuid.uuid4())
