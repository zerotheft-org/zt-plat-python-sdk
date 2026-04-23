"""
Phase 1 test fixtures.

No DB, no Keycloak, no Docker required.
All external dependencies are mocked.
"""
from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app import DenialLogger, TenantRLSMiddleware
from app.infrastructure.keycloak_verifier import KeycloakTokenVerifier


# ---------------------------------------------------------------------------
# Verifier factories
# ---------------------------------------------------------------------------

def make_verifier(claims: dict) -> KeycloakTokenVerifier:
    """
    Stub verifier that returns pre-built claims without hitting Keycloak.
    Use this when you want the JWT verification to succeed.
    """
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.return_value = claims
    return v


def make_verifier_raising(exc: Exception) -> KeycloakTokenVerifier:
    """
    Stub verifier that raises a given exception on verify().
    Use this to simulate expired tokens, invalid signatures, etc.
    """
    v = MagicMock(spec=KeycloakTokenVerifier)
    v.verify.side_effect = exc
    return v


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def make_app(
    verifier: KeycloakTokenVerifier,
    enforcement: bool = True,
) -> FastAPI:
    """
    Build a minimal FastAPI app with TenantRLSMiddleware wired in.

    DenialLogger is mocked — no DB session needed for unit tests.
    Exposes two routes:
      GET /protected  — requires tenant context
      GET /health     — skip path, no auth needed
    """
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

    # Expose mock so tests can assert on it
    app.state.mock_denial_logger = mock_denial_logger
    return app


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TENANT_A = str(uuid.uuid4())
TENANT_B = str(uuid.uuid4())
ADMIN_USER = str(uuid.uuid4())
REGULAR_USER = str(uuid.uuid4())
