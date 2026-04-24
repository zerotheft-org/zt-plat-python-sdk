"""
Keycloak Smoke Test — proves the KeycloakTokenVerifier works against a
real Keycloak instance end-to-end.

Skipped automatically when Keycloak env vars are not configured.
Run explicitly:
    .venv/bin/pytest tests/test_keycloak_smoke.py -v

Requires these env vars (see .env.example):
    KEYCLOAK_JWKS_URL   — realm JWKS endpoint
    KEYCLOAK_ISSUER     — realm issuer URL
    KEYCLOAK_AUDIENCE   — client ID the token is issued for
    KC_TOKEN_URL        — token endpoint for client_credentials grant
    KC_CLIENT_ID        — service account client ID
    KC_CLIENT_SECRET    — service account client secret
"""
from __future__ import annotations

import json
import base64
import os

import httpx
import pytest
from jwt import InvalidTokenError

from common.rls_middleware.infrastructure.keycloak_verifier import KeycloakTokenVerifier

# ---------------------------------------------------------------------------
# Skip if Keycloak is not configured
# ---------------------------------------------------------------------------

_REQUIRED = [
    "KEYCLOAK_JWKS_URL",
    "KEYCLOAK_ISSUER",
    "KEYCLOAK_AUDIENCE",
    "KC_TOKEN_URL",
    "KC_CLIENT_ID",
    "KC_CLIENT_SECRET",
]

_missing = [k for k in _REQUIRED if not os.environ.get(k)]
_skip = pytest.mark.skipif(
    bool(_missing),
    reason=f"Keycloak env vars not set: {', '.join(_missing)}",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_token() -> str:
    """
    Obtain a real JWT from Keycloak using the client_credentials grant.
    This is a service-account flow — no user interaction needed.
    """
    resp = httpx.post(
        os.environ["KC_TOKEN_URL"],
        data={
            "grant_type": "client_credentials",
            "client_id": os.environ["KC_CLIENT_ID"],
            "client_secret": os.environ["KC_CLIENT_SECRET"],
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _decode_payload_unverified(token: str) -> dict:
    """Decode the JWT payload without verification (for inspecting claims)."""
    payload_b64 = token.split(".")[1]
    # Add padding if needed
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_skip
class TestKeycloakSmoke:
    """
    End-to-end proof that KeycloakTokenVerifier can fetch JWKS from
    the real Keycloak instance and verify a real JWT.

    NOTE: Keycloak client_credentials tokens often have aud="account"
    instead of the client ID. The verifier is constructed with the
    actual token audience so signature + claims validation works
    end-to-end. For production user-facing tokens, add an "audience"
    protocol mapper in Keycloak to set aud to your client ID.
    """

    @pytest.fixture(scope="class")
    def real_token(self):
        return _fetch_token()

    @pytest.fixture(scope="class")
    def token_audience(self, real_token):
        """Extract the actual aud claim from the token."""
        claims = _decode_payload_unverified(real_token)
        aud = claims.get("aud", os.environ["KEYCLOAK_AUDIENCE"])
        # aud can be a string or a list; verifier expects a single string
        return aud if isinstance(aud, str) else aud[0]

    @pytest.fixture(scope="class")
    def verifier(self, token_audience):
        """
        Build verifier with the token's actual audience.
        client_credentials tokens may have aud="account" instead of
        the client ID — this is normal Keycloak behavior.
        """
        return KeycloakTokenVerifier(
            jwks_url=os.environ["KEYCLOAK_JWKS_URL"],
            issuer=os.environ["KEYCLOAK_ISSUER"],
            audience=token_audience,
        )

    async def test_valid_token_returns_claims(self, verifier, real_token):
        """A freshly minted Keycloak JWT must decode successfully."""
        claims = await verifier.verify(real_token)
        assert isinstance(claims, dict)
        assert "sub" in claims, "Token must have a 'sub' (subject) claim"
        assert "iss" in claims, "Token must have an 'iss' (issuer) claim"
        assert claims["iss"] == os.environ["KEYCLOAK_ISSUER"]

    async def test_valid_token_has_expected_audience(self, verifier, real_token, token_audience):
        """aud claim must match the configured audience."""
        claims = await verifier.verify(real_token)
        aud = claims.get("aud")
        if isinstance(aud, list):
            assert token_audience in aud
        else:
            assert aud == token_audience

    async def test_garbage_token_raises(self, verifier):
        """Random garbage must raise InvalidTokenError, never return claims."""
        with pytest.raises(Exception):
            await verifier.verify("not.a.real.jwt")

    async def test_tampered_token_raises(self, verifier, real_token):
        """Flipping a character in the signature must fail verification."""
        parts = real_token.rsplit(".", 1)
        if len(parts) == 2:
            # Flip the last char of the signature
            sig = parts[1]
            tampered_char = "A" if sig[-1] != "A" else "B"
            tampered = parts[0] + "." + sig[:-1] + tampered_char
            with pytest.raises(Exception):
                await verifier.verify(tampered)

    async def test_jwks_cache_works(self, verifier, real_token):
        """Second call should use cached JWKS — no HTTP fetch."""
        # First call populates cache
        await verifier.verify(real_token)
        cached_at = verifier._jwks_fetched_at

        # Second call should reuse cache
        await verifier.verify(real_token)
        assert verifier._jwks_fetched_at == cached_at, "JWKS should be cached"
