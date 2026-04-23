from __future__ import annotations

import logging
import os
import time

import httpx
from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWKError

logger = logging.getLogger(__name__)

# JWKS keys only change on Keycloak key rotation — cache for 5 minutes.
# On kid miss (rotation event) we re-fetch immediately before failing.
_JWKS_CACHE_TTL_SECONDS = 300


class KeycloakTokenVerifier:
    """
    Verifies Keycloak-issued JWTs using the realm's public JWKS endpoint.

    Instantiate ONCE at service startup. Safe to share across all requests.

    What it verifies
    ----------------
    - RSA signature (RS256 — Keycloak default)
    - Token expiry (exp claim)
    - Issued-at (iat claim)
    - Issuer (iss must match KEYCLOAK_ISSUER)
    - Audience (aud must match KEYCLOAK_AUDIENCE / your client ID)

    JWKS caching
    ------------
    Fetches Keycloak's public keys once and caches for 5 minutes.
    On key ID (kid) miss — which happens during Keycloak key rotation —
    invalidates the cache, re-fetches once, and retries before failing.
    This means key rotation is handled transparently without a service restart.

    On JWKS fetch failure with a stale cache: uses stale keys rather than
    hard-failing all requests. Logs a warning. This is intentional — a
    temporary Keycloak outage should not take down the service.

    Configuration
    -------------
    Pass values explicitly OR fall back to environment variables:

        # Explicit (preferred — no hidden env coupling):
        KeycloakTokenVerifier(
            jwks_url="https://keycloak.example.com/realms/zt/protocol/openid-connect/certs",
            issuer="https://keycloak.example.com/realms/zt",
            audience="zerotheft-api",
        )

        # Env fallback (reads KEYCLOAK_JWKS_URL, KEYCLOAK_ISSUER, KEYCLOAK_AUDIENCE):
        KeycloakTokenVerifier()
    """

    def __init__(
        self,
        *,
        jwks_url: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        algorithm: str = "RS256",
    ) -> None:
        self._jwks_url = jwks_url or os.environ.get("KEYCLOAK_JWKS_URL", "")
        self._issuer = issuer or os.environ.get("KEYCLOAK_ISSUER", "")
        self._audience = audience or os.environ.get("KEYCLOAK_AUDIENCE", "")
        self._algorithm = algorithm

        if not self._jwks_url or not self._issuer or not self._audience:
            missing = [
                name
                for name, val in [
                    ("jwks_url / KEYCLOAK_JWKS_URL", self._jwks_url),
                    ("issuer / KEYCLOAK_ISSUER", self._issuer),
                    ("audience / KEYCLOAK_AUDIENCE", self._audience),
                ]
                if not val
            ]
            raise ValueError(
                f"KeycloakTokenVerifier: missing required config: {', '.join(missing)}. "
                "Pass them as constructor kwargs or set the corresponding env vars."
            )

        self._jwks_cache: dict | None = None
        self._jwks_fetched_at: float = 0.0

    async def verify(self, token: str) -> dict:
        """
        Fully verify a Keycloak JWT.

        Returns the decoded claims dict on success.
        Raises jose.JWTError (or a subclass) on any verification failure.
        Never returns claims from an unverified token.

        Parameters
        ----------
        token : str
            Raw JWT string (without 'Bearer ' prefix).

        Returns
        -------
        dict
            Verified claims. Relevant keys:
              sub          — Keycloak user UUID
              tenant_id    — custom claim added via Keycloak protocol mapper
              realm_access — { "roles": ["platform_admin", ...] }
              permissions  — custom claim list (e.g. ["tenant:investigate"])
        """
        jwks = await self._get_jwks()

        try:
            return jwt.decode(
                token,
                jwks,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except JWKError:
            # kid not in cache — Keycloak rotated keys.
            # Invalidate, re-fetch once, retry before failing.
            logger.info("JWT kid not in JWKS cache — refreshing and retrying")
            self._jwks_cache = None
            jwks = await self._get_jwks()
            return jwt.decode(
                token,
                jwks,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
            )
        except ExpiredSignatureError:
            logger.warning("Keycloak JWT expired")
            raise
        except JWTError as exc:
            logger.warning("JWT verification failed: %s", exc)
            raise

    async def _get_jwks(self) -> dict:
        """Return cached JWKS or fetch fresh from Keycloak if stale."""
        now = time.monotonic()
        if (
            self._jwks_cache
            and (now - self._jwks_fetched_at) < _JWKS_CACHE_TTL_SECONDS
        ):
            return self._jwks_cache

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self._jwks_url, timeout=5.0)
            response.raise_for_status()
            self._jwks_cache = response.json()
            self._jwks_fetched_at = now
            logger.info("Keycloak JWKS refreshed | url=%s", self._jwks_url)
            return self._jwks_cache
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch JWKS: %s", exc)
            if self._jwks_cache:
                logger.warning("Using stale JWKS cache due to fetch failure")
                return self._jwks_cache
            raise RuntimeError(
                f"Cannot verify JWTs: JWKS unreachable at {self._jwks_url}"
            ) from exc
