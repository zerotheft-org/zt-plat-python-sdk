from __future__ import annotations

import logging
import os
import time

import httpx
import jwt
from jwt import PyJWKSet, ExpiredSignatureError, InvalidTokenError

logger = logging.getLogger(__name__)

_JWKS_CACHE_TTL_SECONDS = 300


class KeycloakTokenVerifier:
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
        jwks = await self._get_jwks()
        jwk_set = PyJWKSet(jwks["keys"])

        try:
            return jwt.decode(
                token,
                jwk_set,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
            )
        except jwt.PyJWKSetError:
            logger.info("JWT kid not in JWKS cache — refreshing and retrying")
            self._jwks_cache = None
            jwks = await self._get_jwks()
            jwk_set = PyJWKSet(jwks["keys"])
            return jwt.decode(
                token,
                jwk_set,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
            )
        except ExpiredSignatureError:
            logger.warning("Keycloak JWT expired")
            raise
        except InvalidTokenError as exc:
            logger.warning("JWT verification failed: %s", exc)
            raise

    async def _get_jwks(self) -> dict:
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
