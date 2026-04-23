from __future__ import annotations

import logging
import os
import uuid
from typing import Set

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from jose import JWTError, ExpiredSignatureError

from ..application.context import set_tenant_context, clear_tenant_context
from ..domain.tenant_context import TenantContext
from ..infrastructure.denial_logger import DenialLogger
from ..infrastructure.audit_logger import AuditLogger
from ..infrastructure.keycloak_verifier import KeycloakTokenVerifier
from .exceptions import TenantContextError, MissingToken, InvalidToken, ExpiredToken

logger = logging.getLogger(__name__)

_DEFAULT_SKIP_PATHS: Set[str] = {
    "/health",
    "/ready",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
}


class TenantRLSMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        token_verifier: KeycloakTokenVerifier,
        denial_logger: DenialLogger,
        audit_logger: AuditLogger | None = None,
        skip_paths: Set[str] | None = None,
        enforcement_enabled: bool | None = None,
    ) -> None:
        super().__init__(app)
        self._verifier = token_verifier
        self._denial_logger = denial_logger
        self._audit_logger = audit_logger or AuditLogger()
        self._skip_paths = skip_paths or _DEFAULT_SKIP_PATHS
        self._enforcement_enabled = enforcement_enabled

        self._tenant_claim_key = os.environ.get("TENANT_CLAIM_KEY", "tenant_id")
        self._admin_role = os.environ.get("ADMIN_ROLE_NAME", "platform_admin")
        self._admin_permission = os.environ.get(
            "ADMIN_PERMISSION_CLAIM", "tenant:investigate"
        )
        self._admin_client_id = os.environ.get("KEYCLOAK_ADMIN_CLIENT_ID", "")
        self._warned_enforcement_disabled = False

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._enforcement_enabled is not None:
            enforcement_enabled = self._enforcement_enabled
        else:
            enforcement_enabled = (
                os.environ.get("RLS_ENFORCEMENT_ENABLED", "true").lower()
                == "true"
            )
        if self._should_skip(request.url.path) or not enforcement_enabled:
            if not enforcement_enabled and not self._warned_enforcement_disabled:
                self._warned_enforcement_disabled = True
                logger.warning(
                    "RLS_ENFORCEMENT_ENABLED=false — tenant isolation DISABLED. "
                    "Never set this in staging or production."
                )
            return await call_next(request)

        trace_id = self._get_trace_id(request)

        try:
            ctx = await self._resolve_context(request, trace_id)
        except TenantContextError as exc:
            logger.warning(
                "RLS reject | path=%s trace=%s reason=%s",
                request.url.path,
                trace_id,
                exc.reason,
            )
            self._denial_logger.log_denial(
                trace_id=trace_id,
                tenant_id=None,
                user_id=None,
                action="MIDDLEWARE_REJECT",
                resource=str(request.url.path),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "tenant_context_required",
                    "message": exc.reason,
                    "trace_id": trace_id,
                },
            )
        except Exception:
            logger.exception(
                "RLS unexpected middleware error | path=%s trace=%s",
                request.url.path,
                trace_id,
            )
            self._denial_logger.log_denial(
                trace_id=trace_id,
                tenant_id=None,
                user_id=None,
                action="MIDDLEWARE_ERROR",
                resource=str(request.url.path),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "tenant_context_error",
                    "message": "Request rejected: tenant context could not be established",
                    "trace_id": trace_id,
                },
            )

        set_tenant_context(
            tenant_id=ctx.tenant_id_str,
            bypass_rls=ctx.bypass_rls,
            trace_id=ctx.trace_id_str,
        )
        request.state.tenant_context = ctx

        try:
            return await call_next(request)
        finally:
            clear_tenant_context()

    async def _resolve_context(self, request: Request, trace_id: str) -> TenantContext:
        token = self._extract_bearer(request)
        if not token:
            raise MissingToken(
                "Missing or malformed Authorization: Bearer header"
            )

        try:
            claims = await self._verifier.verify(token)
        except ExpiredSignatureError as exc:
            raise ExpiredToken(f"JWT expired: {exc}") from exc
        except JWTError as exc:
            raise InvalidToken(f"JWT verification failed: {exc}") from exc

        admin_target = request.headers.get("X-Admin-Target-Tenant")
        if self._is_platform_admin(claims) and admin_target:
            ctx = self._build_admin_context(claims, admin_target, trace_id)
            self._audit_logger.log_admin_access(
                actor_user_id=claims.get("sub"),
                target_tenant_id=admin_target,
                reason_code=self._admin_permission,
                trace_id=trace_id,
                resource=str(request.url.path),
            )
            return ctx

        return self._build_user_context(claims, trace_id)

    def _build_user_context(self, claims: dict, trace_id: str) -> TenantContext:
        raw = claims.get(self._tenant_claim_key)
        if not raw:
            raise InvalidToken(
                f"JWT missing claim '{self._tenant_claim_key}'. "
                "Ensure a Keycloak protocol mapper adds this claim to tokens."
            )
        try:
            tenant_uuid = uuid.UUID(str(raw))
        except ValueError:
            raise InvalidToken(
                f"JWT claim '{self._tenant_claim_key}' is not a valid UUID: {raw!r}"
            )

        return TenantContext(
            tenant_id=tenant_uuid,
            user_id=self._parse_uuid(claims.get("sub")),
            is_platform_admin=False,
            bypass_rls=False,
            trace_id=self._parse_uuid(trace_id) or uuid.uuid4(),
        )

    def _build_admin_context(
        self,
        claims: dict,
        target_tenant_id: str,
        trace_id: str,
    ) -> TenantContext:
        if not self._has_admin_permission(claims):
            raise InvalidToken(
                f"Admin access requires permission '{self._admin_permission}'"
            )
        try:
            target_uuid = uuid.UUID(target_tenant_id)
        except ValueError:
            raise InvalidToken(
                f"X-Admin-Target-Tenant is not a valid UUID: {target_tenant_id!r}"
            )

        logger.info(
            "Admin context granted | sub=%s target=%s trace=%s",
            claims.get("sub"),
            target_tenant_id,
            trace_id,
        )

        return TenantContext(
            tenant_id=target_uuid,
            user_id=self._parse_uuid(claims.get("sub")),
            is_platform_admin=True,
            bypass_rls=True,
            trace_id=self._parse_uuid(trace_id) or uuid.uuid4(),
        )

    def _is_platform_admin(self, claims: dict) -> bool:
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        return self._admin_role in realm_roles

    def _has_admin_permission(self, claims: dict) -> bool:
        if self._admin_permission in claims.get("permissions", []):
            return True
        if self._admin_client_id:
            client_roles = (
                claims.get("resource_access", {})
                .get(self._admin_client_id, {})
                .get("roles", [])
            )
            if self._admin_permission in client_roles:
                return True
        return False

    def _extract_bearer(self, request: Request) -> str | None:
        auth = request.headers.get("Authorization", "")
        return auth[len("Bearer "):] if auth.startswith("Bearer ") else None

    def _get_trace_id(self, request: Request) -> str:
        for header in ("X-Request-ID", "X-Trace-ID"):
            value = request.headers.get(header)
            if value:
                try:
                    uuid.UUID(value)
                    return value
                except ValueError:
                    continue
        return str(uuid.uuid4())

    def _should_skip(self, path: str) -> bool:
        return path in self._skip_paths or path.startswith("/webhooks/")

    @staticmethod
    def _parse_uuid(value: str | None) -> uuid.UUID | None:
        try:
            return uuid.UUID(str(value)) if value else None
        except ValueError:
            return None