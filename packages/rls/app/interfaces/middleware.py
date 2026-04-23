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
    """
    FastAPI middleware that enforces tenant isolation for every HTTP request.

    Execution order per request
    ---------------------------
    1. Skip check  — health/docs/webhook paths pass through untouched
    2. Extract     — read Bearer token from Authorization header
    3. Verify      — validate JWT signature + claims via Keycloak JWKS
    4. Resolve     — build TenantContext (user or admin)
    5. Propagate   — write tenant_id to ContextVar
    6. Call next   — route handler runs; SQLAlchemy listener fires SET LOCAL
    7. Clear       — always clear ContextVar in finally block

    FAIL-CLOSED guarantee
    ---------------------
    Any exception in steps 1–5 returns HTTP 403. Never 500.
    Zero DB calls are made on rejection.
    The finally block always clears context — even if the route handler raised.

    Platform admin access
    ----------------------
    Admins must provide X-Admin-Target-Tenant header.
    JWT must have platform_admin realm role AND tenant:investigate permission.
    The middleware sets app.current_tenant to the target tenant UUID.
    The DB sees the admin session as a normal tenant session — same RLS.
    bypass_rls=True on TenantContext is an application-layer flag only,
    used for PII masking in route handlers. It is NEVER sent to the DB.

    Registration
    ------------
    Register AFTER CORS/logging middleware — this runs closest to handlers.

        app.add_middleware(
            TenantRLSMiddleware,
            token_verifier=KeycloakTokenVerifier(),
            denial_logger=DenialLogger(session_factory=SessionLocal),
        )
    """

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
        # ── 1. Skip paths / enforcement toggle ─────────────────────────────
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

        # ── 2–4. Extract + Verify + Resolve ───────────────────────────────
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
            # FAIL-CLOSED: unexpected crash → 403, never 500
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

        # ── 5. Propagate via ContextVar ────────────────────────────────────
        # bypass_rls is stored for application-layer use (PII masking etc).
        # The SQLAlchemy listener reads only tenant_id — bypass_rls is never
        # sent to the DB session.
        set_tenant_context(
            tenant_id=ctx.tenant_id_str,
            bypass_rls=ctx.bypass_rls,
            trace_id=ctx.trace_id_str,
        )
        request.state.tenant_context = ctx

        # ── 6 + 7. Call route handler, always clear context ────────────────
        try:
            return await call_next(request)
        finally:
            clear_tenant_context()

    # ── Context resolution ─────────────────────────────────────────────────

    async def _resolve_context(self, request: Request, trace_id: str) -> TenantContext:
        """
        Extract token, verify with Keycloak, build TenantContext.
        All failures raise _TenantContextError which dispatch catches.
        """
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

        # Platform admin path — requires both role AND permission AND header
        admin_target = request.headers.get("X-Admin-Target-Tenant")
        if self._is_platform_admin(claims) and admin_target:
            ctx = self._build_admin_context(claims, admin_target, trace_id)
            # Mandatory audit: every admin-targeted request is logged
            # BEFORE the response is returned (GDPR/SOC2 requirement).
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
        """
        Build context for a standard tenant user.

        Reads a single tenant_id claim from the JWT.
        One token = one tenant. User selects active tenant at login;
        JWT is scoped to that one tenant for the session duration.
        """
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
        """
        Build context for a platform admin targeting a specific tenant.

        The admin does NOT get DB-level bypass.
        app.current_tenant is set to the target UUID — RLS is identical.
        bypass_rls=True is an application-layer flag for route handlers only.

        Audit logging is handled by the caller (_resolve_context) immediately
        after this method returns — before the response is sent.
        """
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
            bypass_rls=True,  # application-layer only — NOT sent to DB
            trace_id=self._parse_uuid(trace_id) or uuid.uuid4(),
        )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _is_platform_admin(self, claims: dict) -> bool:
        """
        Check platform_admin in realm_access.roles.
        This is a Keycloak realm-level role. If your team configured it as
        a client role it will be in resource_access.<client_id>.roles instead.
        """
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        return self._admin_role in realm_roles

    def _has_admin_permission(self, claims: dict) -> bool:
        """
        Check tenant:investigate in either:
          - A custom 'permissions' claim (Keycloak mapper)  [preferred]
          - resource_access.<admin_client_id>.roles          [fallback]
        """
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
        """
        Use upstream trace ID if provided and it's a valid UUID,
        otherwise generate one. The DB columns (audit.audit_events.trace_id,
        security.rls_denials.trace_id) are UUID type, so we must ensure the
        value is always a valid UUID string.
        """
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
