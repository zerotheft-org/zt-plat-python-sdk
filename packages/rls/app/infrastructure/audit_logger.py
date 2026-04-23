"""
AuditLogger — writes admin access events to audit.audit_events.

Every platform admin "target" request triggers a high-priority audit log
entry linking the admin_id, target_tenant_id, and reason_code.
Required per GDPR/SOC2 compliance.

Uses its own session factory (same pattern as DenialLogger) so it can
commit independently of the request's transaction.

RLS constraint (actual policy on audit.audit_events for app_user):
  WITH CHECK (event_type = 'tenant' AND tenant_id = internal.current_tenant_id())

This means the session must SET LOCAL app.current_tenant = target_tenant_id
BEFORE the INSERT, so the RLS check passes. Admin context information
(actor, reason, target) is stored in the payload JSONB column.
"""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import text

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Writes admin access audit events to audit.audit_events.

    Fire-and-forget for the HTTP response path: write failures are logged
    but never change the response status code. However, for SOC2 compliance
    the calling code should treat a failure as a high-severity alert.

    Usage
    -----
        audit_logger = AuditLogger(session_factory=SessionLocal)
        audit_logger.log_admin_access(
            actor_user_id="...",
            target_tenant_id="...",
            reason_code="tenant:investigate",
            trace_id="...",
        )
    """

    def __init__(self, session_factory=None) -> None:
        """
        Parameters
        ----------
        session_factory : callable | None
            A zero-argument callable that returns a SQLAlchemy Session
            (or context manager). If None, audit logging is disabled
            (useful for unit tests in Phase 1).
        """
        self._session_factory = session_factory

    def log_admin_access(
        self,
        *,
        actor_user_id: str | None = None,
        target_tenant_id: str | None = None,
        reason_code: str | None = None,
        trace_id: str | None = None,
        resource: str | None = None,
    ) -> None:
        """
        Write one admin access audit event to audit.audit_events.

        The actual table schema uses:
          - event_type   = 'tenant'  (required by RLS WITH CHECK)
          - tenant_id    = target    (required by RLS WITH CHECK)
          - actor_user_id            (admin's Keycloak sub)
          - action       = 'admin_access'
          - resource                 (request path)
          - trace_id                 (UUID correlation ID)
          - payload      = JSONB     (reason_code + admin context)

        The session must SET LOCAL app.current_tenant = target_tenant_id
        before the INSERT, because the RLS policy enforces:
          tenant_id = internal.current_tenant_id()
        """
        if not self._session_factory:
            logger.debug("AuditLogger: no session_factory configured, skipping write")
            return

        # Validate target_tenant_id is a UUID before string interpolation
        # (defense-in-depth; middleware already validates upstream)
        if target_tenant_id:
            try:
                uuid.UUID(target_tenant_id)
            except ValueError:
                logger.error(
                    "AuditLogger: invalid target_tenant_id UUID: %s",
                    target_tenant_id,
                )
                return

        try:
            with self._session_factory() as session:
                # SET LOCAL so RLS WITH CHECK passes:
                # event_type = 'tenant' AND tenant_id = current_tenant_id()
                if target_tenant_id:
                    session.execute(
                        text(
                            "SELECT set_config('app.current_tenant', :tenant_id, true)"
                        ),
                        {"tenant_id": target_tenant_id},
                    )
                session.execute(
                    text("""
                        INSERT INTO audit.audit_events
                            (event_type, tenant_id, actor_user_id, action,
                             resource, trace_id, payload)
                        VALUES
                            (:event_type, :tenant_id, :actor_user_id, :action,
                             :resource, :trace_id, CAST(:payload AS JSONB))
                    """),
                    {
                        "event_type": "tenant",
                        "tenant_id": target_tenant_id,
                        "actor_user_id": actor_user_id,
                        "action": "admin_access",
                        "resource": resource,
                        "trace_id": trace_id,
                        "payload": json.dumps({
                            "reason_code": reason_code,
                            "admin_user_id": actor_user_id,
                            "target_tenant_id": target_tenant_id,
                        }),
                    },
                )
                session.commit()
            logger.info(
                "Admin audit event written | actor=%s target=%s trace=%s",
                actor_user_id,
                target_tenant_id,
                trace_id,
            )
        except Exception as exc:
            logger.error(
                "Failed to write admin audit event | actor=%s target=%s trace=%s error=%s",
                actor_user_id,
                target_tenant_id,
                trace_id,
                exc,
                exc_info=True,
            )
