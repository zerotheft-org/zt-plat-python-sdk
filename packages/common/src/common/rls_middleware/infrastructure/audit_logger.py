from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import text

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, session_factory=None) -> None:
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
        if not self._session_factory:
            logger.debug("AuditLogger: no session_factory configured, skipping write")
            return

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