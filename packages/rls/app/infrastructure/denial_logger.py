from __future__ import annotations

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


class DenialLogger:
    """
    Writes RLS denial events to security.rls_denials.

    Why a separate session factory
    --------------------------------
    When a denial is logged, the request's own DB session may already be in
    a rolled-back or closed state (e.g. after an RLS violation). We accept a
    session_factory callable so we can always open a fresh, independent session
    that commits on its own — completely isolated from the failing request.

    Fire-and-forget contract
    ------------------------
    This class NEVER raises. Any write failure is logged to the application
    logger only. A logging failure must never change the 403 already being
    returned to the client.

    Usage
    -----
        denial_logger = DenialLogger(session_factory=SessionLocal)
        denial_logger.log_denial(
            trace_id="...",
            tenant_id="...",
            user_id="...",
            action="SELECT",
            resource="billing.invoices",
        )
    """

    def __init__(self, session_factory) -> None:
        """
        Parameters
        ----------
        session_factory : callable
            A zero-argument callable that returns a SQLAlchemy Session
            (or context manager). Typically `SessionLocal` from your service.
        """
        self._session_factory = session_factory

    def log_denial(
        self,
        *,
        trace_id: str | None = None,
        tenant_id: str | None = None,
        user_id: str | None = None,
        action: str | None = None,
        resource: str | None = None,
    ) -> None:
        """
        Write one denial record to security.rls_denials.

        Parameters
        ----------
        trace_id : str | None
            Correlates this denial with the 403 response body and app logs.
            Always set for middleware rejections; may be None for DB-level denials
            caught before trace_id is resolved.
        tenant_id : str | None
            Active tenant UUID when denial occurred.
            None if rejection happened before tenant context was resolved
            (e.g. missing JWT, malformed Authorization header).
        user_id : str | None
            Keycloak `sub` claim — the human who triggered the denial.
            None if JWT was missing or invalid.
        action : str | None
            What was attempted:
              MIDDLEWARE_REJECT  — rejected by middleware (no/bad JWT)
              MIDDLEWARE_ERROR   — unexpected middleware crash
              SELECT / INSERT / UPDATE / DELETE  — DB-level RLS denial
        resource : str | None
            Table name (e.g. "billing.invoices") or request path ("/api/invoices").
        """
        try:
            with self._session_factory() as session:
                session.execute(
                    text("""
                        INSERT INTO security.rls_denials
                            (tenant_id, user_id, action, resource, trace_id)
                        VALUES
                            (:tenant_id, :user_id, :action, :resource, :trace_id)
                    """),
                    {
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "action": action,
                        "resource": resource,
                        "trace_id": trace_id,
                    },
                )
                session.commit()
        except Exception as exc:
            logger.error(
                "Failed to write denial record | trace=%s error=%s",
                trace_id,
                exc,
                exc_info=True,
            )
