"""
C5 — Admin Audit (Integration)

Verifies that:
  - AuditLogger writes a row to audit.audit_events as app_user
  - The row contains actor_user_id, tenant_id, action, payload (JSONB)
  - trace_id is propagated (UUID column)
  - event_type = 'tenant' (required by RLS WITH CHECK for app_user)
  - Tenant-scoped audit events are visible to the owning tenant
  - System audit events are NOT visible to app_user

The audit_tenant_isolation policy on audit.audit_events:
  USING  (event_type = 'tenant' AND tenant_id = internal.current_tenant_id())
  WITH CHECK (same)
"""
from __future__ import annotations

import json
import uuid

from sqlalchemy import text

from app.infrastructure.audit_logger import AuditLogger
from tests.phase2.conftest import ADMIN_USER, TENANT_A, TRACE_SEED_A


class TestAdminAuditWrite:

    def test_admin_access_creates_audit_event(
        self, app_user_session_factory, raw_session,
    ):
        """
        C5: Admin + X-Admin-Target-Tenant → row in audit.audit_events
        with event_type='tenant', correct tenant_id, and payload JSONB.
        """
        trace = str(uuid.uuid4())

        logger = AuditLogger(session_factory=app_user_session_factory)
        logger.log_admin_access(
            actor_user_id=ADMIN_USER,
            target_tenant_id=TENANT_A,
            reason_code="tenant:investigate",
            trace_id=trace,
            resource="/api/projects",
        )

        row = raw_session.execute(
            text("""
                SELECT event_type, tenant_id::TEXT, actor_user_id::TEXT,
                       action, resource, trace_id::TEXT, payload
                FROM audit.audit_events
                WHERE trace_id = :tid
            """),
            {"tid": trace},
        ).fetchone()

        assert row is not None
        assert row[0] == "tenant"              # event_type
        assert row[1] == TENANT_A              # tenant_id
        assert row[2] == ADMIN_USER            # actor_user_id
        assert row[3] == "admin_access"        # action
        assert row[4] == "/api/projects"       # resource
        assert row[5] == trace                 # trace_id

        # Payload JSONB contains reason_code and admin context
        payload = row[6] if isinstance(row[6], dict) else json.loads(row[6])
        assert payload["reason_code"] == "tenant:investigate"
        assert payload["admin_user_id"] == ADMIN_USER
        assert payload["target_tenant_id"] == TENANT_A

    def test_audit_event_has_created_at(
        self, app_user_session_factory, raw_session,
    ):
        """Audit event must have a timestamp (DB default: now())."""
        trace = str(uuid.uuid4())

        logger = AuditLogger(session_factory=app_user_session_factory)
        logger.log_admin_access(
            actor_user_id=ADMIN_USER,
            target_tenant_id=TENANT_A,
            reason_code="tenant:investigate",
            trace_id=trace,
        )

        row = raw_session.execute(
            text("SELECT created_at FROM audit.audit_events WHERE trace_id = :tid"),
            {"tid": trace},
        ).fetchone()
        assert row is not None
        assert row[0] is not None

    def test_audit_write_failure_does_not_raise(self):
        """Fire-and-forget: AuditLogger must never raise on write failure."""
        def bad_factory():
            raise RuntimeError("DB unreachable")

        logger = AuditLogger(session_factory=bad_factory)
        # Must not raise
        logger.log_admin_access(
            actor_user_id=ADMIN_USER,
            target_tenant_id=TENANT_A,
            reason_code="tenant:investigate",
            trace_id=str(uuid.uuid4()),
        )

    def test_audit_logger_without_session_factory_is_noop(self):
        """AuditLogger with no session_factory should silently skip."""
        logger = AuditLogger()  # no session_factory
        # Must not raise
        logger.log_admin_access(
            actor_user_id=ADMIN_USER,
            target_tenant_id=TENANT_A,
            reason_code="tenant:investigate",
            trace_id=str(uuid.uuid4()),
        )


class TestAuditEventVisibility:

    def test_tenant_sees_own_audit_events(self, tenant_a_session):
        """
        Tenant-scoped audit events (event_type='tenant', matching tenant_id)
        are visible to the owning tenant via app_user.
        """
        rows = tenant_a_session.execute(
            text("""
                SELECT trace_id::TEXT
                FROM audit.audit_events
                WHERE event_type = 'tenant'
            """)
        ).fetchall()
        traces = [r[0] for r in rows]
        assert TRACE_SEED_A in traces

    def test_tenant_cannot_see_system_audit_events(self, tenant_a_session):
        """
        Non-tenant audit events (event_type='system') are hidden from
        app_user — the RLS policy only permits event_type='tenant'.
        """
        rows = tenant_a_session.execute(
            text("SELECT * FROM audit.audit_events WHERE event_type = 'system'")
        ).fetchall()
        assert len(rows) == 0

    def test_raw_session_sees_all_audit_events(self, raw_session):
        """
        Admin session (no SET ROLE) bypasses RLS entirely —
        can read both tenant and system events. This is how
        the audit_reader role works in production.
        """
        from tests.phase2.conftest import TRACE_SEED_SYSTEM
        rows = raw_session.execute(
            text("""
                SELECT DISTINCT event_type
                FROM audit.audit_events
                WHERE trace_id IN (:t1, :t2)
            """),
            {"t1": TRACE_SEED_A, "t2": TRACE_SEED_SYSTEM},
        ).fetchall()
        types = {r[0] for r in rows}
        assert "tenant" in types
        assert "system" in types
