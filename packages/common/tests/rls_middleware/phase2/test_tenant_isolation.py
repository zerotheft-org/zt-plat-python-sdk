"""
C1 — Tenant Isolation (Integration)

Verifies at the DB level:
  - Tenant A sees only its own row in core.tenants
  - Tenant A cannot see Tenant B's data via explicit WHERE
  - No tenant context → 0 rows (fail-closed)

Uses actual core.tenants table with RLS policy:
  USING (tenant_id = internal.current_tenant_id())
"""
from __future__ import annotations

from sqlalchemy import text

from tests.rls_middleware.phase2.conftest import TENANT_A, TENANT_B


class TestCrossTenantIsolation:

    def test_tenant_a_sees_own_tenant(self, tenant_a_session):
        """Tenant A should see exactly their own tenant row."""
        rows = tenant_a_session.execute(
            text("SELECT tenant_id::TEXT, name FROM core.tenants")
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == TENANT_A
        assert rows[0][1] == "RLS Test Tenant A"

    def test_tenant_a_cannot_see_tenant_b(self, tenant_a_session):
        """
        C1: Tenant A queries core.tenants filtered by Tenant B's ID → 0 rows.
        No error, just empty. This is the core RLS guarantee.
        """
        rows = tenant_a_session.execute(
            text("SELECT * FROM core.tenants WHERE tenant_id = :tid"),
            {"tid": TENANT_B},
        ).fetchall()
        assert len(rows) == 0

    def test_tenant_b_sees_own_tenant(self, tenant_b_session):
        """Tenant B should see exactly their own tenant row."""
        rows = tenant_b_session.execute(
            text("SELECT tenant_id::TEXT, name FROM core.tenants")
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == TENANT_B
        assert rows[0][1] == "RLS Test Tenant B"

    def test_tenant_b_cannot_see_tenant_a(self, tenant_b_session):
        """Reverse direction: Tenant B also cannot see Tenant A's data."""
        rows = tenant_b_session.execute(
            text("SELECT * FROM core.tenants WHERE tenant_id = :tid"),
            {"tid": TENANT_A},
        ).fetchall()
        assert len(rows) == 0


class TestFailClosedAtDbLevel:

    def test_no_context_returns_zero_rows(self, no_tenant_session):
        """
        When app.current_tenant is '' → internal.current_tenant_id() returns NULL
        → UUID equality is false → 0 rows. This is the fail-closed guarantee.
        """
        rows = no_tenant_session.execute(
            text("SELECT * FROM core.tenants")
        ).fetchall()
        assert len(rows) == 0

    def test_no_context_does_not_raise_error(self, no_tenant_session):
        """
        Fail-closed must be silent — 0 rows, not a SQL error.
        If this raised, the test would fail before the assertion.
        """
        result = no_tenant_session.execute(
            text("SELECT count(*) FROM core.tenants")
        ).scalar()
        assert result == 0
