"""
C3 — Global Tables (Integration)

Verifies that billing.plan_catalog (no tenant_id column, global read access)
is visible to all tenants and even without a tenant context.

Uses actual billing.plan_catalog with RLS policy:
  FOR SELECT USING (true)          — any role can read
  FOR INSERT WITH CHECK (true)     — seeding
"""
from __future__ import annotations

from sqlalchemy import text


class TestGlobalTableAccess:

    def test_tenant_a_reads_all_plans(self, tenant_a_session):
        """C3: Any tenant reads billing.plan_catalog → sees all rows."""
        rows = tenant_a_session.execute(
            text("SELECT name FROM billing.plan_catalog ORDER BY name")
        ).fetchall()
        names = [r[0] for r in rows]
        # At minimum the 3 seeded plans; real DB may have more
        assert "Free" in names
        assert "Pro" in names
        assert "Enterprise" in names

    def test_tenant_b_reads_all_plans(self, tenant_b_session):
        """Different tenant sees the same global catalog."""
        count = tenant_b_session.execute(
            text("SELECT count(*) FROM billing.plan_catalog")
        ).scalar()
        assert count >= 3  # our 3 seeded + any pre-existing

    def test_no_context_can_still_read_global_table(self, no_tenant_session):
        """
        Global tables use USING(true) — even missing context doesn't block reads.
        This ensures health checks or background jobs can read shared metadata.
        """
        count = no_tenant_session.execute(
            text("SELECT count(*) FROM billing.plan_catalog")
        ).scalar()
        assert count >= 3
