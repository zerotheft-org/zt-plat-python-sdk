-- ==========================================================================
-- RLS Enforcement SQL — REFERENCE DOCUMENTATION ONLY
-- ==========================================================================
-- These policies are ALREADY APPLIED to the CockroachDB cluster via the
-- main migration scripts. This file exists as a readable reference for
-- the middleware team and security auditors.
--
-- DO NOT run this file directly. Changes go through the migration pipeline.
--
-- Actual schemas: core, iam, org, billing, comms, audit, security, internal
-- Login role:     app_service_dev (member of app_user)
-- RLS target:     app_user (NOLOGIN, NOBYPASSRLS)
-- Audit reader:   audit_reader (BYPASSRLS — SOC2 dashboard)
--
-- Session variable contract:
--   app.current_tenant  — UUID string set via SET LOCAL per-transaction
--   (app.bypass_rls removed — admin sees same RLS as tenant users)
--
-- internal.current_tenant_id() returns NULL when session var is empty/unset.
-- All policies compare against NULL → 0 rows, never an error, never a leak.
-- ==========================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 0. Helper functions (schema: internal)
-- ──────────────────────────────────────────────────────────────────────────

-- Returns NULL when session var is empty/unset → fail-closed.
-- SECURITY INVOKER: runs as the caller's role (app_user).
CREATE OR REPLACE FUNCTION internal.current_tenant_id()
RETURNS UUID AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- User-tenant helper: checks if a user row exists in the current tenant.
-- SECURITY DEFINER: runs as function owner to query iam.users through RLS.
CREATE OR REPLACE FUNCTION internal.user_in_current_tenant(p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM iam.users
    WHERE user_id = p_user_id
      AND tenant_id = internal.current_tenant_id()
      AND status = 'active'
  );
$$ LANGUAGE SQL STABLE SECURITY DEFINER;


-- ──────────────────────────────────────────────────────────────────────────
-- 1. Tenant-scoped tables (direct tenant_id match)
-- ──────────────────────────────────────────────────────────────────────────
-- Tables: core.tenants, core.tenant_settings, core.tenant_domains,
--         org.branches, org.departments, billing.subscriptions,
--         billing.invoices, billing.payment_methods, comms.notification_prefs,
--         comms.message_log, iam.users

-- Example (same pattern for all tenant-scoped tables):
--   ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE <table> FORCE ROW LEVEL SECURITY;
--   CREATE POLICY tenant_isolation ON <table>
--     AS PERMISSIVE FOR ALL TO app_user
--     USING  (tenant_id = internal.current_tenant_id())
--     WITH CHECK (tenant_id = internal.current_tenant_id());


-- ──────────────────────────────────────────────────────────────────────────
-- 2. User-linked tables (no direct tenant_id — uses helper function)
-- ──────────────────────────────────────────────────────────────────────────
-- Some schemas still keep user_id-only relationship tables that need helper
-- lookups into iam.users. iam.users itself is now tenant-scoped and can use a
-- direct tenant_id policy.

--   CREATE POLICY user_lookup_policy ON <table_without_tenant_id>
--     AS PERMISSIVE FOR ALL TO app_user
--     USING  (internal.user_in_current_tenant(user_id));

-- iam.users (tenant-scoped) now uses direct tenant filter:
--   CREATE POLICY tenant_isolation ON iam.users
--     AS PERMISSIVE FOR ALL TO app_user
--     USING  (tenant_id = internal.current_tenant_id())
--     WITH CHECK (tenant_id = internal.current_tenant_id());


-- ──────────────────────────────────────────────────────────────────────────
-- 3. Global tables (USING true — readable by any role)
-- ──────────────────────────────────────────────────────────────────────────
-- billing.plan_catalog

--   CREATE POLICY public_read ON billing.plan_catalog
--     AS PERMISSIVE FOR SELECT TO app_user
--     USING (true);
--   CREATE POLICY plan_catalog_write ON billing.plan_catalog
--     AS PERMISSIVE FOR INSERT TO app_user
--     WITH CHECK (true);


-- ──────────────────────────────────────────────────────────────────────────
-- 4. Audit events (tenant-scoped for app_user; BYPASSRLS for audit_reader)
-- ──────────────────────────────────────────────────────────────────────────
-- audit.audit_events

--   CREATE POLICY audit_tenant_isolation ON audit.audit_events
--     AS PERMISSIVE FOR ALL TO app_user
--     USING  (event_type = 'tenant' AND tenant_id = internal.current_tenant_id())
--     WITH CHECK (event_type = 'tenant' AND tenant_id = internal.current_tenant_id());


-- ──────────────────────────────────────────────────────────────────────────
-- 5. Security denials (write-only for app_user)
-- ──────────────────────────────────────────────────────────────────────────
-- security.rls_denials

--   CREATE POLICY denial_write_only ON security.rls_denials
--     AS PERMISSIVE FOR INSERT TO app_user
--     WITH CHECK (true);
-- (No SELECT policy — app_user cannot read denials)


-- ──────────────────────────────────────────────────────────────────────────
-- 6. Roles
-- ──────────────────────────────────────────────────────────────────────────
-- app_user:      NOLOGIN, NOBYPASSRLS — all RLS policies target this role
-- app_service_dev: LOGIN, MEMBER OF app_user — dev connection role
-- audit_writer:  NOLOGIN — reserved for future use
-- audit_reader:  NOLOGIN, BYPASSRLS — SOC2 dashboard reads all audit events
