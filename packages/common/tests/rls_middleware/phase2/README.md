# Phase 2 — Integration Tests

Run AFTER Phase 1 unit tests all pass AND after the RLS SQL block has been
executed against CRDB.

## Requirements

- `CRDB_TEST_URL` — app-level connection (e.g. `app_service_dev`, member of `app_user`)
- `CRDB_ADMIN_URL` — admin connection (e.g. `crdb`, member of `admin` / BYPASSRLS)
- All migrations and RLS enforcement SQL already applied to the target DB

## Acceptance Criteria

| ID | Scenario | Test file | Status |
|---|---|---|---|
| C1 | Tenant A queries tenant-scoped table with Tenant B's data → 0 rows | `test_tenant_isolation.py` | ✅ |
| C2 | Missing/invalid JWT → HTTP 403, zero DB calls | `test_http_403_no_db.py` | ✅ |
| C3 | Any tenant reads `billing.plan_catalog` → succeeds | `test_global_tables.py` | ✅ |
| C4 | Any denial → row in `security.rls_denials` with matching `trace_id` | `test_denial_db_write.py` | ✅ |
| C5 | Admin + `X-Admin-Target-Tenant` → access granted + audit event | `test_admin_audit.py` | ✅ |

## Test Files

```
tests/phase2/
├── conftest.py                # CRDB dual-engine setup, session factories, seed/cleanup
├── test_tenant_isolation.py   # C1: cross-tenant access returns 0 rows
├── test_http_403_no_db.py     # C2: missing/invalid JWT → 403, zero DB queries
├── test_global_tables.py      # C3: plan_catalog readable by all tenants
├── test_denial_db_write.py    # C4: denial records written to rls_denials
├── test_admin_audit.py        # C5: admin access writes to audit.audit_events
└── test_user_tenant_isolation.py  # Tenant-scoped iam.users + external_auth_id lookup
```

## Running

```bash
# Phase 2 only (requires CRDB connection)
uv run pytest tests/phase2/ -v

# Full suite (Phase 1 + Phase 2)
uv run pytest tests/ -v
```

## Dual-Engine Architecture

Phase 2 uses two separate DB connections:

- **test_engine** (`CRDB_TEST_URL` / `app_service_dev`) — Subject to RLS.
  Used for all test sessions that exercise RLS policies.
- **admin_engine** (`CRDB_ADMIN_URL` / `crdb`) — Bypasses RLS.
  Used for seed/cleanup and verification reads (e.g. reading
  `security.rls_denials` which `app_user` cannot SELECT).

## Known xfails

- None in-repo. If an environment is missing `iam.users` tenant RLS policies,
  tenant visibility assertions in `test_user_tenant_isolation.py` may fail closed (0 rows).
