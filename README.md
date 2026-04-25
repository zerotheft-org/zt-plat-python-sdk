# zt-plat-python-sdk

ZeroTheft shared Python platform SDK.

## Packages

| Package | Path | Description |
|---------|------|-------------|
| `common` | `packages/common/` | Shared platform library: config, secrets, messaging, telemetry, RLS middleware |

## Contents

### `common`
- **`config`** — Pydantic-based configuration management
- **`secrets`** — Secret manager with pluggable providers (Env, AWS) and pub/sub invalidation (Redis, RabbitMQ)
- **`messaging`** — Async messaging producer with aio-pika
- **`telemetry`** — OpenTelemetry instrumentation helpers
- **`rls_middleware`** — FastAPI middleware for tenant row-level security (RLS) with CockroachDB

---

## Local Development

### Prerequisites

- Python `>=3.12`
- [Hatch](https://hatch.pypa.io/) (`pip install hatch`)

### Setup

```bash
cd packages/common
hatch env create
hatch run pytest tests/ -v
```

### Running a subset of tests

```bash
hatch run pytest tests/test_telemetry.py -v
```

---

## Repository Structure

```
packages/common/
├── pyproject.toml          # Package metadata, deps, build config
├── src/common/
│   ├── __init__.py
│   ├── config/
│   ├── secrets/
│   ├── messaging/
│   ├── telemetry/
│   └── rls_middleware/
└── tests/
    ├── __init__.py         # Required for pytest path resolution
    ├── test_config.py
    ├── test_secrets.py
    ├── test_messaging.py
    ├── test_telemetry.py
    └── test_rls_middleware.py
```

> **Important:** `tests/__init__.py` must exist. Without it, `pytest` may fail with `ModuleNotFoundError: No module named 'tests'`.

---

## Adding a New Module

1. Create the package directory under `src/common/<module>/`
2. Add an `__init__.py` with the public API
3. Write tests in `tests/test_<module>.py`
4. Update `pyproject.toml` if new runtime dependencies are needed
5. Run the full test suite locally:
   ```bash
   hatch run pytest tests/ -v
   ```

---

## Versioning & Publishing

`common` is published to **AWS CodeArtifact** (`zt-python` repository in the Shared-Services account).

### How Publishing Works

On every merge to `main` that touches `packages/common/**` or `.github/workflows/ci.yml`:

1. **Test** — Runs `pytest` via Hatch
2. **Build** — Creates a Python wheel (`python -m build`)
3. **Publish** — Uploads to CodeArtifact via `twine`

> **You do not need to publish manually.** The CI pipeline handles it automatically.

### Bumping the Version

Before merging changes that should be consumable by backend services, bump the version in `packages/common/pyproject.toml`:

```toml
[project]
name = "common"
version = "0.1.5"   # <-- bump this
```

Follow [SemVer](https://semver.org/):
- **Patch** (`0.1.4` → `0.1.5`) — Bug fixes, internal changes
- **Minor** (`0.1.4` → `0.2.0`) — New features, backward-compatible additions
- **Major** (`0.1.4` → `1.0.0`) — Breaking changes

> **Note:** CodeArtifact does **not** allow overwriting an existing version. If you forget to bump and CI fails with `409 Conflict`, increment the version and push again.

### Checking Published Versions

```bash
aws codeartifact list-package-versions \
  --domain zt \
  --domain-owner 744561091152 \
  --repository zt-python \
  --package common \
  --format pypi
```

---

## Consuming `common` in a Backend Service

### 1. Add to `requirements.txt`

```text
fastapi>=0.100.0
uvicorn[standard]>=0.23.0
common>=0.1.0
```

Pin to a minimum version that includes the features you need:

```text
common>=0.1.4
```

### 2. Import in your code

```python
from common.telemetry import setup_tracing
from common.rls_middleware import TenantContext
from common.config import Settings
```

### 3. Local development without CodeArtifact

If you are developing `common` and a backend service simultaneously, install `common` in editable mode:

```bash
cd zt-plat-python-sdk/packages/common
pip install -e .
```

Then work on the backend service normally. Changes to `common` will be reflected immediately.

### 4. CI / Docker build

The backend service CI pipeline automatically authenticates to CodeArtifact and passes the private pip index to the Docker build. No extra configuration is needed in the service repo beyond specifying `common>=x.y.z` in `requirements.txt`.

See [zt-plat-github-workflows/README.md](https://github.com/zerotheft-org/zt-plat-github-workflows/blob/main/README.md) for details on the Docker build process.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pytest: not found` in CI | Hatch default env missing `dev` features | Ensure `pyproject.toml` has `[tool.hatch.envs.default] features = ["dev"]` |
| `ModuleNotFoundError: No module named 'tests'` | Missing `tests/__init__.py` | Add an empty `__init__.py` in `tests/` |
| `409 Conflict` on publish | Version already exists in CodeArtifact | Bump `version` in `pyproject.toml` |
| `AccessDeniedException: codeartifact:GetAuthorizationToken` | Wrong domain/repo name | Verify `CODEARTIFACT_DOMAIN=zt` and `CODEARTIFACT_REPO=zt-python` |
| Backend CI fails to install `common` | Smoke test or Dockerfile issue | Check that `CODEARTIFACT_INDEX_URL` and `CODEARTIFACT_TOKEN` build args are passed correctly |
| `python-jose` CVE warnings | Deprecated dependency with known CVEs | Use `PyJWT>=2.8.0` instead (already done in `common>=0.1.4`) |

---

## Architecture Decision Records

### Why CodeArtifact instead of PyPI?

- **Private packages** — `common` contains internal abstractions (RLS middleware, telemetry) that should not be public.
- **IAM integration** — CodeArtifact uses the same OIDC role as ECR, simplifying CI setup.
- **Upstream proxying** — `zt-python` proxies PyPI, so backends can use a single index for both public and private packages.

### Why Hatch instead of Poetry / pip?

- **PEP 621 compliance** — Standard `pyproject.toml` metadata.
- **Editable installs** — `pip install -e .` works out of the box.
- **Environment management** — Built-in venv handling without extra tooling.

---

## Contributing

1. Open a branch from `main`
2. Make changes + add tests
3. Run `hatch run pytest tests/ -v` locally
4. Bump version in `pyproject.toml` if the change should be published
5. Open a PR — CI will test but **will not publish** until merged to `main`
6. After merge, verify the new version appears in CodeArtifact
