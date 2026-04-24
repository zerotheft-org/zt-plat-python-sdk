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

## Development

```bash
cd packages/common
pip install hatch
hatch env create
hatch run pytest tests/ -v
```

## Publishing

Packages are automatically built and published to AWS CodeArtifact on merge to `main`.

