# ZeroTheft Python SDK

Shared Python packages for all ZeroTheft backend services.

## Packages

| Package | Path | Description |
|---------|------|-------------|
| `common` | `packages/common/` | Config, messaging, secrets management |
| `zerotheft-rls` | `packages/rls/` | FastAPI tenant RLS middleware for CockroachDB |

## Usage

Install from CodeArtifact:

```bash
pip install --index-url https://zerotheft-744561091152.d.codeartifact.us-east-1.amazonaws.com/pypi/zerotheft-python/simple/ common zerotheft-rls
```

Or in `requirements.txt`:

```txt
--index-url https://zerotheft-744561091152.d.codeartifact.us-east-1.amazonaws.com/pypi/zerotheft-python/simple/

common==0.1.0
zerotheft-rls==0.1.0
```

## Publishing

Packages are published automatically via GitHub Actions when a PR is merged to `main`.

## Rules

- Domains consume platform artifacts
- Domains never modify platform code
- All services must use platform observability
