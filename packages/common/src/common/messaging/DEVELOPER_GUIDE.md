# Publishing Audit Events — Developer Guide

How to wire a service into the audit pipeline using `common/messaging`
and `AuditPublisher`.

The full flow when everything is working:

```
Your service
  → AuditPublisher.some_event(...)
  → RabbitMQProducer.publish()
  → audit.events exchange (RabbitMQ)
  → audit-service RabbitMQConsumer
  → CockroachDB (append) + ImmuDB (verifiedSet)
  → tamper-evident, hash-chained audit log
```

---

## Prerequisites

Your service needs:
- `aio-pika>=9.0.0` in its dependencies (or `common[messaging]`)
- A RabbitMQ credential secret in AWS Secrets Manager (see [Secret shape](#2-add-the-secret))
- Access to the shared `audit.events` exchange on the audit broker

---

## 1. Add the dependency

```toml
# pyproject.toml
[project]
dependencies = [
    "common",           # already there
    "aio-pika>=9.0.0",  # add this
]
```

---

## 2. Add the secret

### AWS Secrets Manager (staging / production)

Create a secret named `{prefix}/{service}/rabbitmq-credentials`:

```json
{
  "user":     "your_service_user",
  "password": "your_password",
  "host":     "rabbitmq-audit.internal.example.com",
  "port":     5672,
  "vhost":    "/"
}
```

### Local dev (`.env`)

```bash
myservice/rabbitmq-credentials={"user":"guest","password":"guest","host":"localhost","port":5672,"vhost":"/"}
```

> This is the **audit broker** secret — separate from the secrets-subscriber
> broker config (`RABBITMQ_*` static vars in `.env`).

---

## 3. Add to `SECRET_ROUTING_MAP`

```python
# main.py
SECRET_ROUTING_MAP = {
    "rotation.db":       ["app/db-credentials"],
    "rotation.rabbitmq": ["myservice/rabbitmq-credentials"],  # ← add
    # ... any other secrets your service uses
}
```

---

## 4. Wire the producer in lifespan

```python
# main.py
from common.messaging import RabbitMQProducer, build_rabbitmq_url

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ... existing steps unchanged ...

    # Final step before yield: audit producer
    rabbitmq_creds = json.loads(secrets.get("myservice/rabbitmq-credentials"))
    audit_producer = RabbitMQProducer(
        broker_url=build_rabbitmq_url(rabbitmq_creds),
        exchange="audit.events",
        service_name="my-service",    # shows up in logs + AMQP app_id header
    )
    await audit_producer.warmup()
    state["audit_producer"] = audit_producer
    app.state.audit_producer = audit_producer

    yield

    # Teardown
    producer = state.get("audit_producer")
    if producer:
        await producer.disconnect()
```

---

## 5. Add the rotation callback

Inside `_make_rotation_callbacks()`:

```python
def on_rabbitmq_rotation() -> None:
    try:
        raw = json.loads(secrets.get("myservice/rabbitmq-credentials"))

        async def _restart():
            old = state.get("audit_producer")
            if old:
                try:
                    await old.disconnect()
                except Exception:
                    pass
            new_producer = RabbitMQProducer(
                broker_url=build_rabbitmq_url(raw),
                exchange="audit.events",
                service_name="my-service",
            )
            await new_producer.warmup()
            state["audit_producer"] = new_producer
            app.state.audit_producer = new_producer

        asyncio.run_coroutine_threadsafe(_restart(), loop).result(timeout=30)
    except Exception as exc:
        logger.error("RabbitMQ rotation callback failed: %s", exc, exc_info=True)

return {
    ...
    "rotation.rabbitmq": on_rabbitmq_rotation,
}
```

---

## 6. Create `AuditPublisher` for your service

`AuditPublisher` (`app/application/common/audit.py`) wraps the raw producer
and exposes named, domain-meaningful methods. Use cases call
`self._audit.user_created(...)` and never touch routing keys or body shapes.

Create the file if it doesn't exist:

```python
# app/application/common/audit.py
from __future__ import annotations
import logging
from typing import Any
from common.messaging import RabbitMQProducer

logger = logging.getLogger(__name__)


class AuditPublisher:

    def __init__(self, producer: RabbitMQProducer) -> None:
        self._producer = producer

    # Add one method per event your service needs to publish.
    # Routing key and body shape live here — nowhere else.

    async def user_created(
        self,
        tenant_id: str,
        actor_user_id: str,
        user_id: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        await self._publish(
            routing_key="audit.tenant.user_created",
            event_type="tenant",
            action="user.created",
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            resource=f"user:{user_id}",
            payload=payload,
        )

    # ── Core publish — private ─────────────────────────────────────────

    async def _publish(
        self,
        routing_key: str,
        event_type: str,
        action: str,
        tenant_id: str | None = None,
        actor_user_id: str | None = None,
        resource: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort — logs on failure, never raises."""
        try:
            body: dict[str, Any] = {
                "event_type": event_type,
                "action": action,
                "actor_user_id": actor_user_id,
                "resource": resource,
                "payload": payload or {},
            }
            if tenant_id:
                body["tenant_id"] = tenant_id

            await self._producer.publish(
                routing_key=routing_key,
                body=body,
                correlation_id=actor_user_id,
            )
        except Exception as exc:
            logger.error(
                "audit_publish_failed routing_key=%s action=%s error=%s",
                routing_key, action, exc,
            )
```

> The auth service already has a full `AuditPublisher` in
> `app/application/common/audit.py` with methods for tenant and user events.
> Check there first before adding a new method — it may already exist.

---

## 7. Add the FastAPI dependency

```python
# app/interface/api/dependencies/dependencies.py
from fastapi import Depends, Request
from app.application.common.audit import AuditPublisher
from common.messaging import RabbitMQProducer


def _get_audit_producer(request: Request) -> RabbitMQProducer:
    return request.app.state.audit_producer


def get_audit_publisher(
    producer: RabbitMQProducer = Depends(_get_audit_producer),
) -> AuditPublisher:
    return AuditPublisher(producer)
```

---

## 8. Inject into use cases via routes

### Route

```python
from app.application.common.audit import AuditPublisher
from app.interface.api.dependencies.dependencies import get_audit_publisher

@router.post("/something")
async def create_something(
    body: CreateSomethingRequest,
    db: AsyncSession = Depends(get_db),
    user_info: dict = Depends(decode_jwt_token),
    audit: AuditPublisher = Depends(get_audit_publisher),
):
    use_case = CreateSomethingUseCase(
        db=db,
        ...,
        audit=audit,
    )
    return await use_case.execute(...)
```

### Use case

```python
from app.application.common.audit import AuditPublisher

class CreateSomethingUseCase:

    def __init__(self, ..., audit: AuditPublisher) -> None:
        self._audit = audit

    async def execute(self, ...):
        # ... do the work, commit the DB ...

        await self._audit.user_created(
            tenant_id=str(tenant_id),
            actor_user_id=str(actor_id),
            user_id=str(new_user.id),
            payload={"email": email},
        )
```

---

## 9. Adding a new event

Everything lives in `audit.py`. No other files change:

```python
# app/application/common/audit.py

async def branch_created(
    self,
    tenant_id: str,
    actor_user_id: str,
    branch_id: str,
    branch_name: str,
) -> None:
    await self._publish(
        routing_key="audit.tenant.branch_created",
        event_type="tenant",
        action="branch.created",
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        resource=f"branch:{branch_id}",
        payload={"branch_name": branch_name},
    )
```

Then in your use case: `await self._audit.branch_created(...)`.

---

## Routing key convention

```
audit.{event_type}.{action_verb}

audit.global.user_login
audit.global.user_login_failed
audit.tenant.user_created
audit.tenant.user_invited
audit.tenant.user_removed
audit.tenant.role_assigned
audit.tenant.role_revoked
audit.tenant.provisioned
audit.tenant.provision_failed
audit.tenant.bootstrapped
audit.system.config_changed
audit.system.service_boot
```

The audit service consumer binding is `audit.#` — any key starting with
`audit.` is delivered automatically.

---

## Event body reference

| Field | Required | Notes |
|---|---|---|
| `event_type` | ✓ | `global`, `tenant`, or `system` |
| `action` | ✓ | Dot-separated verb, e.g. `user.created` |
| `tenant_id` | Required when `event_type=tenant` | UUID string |
| `actor_user_id` | Recommended | UUID of the user performing the action |
| `resource` | Recommended | `"{entity}:{id}"`, e.g. `"user:abc-123"` |
| `payload` | Optional | Any JSON-serialisable dict with extra context |

The audit service enforces these — `event_type=tenant` without `tenant_id`
causes the message to be nacked and dead-lettered.

---

## Local development

With `SECRETS_PROVIDER=env` the producer connects to whatever broker is in
`myservice/rabbitmq-credentials`. You need RabbitMQ running locally:

```bash
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
```

The audit service must also be running to consume and process events.
To verify messages are flowing without the full audit service, check the
RabbitMQ management UI at `http://localhost:15672`.

---

## Checklist

- [ ] `aio-pika>=9.0.0` in `pyproject.toml`
- [ ] Secret created in AWS Secrets Manager (correct JSON shape)
- [ ] Secret added to `.env` for local dev (JSON string value)
- [ ] `rotation.rabbitmq` added to `SECRET_ROUTING_MAP` in `main.py`
- [ ] Producer wired in `lifespan` with rotation callback
- [ ] `get_audit_publisher` dependency added to `dependencies.py`
- [ ] `AuditPublisher` created at `app/application/common/audit.py`
- [ ] Method added to `AuditPublisher` for each new event
- [ ] Use case accepts `audit: AuditPublisher` in `__init__`
- [ ] Route injects `audit: AuditPublisher = Depends(get_audit_publisher)`
- [ ] Routing key follows `audit.{event_type}.{action}` convention
- [ ] `tenant_id` included whenever `event_type=tenant`