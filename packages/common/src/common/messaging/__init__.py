"""
common.messaging
================
Shared async RabbitMQ producer for publishing messages across services.

Quick start:

    from common.messaging import RabbitMQProducer, build_rabbitmq_url

    # In bootstrap, after fetching credentials from secrets manager:
    creds = json.loads(secrets.get("myservice/rabbitmq-credentials"))
    producer = RabbitMQProducer(
        broker_url=build_rabbitmq_url(creds),
        exchange="audit.events",
        service_name="auth-service",
    )
    await producer.connect()
    app.state.audit_producer = producer

    # In a use case or route:
    await producer.publish(
        routing_key="audit.tenant.user_created",
        body={"event_type": "tenant", "action": "user.created", ...},
    )
"""

from common.messaging.producer import RabbitMQProducer, build_rabbitmq_url

__all__ = [
    "RabbitMQProducer",
    "build_rabbitmq_url",
]