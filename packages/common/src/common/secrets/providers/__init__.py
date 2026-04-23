import logging
from typing import Callable

from common.config.base import BaseConfig
from common.secrets.manager import SecretManager, SecretsProvider, RefreshEventSubscriber

logger = logging.getLogger(__name__)


def build_provider(config: BaseConfig) -> SecretsProvider:
    if config.secrets_provider == "aws":
        from common.secrets.providers.aws import AWSSecretsProvider
        return AWSSecretsProvider(
            region=config.secrets_region,
            prefix=config.secrets_prefix,
            profile=config.secrets_profile,
        )
    elif config.secrets_provider == "env":
        from common.secrets.providers.env import EnvSecretsProvider
        return EnvSecretsProvider(prefix=config.secrets_prefix)
    else:
        raise ValueError(f"Unknown secrets provider: {config.secrets_provider!r}")


def build_subscriber(config: BaseConfig) -> RefreshEventSubscriber | None:
    if not config.subscriber_type:
        logger.info("No subscriber configured — local-only TTL mode")
        return None

    if config.subscriber_type == "redis":
        if not config.redis_host:
            raise ValueError("REDIS_HOST required when SUBSCRIBER_TYPE=redis")
        import redis
        from common.secrets.subscribers.redis_subscriber import RedisRefreshSubscriber
        redis_client = redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            db=config.redis_db,
            password=config.redis_password,
            decode_responses=False,
        )
        return RedisRefreshSubscriber(redis_client)

    if config.subscriber_type == "rabbitmq":
        if not config.rabbitmq_host:
            raise ValueError("RABBITMQ_HOST required when SUBSCRIBER_TYPE=rabbitmq")
        from common.secrets.subscribers.rabbitmq_subscriber import RabbitMQRefreshSubscriber
        return RabbitMQRefreshSubscriber(
            host=config.rabbitmq_host,
            port=config.rabbitmq_port,
            username=config.rabbitmq_username,
            password=config.rabbitmq_password,
            exchange=config.rabbitmq_exchange,
            routing_keys=config.rabbitmq_routing_keys,
        )

    raise ValueError(f"Unknown subscriber type: {config.subscriber_type!r}")


def build_secret_manager(
    config: BaseConfig,
    memory_ttl_seconds: int | None = None,
    routing_key_map: dict[str, list[str]] | None = None,
    on_rotation_callbacks: dict[str, Callable[[], None]] | None = None,  # NEW
) -> SecretManager:
    """
    Build a fully configured SecretManager from BaseConfig.

    on_rotation_callbacks: optional dict of routing_key -> zero-arg callable.
        Called after cache is cleared for that routing key.
        Runs in the subscriber background thread — dispatch async work with
        asyncio.run_coroutine_threadsafe().
    """
    provider = build_provider(config)
    subscriber = build_subscriber(config)
    ttl = memory_ttl_seconds if memory_ttl_seconds is not None else config.memory_ttl_seconds

    return SecretManager(
        provider=provider,
        subscriber=subscriber,
        memory_ttl_seconds=ttl,
        routing_key_map=routing_key_map,
        on_rotation_callbacks=on_rotation_callbacks,
    )