from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseConfig(BaseSettings):
    # Which environment are we in
    environment: str = Field(default="local")
    log_level: str = Field(default="INFO")

    # Secrets provider selection
    secrets_provider: str = Field(default="env")       # "env" | "aws"
    secrets_region: str = Field(default="us-east-1")   # only used if aws
    secrets_prefix: str = Field(default="")            # e.g. "zerotheft/"
    secrets_profile: str | None = Field(default=None)

    # subscriber selector
    subscriber_type: str | None = None # "redis" | "rabbitmq" | None
    
    # Redis pub/sub for cache invalidation (optional)
    redis_host: str | None = Field(default=None)
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: str | None = Field(default=None)

    #  RabbitMQ fields
    rabbitmq_host: str | None = None
    rabbitmq_port: int = 5672
    rabbitmq_username: str = "guest"
    rabbitmq_password: str = "guest"
    rabbitmq_exchange: str = "secrets"
    rabbitmq_routing_keys: list[str] = ["secret.#"] # will be per service specific

    
    # Cache TTL
    memory_ttl_seconds: int = Field(default=300)  # 5 minutes

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )