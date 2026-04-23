
import os
import logging

from common.secrets.manager import SecretsProvider

logger = logging.getLogger(__name__)


class EnvSecretsProvider(SecretsProvider):
    def __init__(self, prefix: str = "") -> None:
        self.prefix = prefix

    def get(self, key: str) -> str:
        full_key = f"{self.prefix}{key}" if self.prefix else key
        value = os.getenv(full_key)

        if value is None:
            raise RuntimeError(f"Missing environment variable: {full_key}")

        logger.debug("Loaded secret from env: %s", full_key)
        return value

    def get_many(self, keys: list[str]) -> dict[str, str]:
        return {key: self.get(key) for key in keys}