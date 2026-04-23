
import json
import logging

from common.secrets.manager import SecretsProvider

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


class AWSSecretsProvider(SecretsProvider):
    """
    Fetches secrets from AWS Secrets Manager.

    prefix example: "mycompany/"
      → key "prod/app1/db_password"
      → fetches SecretId "mycompany/prod/app1/db_password"
    """

    def __init__(self, region: str, prefix: str = "", profile: str | None = None) -> None:
        if boto3 is None:
            raise ImportError(
                "boto3 is required for AWSSecretsProvider. "
                "Install: uv add boto3"
            )
        session = boto3.Session(region_name=region, profile_name=profile)
        self.client = session.client("secretsmanager")
        self.prefix = prefix
        logger.info("AWSSecretsProvider ready — region=%s prefix=%s profile=%s", region, prefix, profile)

    def get(self, key: str) -> str:
        secret_id = f"{self.prefix}{key}" if self.prefix else key

        try:
            response = self.client.get_secret_value(SecretId=secret_id)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("AWS secret fetch failed: %s — %s", secret_id, error_code)
            raise RuntimeError(f"Failed to load secret '{secret_id}': {error_code}") from e

        # SecretString for plain text, SecretBinary for binary
        # We only support SecretString here
        secret = response.get("SecretString")
        if secret is None:
            raise RuntimeError(f"Secret '{secret_id}' has no SecretString value")

        # If the secret is a JSON blob (common in AWS), and key has a sub-key
        # e.g. "prod/app1/db" → stored as {"password": "xxx", "host": "yyy"}
        # We return the raw string. Parsing is the caller's job.
        logger.info("Fetched secret from AWS: %s", secret_id)
        return secret

    def get_many(self, keys: list[str]) -> dict[str, str]:
        """Batch fetch using batch_get_secret_value (max 20 per call)"""
        if not keys:
            return {}

        # Build full secret IDs with prefix
        secret_ids = [f"{self.prefix}{key}" if self.prefix else key for key in keys]
        
        # Create mapping: secret_id -> original_key for result mapping
        id_to_key = {secret_id: key for secret_id, key in zip(secret_ids, keys)}
        
        results = {}
        
        # AWS batch limit is 20 secrets per call
        batch_size = 20
        for i in range(0, len(secret_ids), batch_size):
            batch_ids = secret_ids[i:i + batch_size]
            
            try:
                response = self.client.batch_get_secret_value(SecretIdList=batch_ids)
                
                # Process successful results
                for secret_entry in response.get("SecretValues", []):
                    # Use 'Name' field which contains the secret ID we requested
                    secret_name = secret_entry.get("Name")
                    secret_string = secret_entry.get("SecretString")
                    
                    if secret_name and secret_string is not None:
                        # Map back to original key
                        original_key = id_to_key.get(secret_name)
                        if original_key:
                            results[original_key] = secret_string
                
                # Handle individual secret errors
                for error in response.get("Errors", []):
                    secret_id = error["SecretId"]
                    error_code = error["ErrorCode"]
                    error_msg = error.get("Message", "")
                    
                    logger.error(
                        "Failed to fetch secret '%s': %s - %s", 
                        secret_id, error_code, error_msg
                    )
                    
                    # Map to original key for error reporting
                    original_key = id_to_key.get(secret_id)
                    if original_key:
                        if error_code == "AccessDeniedException":
                            raise PermissionError(
                                f"Access denied for secret '{original_key}'"
                            )
                        else:
                            raise RuntimeError(
                                f"Failed to load secret '{original_key}': {error_code}"
                            )
                
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                logger.error("Batch API call failed: %s - %s", error_code, e)
                raise RuntimeError(f"Batch secret fetch failed: {error_code}") from e

        # Verify all keys were fetched
        missing = set(keys) - set(results.keys())
        if missing:
            raise RuntimeError(
                f"Missing secrets after batch fetch: {list(missing)}"
            )

        logger.info("Batch fetched %d secrets", len(results))
        return results