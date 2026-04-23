"""
Typed exceptions for the RLS middleware boundary.

All inherit from TenantContextError so dispatch() can catch them in one
except clause and return a uniform 403. Consuming services can also catch
specific subtypes for logging/metrics if they wrap the middleware.
"""
from __future__ import annotations


class TenantContextError(Exception):
    """Base - any tenant context resolution failure -> HTTP 403."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class MissingToken(TenantContextError):
    """No Authorization header or malformed Bearer prefix."""


class InvalidToken(TenantContextError):
    """JWT signature verification failed, bad claims, or missing tenant_id."""


class ExpiredToken(TenantContextError):
    """JWT exp claim is in the past."""