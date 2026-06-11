"""Base Threat Intelligence Provider Abstract Class."""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from app.models.schemas import ProviderResult
from app.core.rate_limiter import SlidingWindowRateLimiter, threat_cache
from app.config import settings


class BaseThreatProvider(ABC):
    """Abstract base class for all threat intelligence provider adapters."""

    def __init__(self, name: str, rpm_limit: int, supported_types: List[str]):
        self.name = name
        self.rate_limiter = SlidingWindowRateLimiter(rpm_limit)
        self.supported_types = supported_types  # e.g. ["IP", "DOMAIN", "URL", "HASH"]

    @property
    @abstractmethod
    def api_key(self) -> str:
        """Returns the configured API key, or empty string."""
        pass

    def is_configured(self) -> bool:
        """Returns True if the provider has valid credentials configured."""
        return bool(self.api_key and self.api_key.strip())

    def supports_ioc_type(self, ioc_type: str) -> bool:
        """Checks whether this provider supports the given IOC type."""
        return ioc_type.upper() in [t.upper() for t in self.supported_types]

    def _get_cache_key(self, ioc: str, ioc_type: str) -> str:
        return f"{self.name.lower()}:{ioc_type.upper()}:{ioc.lower().strip()}"

    def get_cached(self, ioc: str, ioc_type: str) -> Optional[ProviderResult]:
        """Retrieves cached result if available."""
        if not settings.CACHE_ENABLED:
            return None
        cached = threat_cache.get(self._get_cache_key(ioc, ioc_type))
        return cached

    def set_cached(self, ioc: str, ioc_type: str, result: ProviderResult) -> None:
        """Saves result to TTL cache."""
        if settings.CACHE_ENABLED:
            threat_cache.set(self._get_cache_key(ioc, ioc_type), result, settings.CACHE_TTL_SECONDS)

    def analyze(self, ioc: str, ioc_type: str, use_cache: bool = True) -> ProviderResult:
        """Standard wrapper providing type check, caching, and rate limiting."""
        # 1. Check if type is supported
        if not self.supports_ioc_type(ioc_type):
            return ProviderResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                coverage_available=False,
                error_message=f"{self.name} does not provide threat intelligence for {ioc_type} indicators."
            )

        # 2. Check cache
        if use_cache:
            cached = self.get_cached(ioc, ioc_type)
            if cached:
                return cached

        # 3. Check configuration
        if not self.is_configured():
            return ProviderResult(
                provider_name=self.name,
                status="NOT_CONFIGURED",
                coverage_available=True,
                error_message=f"API key for {self.name} is not configured. Set in .env or Settings."
            )

        # 4. Enforce rate limit
        allowed = self.rate_limiter.acquire(block=False)
        if not allowed:
            return ProviderResult(
                provider_name=self.name,
                status="RATE_LIMITED",
                coverage_available=True,
                error_message=f"Rate limit exceeded for {self.name}. Request throttled."
            )

        # 5. Execute provider query
        try:
            result = self._query_provider(ioc, ioc_type)
            self.set_cached(ioc, ioc_type, result)
            return result
        except Exception as e:
            return ProviderResult(
                provider_name=self.name,
                status="FAILED",
                coverage_available=True,
                error_message=f"Query error: {str(e)}"
            )

    @abstractmethod
    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        """Subclass implementation of actual API request and parsing."""
        pass
