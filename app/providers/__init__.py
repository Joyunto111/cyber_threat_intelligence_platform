"""Threat Intelligence Providers Manager."""

from typing import List, Dict, Any
from app.providers.base import BaseThreatProvider
from app.providers.virustotal import VirusTotalProvider
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.alienvault import AlienVaultOTXProvider
from app.providers.local_intel import LocalThreatIntelProvider
from app.models.schemas import ProviderResult, ProviderStatus
from app.config import settings


class ProviderManager:
    """Orchestrates all threat intelligence provider queries and configurations."""

    def __init__(self):
        self.providers: Dict[str, BaseThreatProvider] = {
            "Local Threat KnowledgeBase": LocalThreatIntelProvider(),
            "VirusTotal": VirusTotalProvider(),
            "AbuseIPDB": AbuseIPDBProvider(),
            "URLhaus": URLhausProvider(),
            "AlienVault OTX": AlienVaultOTXProvider(),
        }

    def get_provider_statuses(self) -> List[ProviderStatus]:
        """Returns the status and configuration state for all registered providers."""
        statuses = []
        for name, provider in self.providers.items():
            configured = provider.is_configured()
            status_text = "READY" if configured else "KEY REQUIRED"
            statuses.append(ProviderStatus(
                name=name,
                configured=configured,
                status=status_text,
                rate_limit_rpm=provider.rate_limiter.rpm,
                supported_types=provider.supported_types,
                notes=(
                    "Built-in offline feeds & live resolvers active" if name == "Local Threat KnowledgeBase"
                    else ("Connected and active" if configured else "Configure API key in .env or settings to enable")
                )
            ))
        return statuses

    def query_all(self, ioc: str, ioc_type: str, use_cache: bool = True) -> List[ProviderResult]:
        """Queries all relevant providers for an IOC and returns list of ProviderResults."""
        results: List[ProviderResult] = []
        for name, provider in self.providers.items():
            # Query if supported
            if provider.supports_ioc_type(ioc_type):
                res = provider.analyze(ioc, ioc_type, use_cache=use_cache)
                results.append(res)
        return results


# Global singleton provider manager
provider_manager = ProviderManager()
