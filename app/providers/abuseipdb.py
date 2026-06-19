"""AbuseIPDB v2 API Adapter."""

import httpx
from typing import Dict, Any
from app.providers.base import BaseThreatProvider
from app.models.schemas import ProviderResult
from app.config import settings


class AbuseIPDBProvider(BaseThreatProvider):
    """Adapter for AbuseIPDB API v2."""

    def __init__(self):
        super().__init__(
            name="AbuseIPDB",
            rpm_limit=settings.ABUSEIPDB_RPM,
            supported_types=["IP"]
        )
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"

    @property
    def api_key(self) -> str:
        return settings.ABUSEIPDB_API_KEY

    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type.upper() != "IP":
            return ProviderResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                coverage_available=False,
                error_message="AbuseIPDB only provides threat intelligence for IP addresses."
            )

        headers = {
            "Key": self.api_key.strip(),
            "Accept": "application/json",
            "User-Agent": settings.USER_AGENT
        }
        params = {
            "ipAddress": ioc.strip(),
            "maxAgeInDays": 90,
            "verbose": True
        }

        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.get(self.endpoint, headers=headers, params=params)

            if resp.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message="AbuseIPDB authentication failed. Check API key."
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    status="RATE_LIMITED",
                    error_message="AbuseIPDB rate limit exceeded."
                )
            elif resp.status_code != 200:
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message=f"AbuseIPDB API HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json().get("data", {})
            abuse_score = float(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            is_whitelisted = bool(data.get("isWhitelisted", False))

            is_malicious = abuse_score >= 25 and not is_whitelisted

            summary = {
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "hostnames": data.get("hostnames", []),
                "is_whitelisted": is_whitelisted,
                "last_reported_at": data.get("lastReportedAt")
            }

            return ProviderResult(
                provider_name=self.name,
                status="SUCCESS",
                is_malicious=is_malicious,
                reputation_score=abuse_score,
                detection_count=total_reports,
                total_engines=100,  # Percentage scale
                source_reliability=0.90,
                summary=summary
            )
