"""URLhaus (abuse.ch) API Adapter."""

import httpx
from typing import Dict, Any
from app.providers.base import BaseThreatProvider
from app.models.schemas import ProviderResult
from app.config import settings


class URLhausProvider(BaseThreatProvider):
    """Adapter for abuse.ch URLhaus API."""

    def __init__(self):
        super().__init__(
            name="URLhaus",
            rpm_limit=settings.URLHAUS_RPM,
            supported_types=["URL", "DOMAIN", "HASH"]
        )
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    @property
    def api_key(self) -> str:
        return settings.URLHAUS_API_KEY

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {
            "Accept": "application/json",
            "User-Agent": settings.USER_AGENT
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key.strip()

        data_payload = {}
        endpoint = ""
        ioc_clean = ioc.strip()

        if ioc_type.upper() == "URL":
            endpoint = f"{self.base_url}/url/"
            data_payload = {"url": ioc_clean}
        elif ioc_type.upper() == "DOMAIN":
            endpoint = f"{self.base_url}/host/"
            data_payload = {"host": ioc_clean}
        elif ioc_type.upper() == "HASH":
            endpoint = f"{self.base_url}/payload/"
            if len(ioc_clean) == 32:
                data_payload = {"md5_hash": ioc_clean}
            elif len(ioc_clean) == 64:
                data_payload = {"sha256_hash": ioc_clean}
            else:
                return ProviderResult(
                    provider_name=self.name,
                    status="UNAVAILABLE",
                    coverage_available=False,
                    error_message="URLhaus payload lookup requires MD5 or SHA256."
                )
        else:
            return ProviderResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                coverage_available=False,
                error_message=f"URLhaus does not support {ioc_type} IOCs."
            )

        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.post(endpoint, data=data_payload, headers=headers)

            if resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    status="RATE_LIMITED",
                    error_message="URLhaus rate limit exceeded."
                )
            elif resp.status_code != 200:
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message=f"URLhaus HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            query_status = data.get("query_status")

            if query_status in ("no_results", "not_found"):
                return ProviderResult(
                    provider_name=self.name,
                    status="SUCCESS",
                    is_malicious=False,
                    reputation_score=0.0,
                    detection_count=0,
                    total_engines=1,
                    source_reliability=0.95,
                    summary={"status": "No malicious records found in URLhaus"}
                )
            elif query_status != "ok":
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message=f"URLhaus query error: {query_status}"
                )

            # URLhaus only tracks verified malicious malware distribution URLs/hosts
            is_malicious = True
            rep_score = 95.0

            summary = {
                "query_status": query_status,
                "urlhaus_reference": data.get("urlhaus_reference"),
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "tags": data.get("tags") or [],
                "reporter": data.get("reporter"),
                "date_added": data.get("date_added"),
                "payloads_count": len(data.get("payloads", [])) if "payloads" in data else 0
            }

            return ProviderResult(
                provider_name=self.name,
                status="SUCCESS",
                is_malicious=is_malicious,
                reputation_score=rep_score,
                detection_count=1,
                total_engines=1,
                source_reliability=0.95,
                summary=summary
            )
