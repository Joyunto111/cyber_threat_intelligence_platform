"""VirusTotal v3 API Adapter."""

import base64
import httpx
from typing import Dict, Any
from app.providers.base import BaseThreatProvider
from app.models.schemas import ProviderResult
from app.config import settings


class VirusTotalProvider(BaseThreatProvider):
    """Adapter for VirusTotal API v3."""

    def __init__(self):
        super().__init__(
            name="VirusTotal",
            rpm_limit=settings.VIRUSTOTAL_RPM,
            supported_types=["IP", "DOMAIN", "URL", "HASH"]
        )
        self.base_url = "https://www.virustotal.com/api/v3"

    @property
    def api_key(self) -> str:
        return settings.VIRUSTOTAL_API_KEY

    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {
            "x-apikey": self.api_key.strip(),
            "Accept": "application/json",
            "User-Agent": settings.USER_AGENT
        }
        
        endpoint = ""
        ioc_clean = ioc.strip()

        if ioc_type.upper() == "IP":
            endpoint = f"{self.base_url}/ip_addresses/{ioc_clean}"
        elif ioc_type.upper() == "DOMAIN":
            endpoint = f"{self.base_url}/domains/{ioc_clean}"
        elif ioc_type.upper() == "URL":
            # VT v3 URL identifier is base64 URL safe without padding
            url_id = base64.urlsafe_b64encode(ioc_clean.encode()).decode().strip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
        elif ioc_type.upper() == "HASH":
            endpoint = f"{self.base_url}/files/{ioc_clean}"
        else:
            return ProviderResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                coverage_available=False,
                error_message=f"Unsupported IOC type: {ioc_type}"
            )

        with httpx.Client(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            resp = client.get(endpoint, headers=headers)
            
            if resp.status_code == 404:
                return ProviderResult(
                    provider_name=self.name,
                    status="SUCCESS",
                    is_malicious=False,
                    reputation_score=0.0,
                    detection_count=0,
                    total_engines=0,
                    source_reliability=0.95,
                    summary={"status": "Not found in VirusTotal dataset (no reports)"}
                )
            elif resp.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message="VirusTotal authentication failed. Verify API key."
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    status="RATE_LIMITED",
                    error_message="VirusTotal API quota or rate limit exceeded."
                )
            elif resp.status_code != 200:
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message=f"VirusTotal API HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            # Reputation score on 0-100 scale
            # If 3 or more engines flag it, it is considered malicious
            is_malicious = malicious >= 3 or (total > 0 and (malicious / total) >= 0.05)
            
            if total > 0:
                rep_score = min(100.0, ((malicious * 1.0 + suspicious * 0.5) / total) * 100 * 2.5)
            else:
                rep_score = 0.0

            summary = {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "harmless_engines": harmless,
                "undetected_engines": undetected,
                "total_engines": total,
                "reputation_vt": attributes.get("reputation", 0),
                "tags": attributes.get("tags", []),
                "categories": attributes.get("categories", {}),
                "meaningful_name": attributes.get("meaningful_name", "")
            }

            return ProviderResult(
                provider_name=self.name,
                status="SUCCESS",
                is_malicious=is_malicious,
                reputation_score=round(rep_score, 1),
                detection_count=malicious,
                total_engines=total,
                source_reliability=0.95,
                summary=summary
            )
