"""AlienVault OTX API Adapter."""

import httpx
from typing import Dict, Any, List
from app.providers.base import BaseThreatProvider
from app.models.schemas import ProviderResult
from app.config import settings


class AlienVaultOTXProvider(BaseThreatProvider):
    """Adapter for AlienVault Open Threat Exchange (OTX) API."""

    def __init__(self):
        super().__init__(
            name="AlienVault OTX",
            rpm_limit=settings.ALIENVAULT_RPM,
            supported_types=["IP", "DOMAIN", "URL", "HASH"]
        )
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"

    @property
    def api_key(self) -> str:
        return settings.ALIENVAULT_OTX_API_KEY

    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {
            "X-OTX-API-KEY": self.api_key.strip(),
            "Accept": "application/json",
            "User-Agent": settings.USER_AGENT
        }
        
        endpoint = ""
        ioc_clean = ioc.strip()

        if ioc_type.upper() == "IP":
            endpoint = f"{self.base_url}/IPv4/{ioc_clean}/general"
        elif ioc_type.upper() == "DOMAIN":
            endpoint = f"{self.base_url}/domain/{ioc_clean}/general"
        elif ioc_type.upper() == "URL":
            endpoint = f"{self.base_url}/url/{ioc_clean}/general"
        elif ioc_type.upper() == "HASH":
            endpoint = f"{self.base_url}/file/{ioc_clean}/general"
        else:
            return ProviderResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                coverage_available=False,
                error_message=f"AlienVault OTX does not support {ioc_type} indicators."
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
                    source_reliability=0.85,
                    summary={"status": "Indicator not present in AlienVault OTX pulses"}
                )
            elif resp.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message="AlienVault OTX authentication failed. Verify API key."
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    status="RATE_LIMITED",
                    error_message="AlienVault OTX rate limit reached."
                )
            elif resp.status_code != 200:
                return ProviderResult(
                    provider_name=self.name,
                    status="FAILED",
                    error_message=f"AlienVault OTX HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])

            # Extract pulse names and tags
            pulse_names = [p.get("name") for p in pulses[:5] if "name" in p]
            malware_families: List[str] = []
            adversaries: List[str] = []
            
            for p in pulses:
                if p.get("adversary") and p.get("adversary") not in adversaries:
                    adversaries.append(p.get("adversary"))
                for mf in p.get("malware_families", []):
                    name = mf.get("display_name") or mf.get("name")
                    if name and name not in malware_families:
                        malware_families.append(name)

            # Malicious if tracked in multiple threat pulses
            is_malicious = pulse_count >= 2
            rep_score = min(100.0, pulse_count * 15.0)

            summary = {
                "pulse_count": pulse_count,
                "recent_pulses": pulse_names,
                "malware_families": malware_families[:5],
                "adversaries": adversaries[:5],
                "country_name": data.get("country_name"),
                "asn": data.get("asn")
            }

            return ProviderResult(
                provider_name=self.name,
                status="SUCCESS",
                is_malicious=is_malicious,
                reputation_score=round(rep_score, 1),
                detection_count=pulse_count,
                total_engines=max(pulse_count, 1),
                source_reliability=0.85,
                summary=summary
            )
