"""Local Threat Intelligence and Live Resolver Provider.

Provides offline database matching against verified threat signatures,
live DNS resolution, RDAP/WHOIS metadata, and network geolocation
even when commercial external API keys are not provided.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import dns.resolver
import httpx

from app.providers.base import BaseThreatProvider
from app.models.schemas import ProviderResult
from app.core.security import is_ip_private_or_reserved, validate_target_host_ssrf
from app.config import settings

LOCAL_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "local_threat_db.json"


class LocalThreatIntelProvider(BaseThreatProvider):
    """Local Threat Intelligence Provider using verified signature feeds and live resolvers."""

    def __init__(self):
        super().__init__(
            name="Local Threat KnowledgeBase",
            rpm_limit=120,
            supported_types=["IP", "DOMAIN", "URL", "HASH"]
        )
        self._local_db: Dict[str, Any] = {}
        self._load_local_db()

    @property
    def api_key(self) -> str:
        # Local provider doesn't require an API key
        return "LOCAL_KEY_BUILTIN"

    def is_configured(self) -> bool:
        return True

    def _load_local_db(self):
        if LOCAL_DB_PATH.exists():
            try:
                with open(LOCAL_DB_PATH, "r", encoding="utf-8") as f:
                    self._local_db = json.load(f)
            except Exception as e:
                self._local_db = {}

    def _query_provider(self, ioc: str, ioc_type: str) -> ProviderResult:
        ioc_clean = ioc.strip().lower()
        
        # Check against local curated feeds
        if ioc_type.upper() == "HASH":
            known_hashes = self._local_db.get("known_hashes", {})
            if ioc_clean in known_hashes:
                entry = known_hashes[ioc_clean]
                score = float(entry.get("score", 100))
                return ProviderResult(
                    provider_name=self.name,
                    status="SUCCESS",
                    is_malicious=score >= 50,
                    reputation_score=score,
                    detection_count=1,
                    total_engines=1,
                    source_reliability=1.0,
                    summary={
                        "signature_name": entry.get("name"),
                        "malware_family": entry.get("malware_family"),
                        "type": entry.get("type"),
                        "description": entry.get("description"),
                        "source": entry.get("source")
                    }
                )

        elif ioc_type.upper() == "IP":
            known_ips = self._local_db.get("known_ips", {})
            if ioc_clean in known_ips:
                entry = known_ips[ioc_clean]
                score = float(entry.get("score", 70))
                return ProviderResult(
                    provider_name=self.name,
                    status="SUCCESS",
                    is_malicious=score >= 50,
                    reputation_score=score,
                    detection_count=1,
                    total_engines=1,
                    source_reliability=0.95,
                    summary={
                        "category": entry.get("category"),
                        "severity": entry.get("severity"),
                        "tags": entry.get("tags", []),
                        "source": entry.get("source")
                    }
                )

        elif ioc_type.upper() == "DOMAIN":
            known_domains = self._local_db.get("known_domains", {})
            if ioc_clean in known_domains:
                entry = known_domains[ioc_clean]
                score = float(entry.get("score", 90))
                return ProviderResult(
                    provider_name=self.name,
                    status="SUCCESS",
                    is_malicious=score >= 50,
                    reputation_score=score,
                    detection_count=1,
                    total_engines=1,
                    source_reliability=0.95,
                    summary={
                        "category": entry.get("category"),
                        "target_brand": entry.get("target_brand"),
                        "malware_family": entry.get("malware_family"),
                        "source": entry.get("source")
                    }
                )

        # If not present in known signatures
        return ProviderResult(
            provider_name=self.name,
            status="SUCCESS",
            is_malicious=False,
            reputation_score=0.0,
            detection_count=0,
            total_engines=1,
            source_reliability=0.90,
            summary={"status": "No match in local baseline threat intelligence database."}
        )


def query_dns_records(domain: str) -> Dict[str, List[str]]:
    """Performs live DNS resolution for A, AAAA, MX, NS, TXT, and CNAME records."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    
    results: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": []
    }
    
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                results[rtype].append(str(rdata).strip())
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, Exception):
            pass
            
    return results


def query_ip_geolocation(ip_str: str) -> Dict[str, Any]:
    """Fetches geolocation and ASN information for public IPs using safe HTTP lookup."""
    is_private, reason = is_ip_private_or_reserved(ip_str)
    if is_private:
        return {
            "status": "private_network",
            "country": "Local / Private",
            "countryCode": "PRV",
            "isp": reason,
            "as": "RFC 1918 / Reserved",
            "city": "Private Network"
        }

    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, headers={"User-Agent": settings.USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
    except Exception as e:
        pass

    return {
        "status": "unavailable",
        "country": "Unknown",
        "countryCode": "UNK",
        "isp": "Lookup unavailable",
        "as": "Unknown"
    }


def query_rdap_whois(domain: str) -> Dict[str, Any]:
    """Fetches RDAP / registration data for domain without third party keys."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        with httpx.Client(timeout=4.0, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": settings.USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                entities = [ent.get("vcardArray", []) for ent in data.get("entities", [])]
                
                return {
                    "registered": True,
                    "handle": data.get("handle"),
                    "registration_date": events.get("registration"),
                    "expiration_date": events.get("expiration"),
                    "last_changed": events.get("last changed"),
                    "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if "ldhName" in ns]
                }
    except Exception:
        pass

    return {
        "registered": None,
        "status": "RDAP lookup timed out or unavailable"
    }
