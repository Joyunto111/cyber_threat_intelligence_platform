"""Provider Adapters Test Suite with Mocked Intelligence Data."""

import pytest
from unittest.mock import patch, MagicMock
from app.providers.virustotal import VirusTotalProvider
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.alienvault import AlienVaultOTXProvider
from app.providers.local_intel import LocalThreatIntelProvider


def test_local_threat_intel_provider():
    provider = LocalThreatIntelProvider()
    assert provider.is_configured() is True
    
    # Query known Wannacry hash
    result = provider.analyze("ed018450a7d5fa75599e744db607d61e", "HASH")
    assert result.status == "SUCCESS"
    assert result.is_malicious is True
    assert result.reputation_score == 100.0
    assert "WannaCry" in result.summary.get("malware_family", "")

    # Query unknown hash
    unknown = provider.analyze("00000000000000000000000000000000", "HASH")
    assert unknown.status == "SUCCESS"
    assert unknown.is_malicious is False


def test_virustotal_not_configured_graceful_handling():
    with patch("app.config.settings.VIRUSTOTAL_API_KEY", ""):
        vt = VirusTotalProvider()
        result = vt.analyze("8.8.8.8", "IP")
        assert result.status == "NOT_CONFIGURED"
        assert result.coverage_available is True


def test_virustotal_mocked_malicious_response():
    with patch("app.config.settings.VIRUSTOTAL_API_KEY", "mock_key_vt"):
        vt = VirusTotalProvider()
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 42,
                        "suspicious": 3,
                        "harmless": 0,
                        "undetected": 25
                    },
                    "reputation": -50,
                    "tags": ["trojan", "stealer"]
                }
            }
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            res = vt.analyze("194.26.29.112", "IP", use_cache=False)
            assert res.status == "SUCCESS"
            assert res.is_malicious is True
            assert res.detection_count == 42


def test_abuseipdb_mocked_response():
    with patch("app.config.settings.ABUSEIPDB_API_KEY", "mock_key_abuse"):
        abuse = AbuseIPDBProvider()
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 34,
                "countryCode": "RU",
                "isp": "Bulletproof Hosting AS",
                "isWhitelisted": False
            }
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            res = abuse.analyze("194.26.29.112", "IP", use_cache=False)
            assert res.status == "SUCCESS"
            assert res.is_malicious is True
            assert res.reputation_score == 85.0
            assert res.detection_count == 34


def test_urlhaus_mocked_response():
    with patch("app.config.settings.URLHAUS_API_KEY", "mock_key_urlhaus"):
        uh = URLhausProvider()
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "tags": ["emotet", "payload"]
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = uh.analyze("http://evil.com/drop.exe", "URL", use_cache=False)
            assert res.status == "SUCCESS"
            assert res.is_malicious is True
            assert "emotet" in res.summary.get("tags", [])


def test_alienvault_mocked_pulse_response():
    with patch("app.config.settings.ALIENVAULT_OTX_API_KEY", "mock_key_otx"):
        otx = AlienVaultOTXProvider()
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 5,
                "pulses": [
                    {"name": "APT29 CozyBear Campaign", "adversary": "APT29", "malware_families": [{"name": "Cobalt Strike"}]}
                ]
            }
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            res = otx.analyze("194.26.29.112", "IP", use_cache=False)
            assert res.status == "SUCCESS"
            assert res.is_malicious is True
            assert res.detection_count == 5
            assert "APT29" in res.summary.get("adversaries", [])
