"""Tests for IOC Validation, Normalization, Defanging, and Extraction."""

import pytest
from app.core.validator import (
    validate_and_normalize_ip,
    validate_and_normalize_domain,
    validate_and_normalize_url,
    validate_and_normalize_hash,
    detect_ioc_type,
    defang_ioc,
    refang_text,
    extract_all_iocs_from_text
)


def test_ip_validation():
    # Valid IPv4
    valid, norm, ver = validate_and_normalize_ip("192.168.1.1")
    assert valid is True
    assert norm == "192.168.1.1"
    assert ver == "IPv4"

    # Valid IPv6
    valid_v6, norm_v6, ver_v6 = validate_and_normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert valid_v6 is True
    assert norm_v6 == "2001:db8:85a3::8a2e:370:7334"
    assert ver_v6 == "IPv6"

    # Invalid IPs
    assert validate_and_normalize_ip("999.999.999.999")[0] is False
    assert validate_and_normalize_ip("not_an_ip")[0] is False
    assert validate_and_normalize_ip("192.168.1.500")[0] is False


def test_domain_validation():
    # Valid domains
    assert validate_and_normalize_domain("evil-domain.com")[0] is True
    assert validate_and_normalize_domain("sub.attack-surface.co.uk")[0] is True
    assert validate_and_normalize_domain("HTTPS://EVIL-DOMAIN.COM/")[1] == "evil-domain.com"

    # Invalid domains
    assert validate_and_normalize_domain("invalid_domain")[0] is False
    assert validate_and_normalize_domain("-leading-hyphen.com")[0] is False
    assert validate_and_normalize_domain("domain.123")[0] is False


def test_url_validation():
    # Valid URLs
    valid, norm = validate_and_normalize_url("https://malicious.org/download/payload.exe?id=123")
    assert valid is True
    assert norm == "https://malicious.org/download/payload.exe?id=123"

    # Missing scheme automatically normalized
    valid_no_scheme, norm_no_scheme = validate_and_normalize_url("phishing-portal.com/login.php")
    assert valid_no_scheme is True
    assert norm_no_scheme.startswith("http://phishing-portal.com")


def test_hash_validation():
    # MD5 (32 hex)
    md5_sample = "ed018450a7d5fa75599e744db607d61e"
    assert validate_and_normalize_hash(md5_sample) == (True, md5_sample, "MD5")

    # SHA-1 (40 hex)
    sha1_sample = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert validate_and_normalize_hash(sha1_sample) == (True, sha1_sample, "SHA-1")

    # SHA-256 (64 hex)
    sha256_sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert validate_and_normalize_hash(sha256_sample) == (True, sha256_sample, "SHA-256")

    # Invalid hash
    assert validate_and_normalize_hash("tooshort")[0] is False
    assert validate_and_normalize_hash("not_hex_characters_xyz_1234567890")[0] is False


def test_defang_and_refang():
    defanged = "hxxps://bad-site[.]com/trojan[.]exe"
    refanged = refang_text(defanged)
    assert refanged == "https://bad-site.com/trojan.exe"

    raw_ip = "1.1.1.1"
    assert defang_ioc(raw_ip, "IP") == "1[.]1[.]1[.]1"


def test_extract_all_iocs_from_text():
    sample_text = """
    Incident Alert:
    The adversary deployed malicious dropper from hxxp://evil-download[.]com/stealer[.]exe.
    The C2 server resolved to 185.220.101.5 and secondary domain c2-hub[.]net.
    File payload SHA256 was e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
    MD5 hash observed: ed018450a7d5fa75599e744db607d61e.
    """
    extracted = extract_all_iocs_from_text(sample_text)
    
    assert len(extracted["urls"]) >= 1
    assert any("evil-download.com" in u["normalized"] for u in extracted["urls"])
    assert any(ip["normalized"] == "185.220.101.5" for ip in extracted["ips"])
    assert any(d["normalized"] == "c2-hub.net" for d in extracted["domains"])
    assert any("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in h["normalized"] for h in extracted["hashes"])
    assert any("ed018450a7d5fa75599e744db607d61e" in h["normalized"] for h in extracted["hashes"])
