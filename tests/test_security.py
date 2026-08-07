"""Security and SSRF Protection Test Suite."""

import io
import pytest
from app.core.security import (
    is_ip_private_or_reserved,
    validate_target_host_ssrf,
    calculate_file_hashes_safely
)
from app.core.exceptions import SSRFSecurityException


def test_private_ip_detection():
    # RFC 1918 Private
    assert is_ip_private_or_reserved("10.0.0.1")[0] is True
    assert is_ip_private_or_reserved("172.16.5.10")[0] is True
    assert is_ip_private_or_reserved("192.168.1.1")[0] is True

    # Loopback
    assert is_ip_private_or_reserved("127.0.0.1")[0] is True
    assert is_ip_private_or_reserved("::1")[0] is True

    # Cloud Metadata (AWS/GCP/Azure link-local)
    assert is_ip_private_or_reserved("169.254.169.254")[0] is True

    # Public IP
    assert is_ip_private_or_reserved("8.8.8.8")[0] is False
    assert is_ip_private_or_reserved("1.1.1.1")[0] is False


def test_ssrf_hostname_validation_blocks_internal():
    # Forbidden hostnames
    with pytest.raises(SSRFSecurityException):
        validate_target_host_ssrf("localhost")

    with pytest.raises(SSRFSecurityException):
        validate_target_host_ssrf("metadata.google.internal")

    # Forbidden direct IPs
    with pytest.raises(SSRFSecurityException):
        validate_target_host_ssrf("127.0.0.1")

    with pytest.raises(SSRFSecurityException):
        validate_target_host_ssrf("10.1.2.3")

    with pytest.raises(SSRFSecurityException):
        validate_target_host_ssrf("169.254.169.254")


def test_safe_file_hashing_in_memory():
    # Test safe hashing of harmless sample bytes without file execution
    harmless_data = b"This is a harmless test string for CTI hash verification."
    stream = io.BytesIO(harmless_data)
    
    result = calculate_file_hashes_safely(stream)
    
    assert "md5" in result
    assert "sha1" in result
    assert "sha256" in result
    assert result["size_bytes"] == len(harmless_data)
    assert "text" in result["detected_file_type"].lower()


def test_safe_file_hashing_size_limit():
    # Verify exceeding file limit raises ValueError
    stream = io.BytesIO(b"X" * 1024)
    with pytest.raises(ValueError):
        calculate_file_hashes_safely(stream, max_size_bytes=512)
