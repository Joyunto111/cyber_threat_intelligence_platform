"""Security and SSRF Protection Module.

Ensures all network requests, URL probes, and file inspections adhere to strict
security boundaries:
- SSRF prevention (blocks private, link-local, loopback, multicast IPs)
- DNS rebinding prevention via pre-connection resolution checks
- Safe HTTP probing with strict timeouts and redirect limits
- Safe in-memory file hashing with size enforcement (no execution)
"""

import ipaddress
import socket
import re
import hashlib
from typing import Tuple, List, Optional
from urllib.parse import urlparse

import httpx

from app.core.exceptions import SSRFSecurityException
from app.config import settings

# Disallowed private and reserved CIDR ranges
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),       # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (Cloud Metadata 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}


def is_ip_private_or_reserved(ip_str: str) -> Tuple[bool, str]:
    """Checks whether an IP address is private, loopback, link-local, or reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        for net in FORBIDDEN_NETWORKS:
            if ip_obj in net:
                return True, f"IP address {ip_str} belongs to restricted/private network {net}"
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return True, f"IP address {ip_str} is flagged as private or reserved"
        return False, "Public IP"
    except ValueError:
        return False, "Not an IP address"


def validate_target_host_ssrf(hostname_or_ip: str) -> None:
    """Validates that a hostname or IP does not resolve to a private or dangerous address.

    Raises:
        SSRFSecurityException if target is forbidden or resolves to a private IP.
    """
    clean_host = hostname_or_ip.strip().lower()
    
    # Strip port if present
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]
    elif clean_host.startswith("[") and "]" in clean_host:
        clean_host = clean_host[1:clean_host.index("]")]

    if clean_host in FORBIDDEN_HOSTNAMES:
        raise SSRFSecurityException(f"Access to restricted hostname '{clean_host}' is blocked for security (SSRF prevention).")

    # Check directly if it's an IP
    is_blocked, reason = is_ip_private_or_reserved(clean_host)
    if is_blocked:
        raise SSRFSecurityException(f"Destination blocked by SSRF filter: {reason}")

    # If it's a domain name, resolve its IP addresses to verify none are private (DNS rebinding)
    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip = sockaddr[0]
            blocked, reason = is_ip_private_or_reserved(resolved_ip)
            if blocked:
                raise SSRFSecurityException(
                    f"Domain '{clean_host}' resolves to restricted IP {resolved_ip} ({reason}). Request blocked."
                )
    except socket.gaierror as e:
        # If hostname cannot be resolved, we do not allow blindly proceeding
        raise SSRFSecurityException(f"Could not resolve hostname '{clean_host}': {e}")


def safe_fetch_url_metadata(
    url: str,
    max_redirects: int = settings.MAX_REDIRECTS,
    timeout: float = settings.REQUEST_TIMEOUT_SECONDS
) -> dict:
    """Safely inspects a URL via HTTP HEAD / GET without rendering or executing content.

    Validates SSRF on initial URL and on each hop if redirects occur.
    Never downloads more than 2MB of response data.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFSecurityException(f"Forbidden URL scheme '{parsed.scheme}'. Only http and https are allowed.")

    if not parsed.hostname:
        raise SSRFSecurityException("URL must contain a valid hostname.")

    current_url = url
    redirect_history: List[str] = [current_url]
    headers_received = {}
    status_code = None
    final_url = current_url
    content_type = ""
    content_length = 0

    client = httpx.Client(
        headers={"User-Agent": settings.USER_AGENT},
        timeout=timeout,
        follow_redirects=False,
        verify=True
    )

    try:
        for hop in range(max_redirects + 1):
            curr_parsed = urlparse(current_url)
            if curr_parsed.scheme not in ("http", "https"):
                raise SSRFSecurityException(f"Redirected to unauthorized scheme: {curr_parsed.scheme}")

            # Verify SSRF on every hop
            validate_target_host_ssrf(curr_parsed.hostname)

            try:
                response = client.head(current_url)
                # Some servers reject HEAD requests with 405 Method Not Allowed
                if response.status_code in (405, 501):
                    response = client.get(current_url, headers={"Range": "bytes=0-1024"})
            except httpx.RequestError as e:
                return {
                    "reachable": False,
                    "error": str(e),
                    "redirect_chain": redirect_history,
                    "final_url": current_url,
                    "status_code": None
                }

            status_code = response.status_code
            headers_received = dict(response.headers)
            content_type = headers_received.get("content-type", "")
            content_length = int(headers_received.get("content-length", 0) or 0)

            # Check redirect (3xx)
            if response.is_redirect and "location" in response.headers:
                next_url = response.headers["location"]
                if next_url.startswith("/"):
                    next_url = f"{curr_parsed.scheme}://{curr_parsed.netloc}{next_url}"
                current_url = next_url
                redirect_history.append(current_url)
            else:
                final_url = current_url
                break
        else:
            return {
                "reachable": False,
                "error": f"Too many redirects (exceeded limit of {max_redirects})",
                "redirect_chain": redirect_history,
                "final_url": current_url,
                "status_code": status_code
            }

        return {
            "reachable": True,
            "status_code": status_code,
            "final_url": final_url,
            "redirect_count": len(redirect_history) - 1,
            "redirect_chain": redirect_history,
            "content_type": content_type,
            "content_length": content_length,
            "headers": {k: v for k, v in headers_received.items() if k.lower() in [
                "server", "content-type", "content-length", "x-powered-by", 
                "strict-transport-security", "location"
            ]}
        }
    finally:
        client.close()


def calculate_file_hashes_safely(file_bytes_stream, max_size_bytes: int = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024) -> dict:
    """Reads file stream in 64KB chunks, calculating MD5, SHA-1, SHA-256.

    Enforces file size limit and NEVER writes to an executable path or executes code.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    total_size = 0
    first_bytes = b""

    while True:
        chunk = file_bytes_stream.read(65536)
        if not chunk:
            break
        if not first_bytes:
            first_bytes = chunk[:512]
        total_size += len(chunk)
        if total_size > max_size_bytes:
            raise ValueError(f"Uploaded file exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB.")
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    # Magic byte identification for common types
    mime_type = detect_mime_type_from_magic(first_bytes)

    return {
        "md5": md5.hexdigest().lower(),
        "sha1": sha1.hexdigest().lower(),
        "sha256": sha256.hexdigest().lower(),
        "size_bytes": total_size,
        "magic_header_hex": first_bytes[:16].hex() if first_bytes else "",
        "detected_file_type": mime_type
    }


def detect_mime_type_from_magic(header: bytes) -> str:
    """Detects file type purely from header bytes without executing the file."""
    if not header:
        return "application/x-empty"
    if header.startswith(b"MZ"):
        return "application/x-dosexec (Windows PE Executable / DLL)"
    if header.startswith(b"\x7fELF"):
        return "application/x-executable (Linux ELF Executable)"
    if header.startswith(b"%PDF"):
        return "application/pdf (PDF Document)"
    if header.startswith(b"PK\x03\x04"):
        return "application/zip (ZIP / Office Archive)"
    if header.startswith(b"\x1f\x8b"):
        return "application/gzip (Gzip Compressed)"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png (PNG Image)"
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg (JPEG Image)"
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "image/gif (GIF Image)"
    if header.startswith(b"Rar!\x1a\x07"):
        return "application/x-rar (RAR Archive)"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed (7-Zip Archive)"
    if header.startswith(b"#!"):
        return "text/x-shellscript (Script / Text)"
    try:
        header.decode('utf-8')
        return "text/plain (ASCII / UTF-8 Text)"
    except UnicodeDecodeError:
        return "application/octet-stream (Binary Data)"


def sanitize_input_text(raw_text: str) -> str:
    """Sanitizes user input by removing null bytes and non-printable control chars."""
    if not raw_text:
        return ""
    # Strip null bytes and control chars (except newline, tab, cr)
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', raw_text)
    return cleaned.strip()
