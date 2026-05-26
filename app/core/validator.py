"""IOC Validation, Normalization, Defanging/Refanging, and Extraction Engine.

Handles comprehensive regex parsing, RFC compliance validation,
and defanged indicator sanitization for cybersecurity operations.
"""

import re
import ipaddress
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse, urlunparse

# Regex patterns for IOC detection and validation
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Standard and compressed IPv6
IPV6_REGEX = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
    r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:ffff(?::0{1,4}){0,1}:){0,1}'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b'
)

# Domain Regex (RFC 1123 compliant with valid TLD requirement)
DOMAIN_REGEX = re.compile(
    r'\b(?!(?:https?|ftp)://)'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,63}\b'
)

# URL Regex (captures http, https, ftp, sftp with path and query)
URL_REGEX = re.compile(
    r'\b(?:https?|ftp|sftp)://'
    r'(?:[a-zA-Z0-9\-._~%!$&\'()*+,;=:]+@)?'
    r'(?:\[[a-fA-F0-9:]+\]|[a-zA-Z0-9.\-_]+)'
    r'(?::[0-9]{1,5})?'
    r'(?:/[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/]*)*(?:\?[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/?]*)?'
    r'(?:#[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/?]*)?'
)

# Hashes
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')


def refang_text(text: str) -> str:
    """Reconstructs live indicators from defanged text commonly found in threat reports."""
    if not text:
        return ""
    # Schemes: hxxp:// -> http://, hxxps:// -> https://, fxp:// -> ftp://
    text = re.sub(r'hxxp(s?)://', r'http\1://', text, flags=re.IGNORECASE)
    text = re.sub(r'me[x]{1,2}age://', r'message://', text, flags=re.IGNORECASE)
    text = re.sub(r'fxp://', r'ftp://', text, flags=re.IGNORECASE)
    
    # Dots: [.], (.), [dot], (dot), {dot}
    text = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}', '.', text, flags=re.IGNORECASE)
    
    # Colons: [:] or (:)
    text = re.sub(r'\[:\]|\(:\)', ':', text)
    
    # At signs: [at], (at), [@], (@)
    text = re.sub(r'\[at\]|\(at\)|\[@\]|\(@\)', '@', text, flags=re.IGNORECASE)
    
    # Slashes: [/], [/], [/ /]
    text = re.sub(r'\[/\]|\[//\]', '/', text)
    
    return text


def defang_ioc(ioc_value: str, ioc_type: str = "") -> str:
    """Defangs an active IOC so it cannot be accidentally clicked or resolved."""
    if not ioc_value:
        return ""
    val = ioc_value.strip()
    
    # Defang URLs
    if val.startswith("http://"):
        val = "hxxp://" + val[7:]
    elif val.startswith("https://"):
        val = "hxxps://" + val[8:]
    elif val.startswith("ftp://"):
        val = "fxp://" + val[6:]

    # Defang dots
    val = val.replace(".", "[.]")
    return val


def validate_and_normalize_ip(ip_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validates an IP address and returns (is_valid, normalized_ip, ip_version)."""
    ip_clean = ip_str.strip()
    try:
        obj = ipaddress.ip_address(ip_clean)
        # Canonical string
        normalized = str(obj)
        version = f"IPv{obj.version}"
        return True, normalized, version
    except ValueError:
        return False, None, None


def validate_and_normalize_domain(domain_str: str) -> Tuple[bool, Optional[str]]:
    """Validates and normalizes a domain name (lowercase, strip trailing dots, punycode check)."""
    d = domain_str.strip().lower()
    
    # Remove protocol prefix if accidentally included
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).hostname or ""
    
    d = d.rstrip(".")
    
    # Check length
    if not d or len(d) > 253:
        return False, None
    
    # Check labels
    labels = d.split(".")
    if len(labels) < 2:
        return False, None  # Must have at least SLD + TLD
    
    for label in labels:
        if not label or len(label) > 63:
            return False, None
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', label):
            return False, None
            
    # TLD must not be purely numeric
    if labels[-1].isdigit():
        return False, None
        
    return True, d


def validate_and_normalize_url(url_str: str) -> Tuple[bool, Optional[str]]:
    """Validates and normalizes a URL.

    Normalizes scheme/hostname to lowercase, strips trailing default ports.
    """
    u = url_str.strip()
    if not re.match(r'^[a-zA-Z0-9+.-]+://', u):
        # Prepend http:// if missing scheme for evaluation
        u = "http://" + u

    try:
        parsed = urlparse(u)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https", "ftp", "sftp"):
            return False, None
        if not parsed.netloc:
            return False, None
            
        # Normalize hostname to lowercase
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, None

        # Reconstruct port if non-standard
        port_part = ""
        if parsed.port:
            if (parsed.scheme == "http" and parsed.port != 80) or \
               (parsed.scheme == "https" and parsed.port != 443):
                port_part = f":{parsed.port}"

        # Clean path: default to / if empty
        path = parsed.path or "/"

        normalized = urlunparse((
            parsed.scheme.lower(),
            f"{hostname}{port_part}",
            path,
            parsed.params,
            parsed.query,
            ""  # Exclude fragment for normalized threat IOC
        ))
        return True, normalized
    except Exception:
        return False, None


def validate_and_normalize_hash(hash_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validates and normalizes a hash string (MD5, SHA-1, SHA-256).

    Returns (is_valid, normalized_hash, hash_type).
    """
    h = hash_str.strip().lower()
    if not re.match(r'^[a-f0-9]+$', h):
        return False, None, None

    if len(h) == 32:
        return True, h, "MD5"
    elif len(h) == 40:
        return True, h, "SHA-1"
    elif len(h) == 64:
        return True, h, "SHA-256"
    return False, None, None


def detect_ioc_type(ioc: str) -> Tuple[str, Optional[str]]:
    """Determines the specific IOC type of a given string.

    Returns (ioc_type, normalized_value).
    Type can be: IP, DOMAIN, URL, HASH, or UNKNOWN.
    """
    cleaned = refang_text(ioc.strip())
    
    # 1. Check IP
    is_ip, norm_ip, _ = validate_and_normalize_ip(cleaned)
    if is_ip:
        return "IP", norm_ip

    # 2. Check Hash
    is_hash, norm_hash, _ = validate_and_normalize_hash(cleaned)
    if is_hash:
        return "HASH", norm_hash

    # 3. Check URL (must have scheme or slash)
    if cleaned.startswith(("http://", "https://", "ftp://", "sftp://")) or "/" in cleaned:
        is_url, norm_url = validate_and_normalize_url(cleaned)
        if is_url:
            return "URL", norm_url

    # 4. Check Domain
    is_domain, norm_dom = validate_and_normalize_domain(cleaned)
    if is_domain:
        return "DOMAIN", norm_dom

    return "UNKNOWN", None


def extract_all_iocs_from_text(raw_text: str) -> Dict[str, List[Dict[str, str]]]:
    """Extracts, defangs, refangs, normalizes, and categorizes all IOCs from bulk text.

    Returns deduplicated dictionary grouped by indicator type with raw and normalized forms.
    """
    refanged = refang_text(raw_text)
    
    extracted: Dict[str, List[Dict[str, str]]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }
    
    seen_normalized: Set[str] = set()

    # 1. Extract URLs first (to avoid double-matching domains/IPs contained inside URLs)
    found_urls = URL_REGEX.findall(refanged)
    for raw_u in found_urls:
        valid, norm = validate_and_normalize_url(raw_u)
        if valid and norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            extracted["urls"].append({
                "raw": raw_u,
                "normalized": norm,
                "defanged": defang_ioc(norm, "URL"),
                "type": "URL"
            })

    # Temporarily mask matched URLs so their hostnames are not re-extracted as standalone domains/IPs
    text_masked = refanged
    for u_item in extracted["urls"]:
        text_masked = text_masked.replace(u_item["raw"], " [MASKED_URL] ")

    # 2. Extract IPv4 & IPv6
    found_ipv4 = IPV4_REGEX.findall(text_masked)
    found_ipv6 = IPV6_REGEX.findall(text_masked)
    for raw_ip in found_ipv4 + found_ipv6:
        valid, norm, version = validate_and_normalize_ip(raw_ip)
        if valid and norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            extracted["ips"].append({
                "raw": raw_ip,
                "normalized": norm,
                "defanged": defang_ioc(norm, "IP"),
                "version": version,
                "type": "IP"
            })

    # 3. Extract Hashes
    found_sha256 = SHA256_REGEX.findall(text_masked)
    found_sha1 = SHA1_REGEX.findall(text_masked)
    found_md5 = MD5_REGEX.findall(text_masked)
    
    # Priority order: SHA256, then SHA1, then MD5 to avoid substring overlaps
    for raw_h in found_sha256:
        valid, norm, htype = validate_and_normalize_hash(raw_h)
        if valid and norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            extracted["hashes"].append({
                "raw": raw_h,
                "normalized": norm,
                "hash_type": htype,
                "type": "HASH"
            })

    for raw_h in found_sha1:
        valid, norm, htype = validate_and_normalize_hash(raw_h)
        if valid and norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            extracted["hashes"].append({
                "raw": raw_h,
                "normalized": norm,
                "hash_type": htype,
                "type": "HASH"
            })

    for raw_h in found_md5:
        valid, norm, htype = validate_and_normalize_hash(raw_h)
        if valid and norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            extracted["hashes"].append({
                "raw": raw_h,
                "normalized": norm,
                "hash_type": htype,
                "type": "HASH"
            })

    # 4. Extract Domains
    found_domains = DOMAIN_REGEX.findall(text_masked)
    for raw_d in found_domains:
        valid, norm = validate_and_normalize_domain(raw_d)
        if valid and norm and norm not in seen_normalized:
            # Additional check: make sure it is not a filename or hash
            if not norm.endswith(('.exe', '.dll', '.pdf', '.txt', '.zip', '.tar', '.gz', '.png', '.jpg')):
                seen_normalized.add(norm)
                extracted["domains"].append({
                    "raw": raw_d,
                    "normalized": norm,
                    "defanged": defang_ioc(norm, "DOMAIN"),
                    "type": "DOMAIN"
                })

    return extracted
