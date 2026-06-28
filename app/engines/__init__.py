"""Threat Analysis Engines Dispatcher."""

from typing import Optional
from sqlalchemy.orm import Session

from app.core.validator import detect_ioc_type
from app.core.exceptions import InvalidIOCException
from app.engines.ip_engine import ip_engine
from app.engines.domain_engine import domain_engine
from app.engines.url_engine import url_engine
from app.engines.hash_engine import hash_engine
from app.models.schemas import FullIOCAnalysisResponse


def analyze_any_ioc(ioc_str: str, db: Optional[Session] = None, use_cache: bool = True) -> FullIOCAnalysisResponse:
    """Intelligently detects IOC type and dispatches to the corresponding analysis engine."""
    ioc_type, normalized = detect_ioc_type(ioc_str)
    
    if ioc_type == "IP":
        return ip_engine.analyze(normalized, db=db, use_cache=use_cache)
    elif ioc_type == "DOMAIN":
        return domain_engine.analyze(normalized, db=db, use_cache=use_cache)
    elif ioc_type == "URL":
        return url_engine.analyze(normalized, db=db, use_cache=use_cache)
    elif ioc_type == "HASH":
        return hash_engine.analyze(normalized, db=db, use_cache=use_cache)
    else:
        raise InvalidIOCException(
            f"Could not identify IOC type for '{ioc_str}'. Must be a valid IPv4/IPv6, Domain, URL, or Hash (MD5/SHA1/SHA256)."
        )
