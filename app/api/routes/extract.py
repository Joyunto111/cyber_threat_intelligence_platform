"""IOC Extraction and Defanging API Endpoints."""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List

from app.core.validator import (
    extract_all_iocs_from_text, defang_ioc, refang_text
)
from app.models.schemas import (
    TextExtractionRequest, TextExtractionResponse, IOCItem,
    DefangRequest, DefangResponse
)

router = APIRouter(prefix="/extract", tags=["IOC Extraction & Formatting"])


@router.post("", response_model=TextExtractionResponse, summary="Extract and Normalize IOCs from Raw Text")
def extract_iocs(request: TextExtractionRequest):
    """Scans raw unstructured text (emails, reports, chat logs), refangs defanged patterns (hxxp, [.], etc.),
    normalizes all indicators, and groups them by IOC type.
    """
    try:
        extracted = extract_all_iocs_from_text(request.text)
        
        ips = [IOCItem(**item) for item in extracted["ips"]]
        domains = [IOCItem(**item) for item in extracted["domains"]]
        urls = [IOCItem(**item) for item in extracted["urls"]]
        hashes = [IOCItem(**item) for item in extracted["hashes"]]
        
        total = len(ips) + len(domains) + len(urls) + len(hashes)

        return TextExtractionResponse(
            total_found=total,
            ips=ips,
            domains=domains,
            urls=urls,
            hashes=hashes
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction error: {str(e)}")


@router.post("/defang", response_model=DefangResponse, summary="Defang or Refang an Indicator")
def defang_endpoint(request: DefangRequest):
    """Safely defangs or refangs an indicator string."""
    if request.defang:
        result = defang_ioc(request.ioc)
    else:
        result = refang_text(request.ioc)
    return DefangResponse(original=request.ioc, result=result)
