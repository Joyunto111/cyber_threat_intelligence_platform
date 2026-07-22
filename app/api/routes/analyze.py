"""IOC Analysis API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.database.session import get_db
from app.engines import analyze_any_ioc
from app.engines.ip_engine import ip_engine
from app.engines.domain_engine import domain_engine
from app.engines.url_engine import url_engine
from app.engines.hash_engine import hash_engine
from app.models.schemas import AnalyzeRequest, FullIOCAnalysisResponse
from app.core.exceptions import InvalidIOCException, SSRFSecurityException

router = APIRouter(prefix="/analyze", tags=["IOC Analysis"])


@router.post("", response_model=FullIOCAnalysisResponse, summary="Analyze Any IOC")
def analyze_indicator(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Automatically detects IOC type (IP, Domain, URL, Hash) and executes full multi-source threat intelligence analysis."""
    try:
        return analyze_any_ioc(request.indicator, db=db, use_cache=request.use_cache)
    except InvalidIOCException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SSRFSecurityException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@router.post("/ip", response_model=FullIOCAnalysisResponse, summary="Analyze IP Address")
def analyze_ip(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyzes an IPv4 or IPv6 address for reputation, geolocation, abuse reports, and reverse DNS."""
    try:
        return ip_engine.analyze(request.indicator, db=db, use_cache=request.use_cache)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/domain", response_model=FullIOCAnalysisResponse, summary="Analyze Domain")
def analyze_domain(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyzes a domain for DNS records, WHOIS/RDAP, DGA generation, typosquatting, and threat feeds."""
    try:
        return domain_engine.analyze(request.indicator, db=db, use_cache=request.use_cache)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/url", response_model=FullIOCAnalysisResponse, summary="Analyze URL")
def analyze_url(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyzes a URL using SSRF-safe HTTP probes, phishing heuristics, and threat lookups without executing code."""
    try:
        return url_engine.analyze(request.indicator, db=db, use_cache=request.use_cache)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SSRFSecurityException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hash", response_model=FullIOCAnalysisResponse, summary="Analyze File Hash")
def analyze_hash(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyzes an MD5, SHA-1, or SHA-256 hash for known malware families and detection history."""
    try:
        return hash_engine.analyze(request.indicator, db=db, use_cache=request.use_cache)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/upload-file", response_model=FullIOCAnalysisResponse, summary="Safely Hash and Analyze Uploaded File")
async def upload_and_hash_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Computes cryptographic hashes (MD5, SHA1, SHA256) of an uploaded file in-memory without executing it, then queries threat intelligence."""
    try:
        return hash_engine.analyze_uploaded_file(file.file, file.filename, db=db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File inspection error: {str(e)}")
