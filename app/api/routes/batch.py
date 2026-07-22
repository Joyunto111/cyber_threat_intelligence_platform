"""Batch IOC Analysis API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List

from app.database.session import get_db
from app.engines import analyze_any_ioc
from app.core.validator import extract_all_iocs_from_text, detect_ioc_type
from app.models.schemas import BatchAnalyzeRequest, BatchAnalyzeResponse, FullIOCAnalysisResponse

router = APIRouter(prefix="/batch", tags=["Batch Analysis"])


@router.post("", response_model=BatchAnalyzeResponse, summary="Analyze List of Indicators in Batch")
def analyze_batch(request: BatchAnalyzeRequest, db: Session = Depends(get_db)):
    """Analyzes a bulk list of indicators, applying rate limits and returning aggregated intelligence."""
    results: List[FullIOCAnalysisResponse] = []
    
    # Limit batch size to 50 indicators per request for stability
    indicators = request.indicators[:50]

    for item in indicators:
        clean = item.strip()
        if not clean:
            continue
        try:
            res = analyze_any_ioc(clean, db=db, use_cache=request.use_cache)
            results.append(res)
        except Exception as e:
            # Continue on individual errors
            continue

    return BatchAnalyzeResponse(
        total_submitted=len(indicators),
        total_processed=len(results),
        results=results
    )


@router.post("/upload", response_model=BatchAnalyzeResponse, summary="Upload CSV or TXT File for Batch Analysis")
async def upload_batch_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Extracts indicators from an uploaded CSV or TXT file and analyzes all discovered IOCs."""
    try:
        content_bytes = await file.read()
        text_content = content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    extracted = extract_all_iocs_from_text(text_content)
    
    all_raw_iocs = (
        [item["normalized"] for item in extracted["ips"]] +
        [item["normalized"] for item in extracted["domains"]] +
        [item["normalized"] for item in extracted["urls"]] +
        [item["normalized"] for item in extracted["hashes"]]
    )

    # Process up to 50 IOCs
    iocs_to_process = all_raw_iocs[:50]
    results: List[FullIOCAnalysisResponse] = []

    for ioc in iocs_to_process:
        try:
            res = analyze_any_ioc(ioc, db=db, use_cache=True)
            results.append(res)
        except Exception:
            continue

    return BatchAnalyzeResponse(
        total_submitted=len(all_raw_iocs),
        total_processed=len(results),
        results=results
    )
