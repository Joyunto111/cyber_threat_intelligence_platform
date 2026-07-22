"""IOC Correlation and Relationship API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.database import IOCRecord
from app.models.schemas import CorrelationGraph
from app.engines.correlation import correlation_engine
from app.core.validator import detect_ioc_type

router = APIRouter(prefix="/correlate", tags=["IOC Correlation Graph"])


@router.get("/{ioc_value}", response_model=CorrelationGraph, summary="Get Correlation Graph for Indicator")
def get_correlation_graph(ioc_value: str, db: Session = Depends(get_db)):
    """Retrieves the evidence-based relationship graph connecting an indicator to IPs, domains, URLs, hashes, and campaigns."""
    ioc_type, norm_val = detect_ioc_type(ioc_value)
    if not norm_val:
        raise HTTPException(status_code=400, detail="Invalid indicator format.")

    record = db.query(IOCRecord).filter(IOCRecord.normalized_value == norm_val).first()
    risk_score = record.risk_score if record else 50.0
    category = record.risk_category if record else "UNKNOWN"

    graph = correlation_engine.build_correlation_graph(
        center_ioc=norm_val,
        center_type=ioc_type,
        center_risk=risk_score,
        center_category=category,
        db=db
    )

    return graph
