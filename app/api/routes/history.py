"""Historical Threat Tracking and Investigation API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any

from app.database.session import get_db
from app.models.database import IOCRecord, AnalysisResult

router = APIRouter(prefix="/history", tags=["Investigation History"])


@router.get("", summary="List Historical Investigations")
def list_investigations(
    query: Optional[str] = Query(None, description="Search indicator or notes"),
    ioc_type: Optional[str] = Query(None, description="Filter by IP, DOMAIN, URL, HASH"),
    risk_category: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, HIGH, CRITICAL"),
    limit: int = Query(50, le=100),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    """Retrieves paginated historical IOC investigations with searching and category filtering."""
    q = db.query(IOCRecord)

    if query:
        search_pattern = f"%{query.strip()}%"
        q = q.filter((IOCRecord.indicator_value.ilike(search_pattern)) | (IOCRecord.notes.ilike(search_pattern)))

    if ioc_type:
        q = q.filter(IOCRecord.indicator_type == ioc_type.upper())

    if risk_category:
        q = q.filter(IOCRecord.risk_category == risk_category.upper())

    total = q.count()
    records = q.order_by(desc(IOCRecord.last_analyzed)).offset(offset).limit(limit).all()

    items = []
    for r in records:
        items.append({
            "id": r.id,
            "indicator_value": r.indicator_value,
            "normalized_value": r.normalized_value,
            "defanged_value": r.defanged_value,
            "indicator_type": r.indicator_type,
            "risk_score": r.risk_score,
            "risk_category": r.risk_category,
            "confidence_score": r.confidence_score,
            "threat_classification": r.threat_classification,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_analyzed": r.last_analyzed.isoformat() if r.last_analyzed else None,
            "analysis_count": r.analysis_count,
            "is_monitored": r.is_monitored
        })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items
    }


@router.get("/{ioc_id}", summary="Get Detailed Historical Investigation")
def get_investigation_detail(ioc_id: int, db: Session = Depends(get_db)):
    """Retrieves full details of a specific past investigation including all provider snapshots."""
    record = db.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    analyses = []
    for a in record.analysis_results:
        analyses.append({
            "id": a.id,
            "provider_name": a.provider_name,
            "status": a.status,
            "is_malicious": a.is_malicious,
            "reputation_score": a.reputation_score,
            "detection_count": a.detection_count,
            "total_engines": a.total_engines,
            "analyzed_at": a.analyzed_at.isoformat() if a.analyzed_at else None,
            "summary": a.parsed_summary_json,
            "error_message": a.error_message
        })

    relationships = []
    for rel in record.outgoing_relationships:
        relationships.append({
            "id": rel.id,
            "target_value": rel.target_value,
            "target_type": rel.target_type,
            "relationship_type": rel.relationship_type,
            "evidence": rel.evidence,
            "source_provider": rel.source_provider,
            "confidence": rel.confidence,
            "created_at": rel.created_at.isoformat() if rel.created_at else None
        })

    return {
        "id": record.id,
        "indicator_value": record.indicator_value,
        "normalized_value": record.normalized_value,
        "defanged_value": record.defanged_value,
        "indicator_type": record.indicator_type,
        "risk_score": record.risk_score,
        "risk_category": record.risk_category,
        "confidence_score": record.confidence_score,
        "threat_classification": record.threat_classification,
        "first_seen": record.first_seen.isoformat() if record.first_seen else None,
        "last_analyzed": record.last_analyzed.isoformat() if record.last_analyzed else None,
        "analysis_count": record.analysis_count,
        "is_monitored": record.is_monitored,
        "notes": record.notes,
        "analyses": analyses,
        "relationships": relationships
    }


@router.delete("/{ioc_id}", summary="Delete Investigation Record")
def delete_investigation(ioc_id: int, db: Session = Depends(get_db)):
    """Deletes an investigation record from the historical tracking database."""
    record = db.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    db.delete(record)
    db.commit()
    return {"status": "deleted", "id": ioc_id}
