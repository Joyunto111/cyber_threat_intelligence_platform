"""Threat Monitoring and Watchlist API Endpoints."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.database.session import get_db
from app.models.database import IOCRecord, WatchlistItem
from app.engines import analyze_any_ioc

router = APIRouter(prefix="/monitor", tags=["Threat Monitoring & Watchlist"])


class WatchlistAddRequest(BaseModel):
    indicator: str
    alert_on_change: bool = True


@router.get("/watchlist", summary="Get Monitored Watchlist IOCs")
def get_watchlist(db: Session = Depends(get_db)):
    """Retrieves all indicators actively monitored on the platform watchlist."""
    items = db.query(WatchlistItem).join(IOCRecord).all()
    out = []
    for w in items:
        out.append({
            "watchlist_id": w.id,
            "ioc_id": w.ioc_id,
            "indicator": w.ioc.indicator_value,
            "type": w.ioc.indicator_type,
            "defanged": w.ioc.defanged_value,
            "current_risk_score": w.ioc.risk_score,
            "previous_risk_score": w.last_risk_score,
            "category": w.ioc.risk_category,
            "added_at": w.added_at.isoformat() if w.added_at else None,
            "last_checked_at": w.last_checked_at.isoformat() if w.last_checked_at else None,
            "alert_on_change": w.alert_on_change,
            "alerts": w.alert_history or []
        })
    return out


@router.post("/add", summary="Add Indicator to Watchlist")
def add_to_watchlist(request: WatchlistAddRequest, db: Session = Depends(get_db)):
    """Adds an indicator to active threat monitoring."""
    # Ensure IOC is analyzed and in DB
    analysis = analyze_any_ioc(request.indicator, db=db, use_cache=True)
    ioc_rec = db.query(IOCRecord).filter(IOCRecord.normalized_value == analysis.normalized).first()
    
    if not ioc_rec:
        raise HTTPException(status_code=500, detail="Failed to locate indicator record in database.")

    ioc_rec.is_monitored = True

    # Check if already in watchlist
    existing = db.query(WatchlistItem).filter(WatchlistItem.ioc_id == ioc_rec.id).first()
    if existing:
        return {"status": "already_monitored", "watchlist_id": existing.id}

    item = WatchlistItem(
        ioc_id=ioc_rec.id,
        alert_on_change=request.alert_on_change,
        last_risk_score=ioc_rec.risk_score,
        last_checked_at=datetime.utcnow()
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    return {"status": "added", "watchlist_id": item.id, "indicator": ioc_rec.indicator_value}


@router.delete("/{ioc_id}", summary="Remove Indicator from Watchlist")
def remove_from_watchlist(ioc_id: int, db: Session = Depends(get_db)):
    """Removes an indicator from the active monitoring watchlist."""
    item = db.query(WatchlistItem).filter(WatchlistItem.ioc_id == ioc_id).first()
    if item:
        db.delete(item)
    
    ioc_rec = db.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()
    if ioc_rec:
        ioc_rec.is_monitored = False

    db.commit()
    return {"status": "removed", "ioc_id": ioc_id}


@router.post("/check-now", summary="Execute Instant Monitoring Check")
def check_watchlist_now(db: Session = Depends(get_db)):
    """Re-analyzes all watchlist indicators to detect reputation delta and trigger alerts."""
    items = db.query(WatchlistItem).join(IOCRecord).all()
    changes_detected = []

    for w in items:
        old_score = w.last_risk_score
        # Force re-analysis without cache
        try:
            new_res = analyze_any_ioc(w.ioc.normalized_value, db=db, use_cache=False)
            new_score = new_res.risk_assessment.risk_score
            score_diff = abs(new_score - old_score)

            w.last_checked_at = datetime.utcnow()
            w.last_risk_score = new_score

            if score_diff >= 10.0:  # Significant shift
                alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "old_score": old_score,
                    "new_score": new_score,
                    "message": f"Risk score shifted by {new_score - old_score:+.1f} points (now {new_score}/100)"
                }
                history = list(w.alert_history or [])
                history.append(alert)
                w.alert_history = history
                changes_detected.append({
                    "indicator": w.ioc.indicator_value,
                    "old_score": old_score,
                    "new_score": new_score
                })
        except Exception:
            continue

    db.commit()
    return {
        "status": "completed",
        "total_monitored": len(items),
        "alerts_triggered": len(changes_detected),
        "changes": changes_detected
    }
