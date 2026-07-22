"""Threat Intelligence Report Generation API Endpoints."""

import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.database import ThreatReport
from app.models.schemas import ReportRequest, ReportResponse
from app.reports import pdf_generator, json_generator, csv_generator
from app.engines import analyze_any_ioc

router = APIRouter(prefix="/reports", tags=["Threat Reports"])


@router.post("/generate", response_model=ReportResponse, summary="Generate Threat Assessment Report (PDF, JSON, CSV)")
def generate_report(request: ReportRequest, db: Session = Depends(get_db)):
    """Generates a professional downloadable PDF, JSON, or CSV threat intelligence report for the requested IOCs."""
    if not request.indicators:
        raise HTTPException(status_code=400, detail="At least one indicator must be specified.")

    analyses = []
    for item in request.indicators[:25]:  # Limit to 25 per report for document clarity
        clean = item.strip()
        if not clean:
            continue
        try:
            res = analyze_any_ioc(clean, db=db, use_cache=True)
            analyses.append(res.model_dump())
        except Exception:
            continue

    if not analyses:
        raise HTTPException(status_code=400, detail="No valid indicators could be analyzed for report.")

    report_type_clean = request.report_type.upper().strip()
    file_path = ""

    if report_type_clean == "PDF":
        file_path = pdf_generator.generate(analyses, title=request.title)
    elif report_type_clean == "JSON":
        file_path = json_generator.generate(analyses, title=request.title)
    elif report_type_clean == "CSV":
        file_path = csv_generator.generate(analyses)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported report format: {request.report_type}. Use PDF, JSON, or CSV.")

    # Record report in database
    db_report = ThreatReport(
        report_title=request.title,
        report_type=report_type_clean,
        file_path=file_path,
        ioc_count=len(analyses),
        summary_json={
            "indicators": [a["indicator"] for a in analyses],
            "average_risk": sum(a["risk_assessment"]["risk_score"] for a in analyses) / len(analyses)
        }
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)

    return ReportResponse(
        report_id=db_report.id,
        title=db_report.report_title,
        report_type=db_report.report_type,
        created_at=db_report.created_at,
        download_url=f"/api/v1/reports/{db_report.id}/download",
        summary=db_report.summary_json
    )


@router.get("", summary="List Generated Threat Reports")
def list_reports(limit: int = 20, db: Session = Depends(get_db)):
    """Lists historical threat reports generated on the platform."""
    reports = db.query(ThreatReport).order_by(desc(ThreatReport.created_at)).limit(limit).all()
    return [{
        "id": r.id,
        "title": r.report_title,
        "type": r.report_type,
        "ioc_count": r.ioc_count,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "download_url": f"/api/v1/reports/{r.id}/download"
    } for r in reports]


@router.get("/{report_id}/download", summary="Download Generated Threat Report")
def download_report(report_id: int, db: Session = Depends(get_db)):
    """Downloads a generated PDF, JSON, or CSV report file."""
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report or not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")

    filename = Path(report.file_path).name
    media_type = "application/octet-stream"
    if report.report_type == "PDF":
        media_type = "application/pdf"
    elif report.report_type == "JSON":
        media_type = "application/json"
    elif report.report_type == "CSV":
        media_type = "text/csv"

    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename
    )
