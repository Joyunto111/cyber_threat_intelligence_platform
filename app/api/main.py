"""FastAPI Main Application Module."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import settings
from app.database.session import get_db
from app.database.init_db import setup_db
from app.models.database import IOCRecord
from app.api.routes.analyze import router as router_analyze
from app.api.routes.extract import router as router_extract
from app.api.routes.batch import router as router_batch
from app.api.routes.correlation import router as router_correlation
from app.api.routes.history import router as router_history
from app.api.routes.reports import router as router_reports
from app.api.routes.config import router as router_config
from app.api.routes.monitor import router as router_monitor


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database schema is created and initial threat signatures seeded
    setup_db()
    yield
    # Shutdown logic if needed


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise-grade Cyber Threat Intelligence Analysis Platform for IOC extraction, validation, multi-source correlation, and AI-powered risk scoring.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for frontend and API clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all API v1 routes
API_PREFIX = "/api/v1"
app.include_router(router_analyze, prefix=API_PREFIX)
app.include_router(router_extract, prefix=API_PREFIX)
app.include_router(router_batch, prefix=API_PREFIX)
app.include_router(router_correlation, prefix=API_PREFIX)
app.include_router(router_history, prefix=API_PREFIX)
app.include_router(router_reports, prefix=API_PREFIX)
app.include_router(router_config, prefix=API_PREFIX)
app.include_router(router_monitor, prefix=API_PREFIX)


@app.get("/health", tags=["System"])
def health_check():
    """Returns application health and operational parameters."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


@app.get(f"{API_PREFIX}/stats", tags=["System"])
def get_platform_statistics(db: Session = Depends(get_db)):
    """Returns high-level statistics for the threat intelligence executive dashboard."""
    total_iocs = db.query(IOCRecord).count()
    malicious_count = db.query(IOCRecord).filter(IOCRecord.risk_category.in_(["HIGH", "CRITICAL"])).count()
    suspicious_count = db.query(IOCRecord).filter(IOCRecord.risk_category == "MEDIUM").count()
    unknown_low_count = total_iocs - (malicious_count + suspicious_count)

    type_counts = db.query(IOCRecord.indicator_type, func.count(IOCRecord.id)).group_by(IOCRecord.indicator_type).all()
    type_distribution = {t: count for t, count in type_counts}

    recent_investigations = db.query(IOCRecord).order_by(IOCRecord.last_analyzed.desc()).limit(8).all()
    recent = [{
        "indicator": r.indicator_value,
        "defanged": r.defanged_value,
        "type": r.indicator_type,
        "risk_score": r.risk_score,
        "category": r.risk_category,
        "classification": r.threat_classification,
        "timestamp": r.last_analyzed.isoformat() if r.last_analyzed else None
    } for r in recent_investigations]

    return {
        "total_analyzed": total_iocs,
        "malicious_indicators": malicious_count,
        "suspicious_indicators": suspicious_count,
        "unknown_or_low_risk": unknown_low_count,
        "type_distribution": type_distribution,
        "recent_investigations": recent
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.api.main:app", host="0.0.0.0", port=8000, reload=True)
