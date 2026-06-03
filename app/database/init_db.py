"""Database Initialization and Seed Data Loader."""

import json
from pathlib import Path
from sqlalchemy.orm import Session
from app.database.session import engine, SessionLocal, init_database
from app.models.database import IOCRecord, AnalysisResult, IOCRelationship, AuditLog
from app.core.validator import defang_ioc

LOCAL_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "local_threat_db.json"


def seed_database_if_empty(db: Session):
    """Populates the database with initial baseline IOC records and verified relationships."""
    if db.query(IOCRecord).first() is not None:
        return  # Already seeded or has data

    if not LOCAL_DB_PATH.exists():
        return

    try:
        with open(LOCAL_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading local threat db: {e}")
        return

    # Seed known hashes
    for h_val, info in data.get("known_hashes", {}).items():
        ioc = IOCRecord(
            indicator_value=h_val,
            normalized_value=h_val.lower(),
            indicator_type="HASH",
            defanged_value=defang_ioc(h_val, "HASH"),
            risk_score=float(info.get("score", 0)),
            risk_category=info.get("severity", "UNKNOWN"),
            confidence_score=95.0,
            threat_classification=info.get("type", "UNKNOWN"),
            notes=f"{info.get('name')}: {info.get('description')}"
        )
        db.add(ioc)
        db.flush()

        # Add AnalysisResult
        analysis = AnalysisResult(
            ioc_id=ioc.id,
            provider_name=info.get("source", "Local Intelligence"),
            status="SUCCESS",
            is_malicious=info.get("score", 0) > 50,
            reputation_score=float(info.get("score", 0)),
            detection_count=45 if info.get("score", 0) > 50 else 0,
            total_engines=70,
            source_reliability=0.95,
            parsed_summary_json=info
        )
        db.add(analysis)

    # Seed known IPs
    for ip_val, info in data.get("known_ips", {}).items():
        ioc = IOCRecord(
            indicator_value=ip_val,
            normalized_value=ip_val,
            indicator_type="IP",
            defanged_value=defang_ioc(ip_val, "IP"),
            risk_score=float(info.get("score", 0)),
            risk_category=info.get("severity", "UNKNOWN"),
            confidence_score=90.0,
            threat_classification=info.get("category", "UNKNOWN"),
            notes=f"Tags: {', '.join(info.get('tags', []))}"
        )
        db.add(ioc)
        db.flush()

        analysis = AnalysisResult(
            ioc_id=ioc.id,
            provider_name=info.get("source", "Local Intelligence"),
            status="SUCCESS",
            is_malicious=info.get("score", 0) > 50,
            reputation_score=float(info.get("score", 0)),
            detection_count=28 if info.get("score", 0) > 50 else 1,
            total_engines=70,
            source_reliability=0.90,
            parsed_summary_json=info
        )
        db.add(analysis)

    # Seed known domains
    for dom_val, info in data.get("known_domains", {}).items():
        ioc = IOCRecord(
            indicator_value=dom_val,
            normalized_value=dom_val.lower(),
            indicator_type="DOMAIN",
            defanged_value=defang_ioc(dom_val, "DOMAIN"),
            risk_score=float(info.get("score", 0)),
            risk_category=info.get("severity", "UNKNOWN"),
            confidence_score=90.0,
            threat_classification=info.get("category", "UNKNOWN"),
            notes=f"Target: {info.get('target_brand', 'Unknown')}"
        )
        db.add(ioc)
        db.flush()

        analysis = AnalysisResult(
            ioc_id=ioc.id,
            provider_name=info.get("source", "Local Intelligence"),
            status="SUCCESS",
            is_malicious=info.get("score", 0) > 50,
            reputation_score=float(info.get("score", 0)),
            detection_count=35,
            total_engines=70,
            source_reliability=0.90,
            parsed_summary_json=info
        )
        db.add(analysis)

    # Seed Campaigns & Correlations
    for camp in data.get("known_c2_campaigns", []):
        camp_name = camp.get("name")
        for ioc_val in camp.get("iocs", []):
            db_ioc = db.query(IOCRecord).filter(IOCRecord.normalized_value == ioc_val.lower()).first()
            if db_ioc:
                rel = IOCRelationship(
                    source_ioc_id=db_ioc.id,
                    target_value=camp_name,
                    target_type="CAMPAIGN",
                    relationship_type="ATTRIBUTED_TO",
                    evidence=f"Campaign attribution to {camp.get('actor')} ({camp.get('description')})",
                    source_provider="MITRE & Threat Intel Feeds",
                    confidence=0.95
                )
                db.add(rel)

    # Initial audit log
    log = AuditLog(
        action="SYSTEM_INIT",
        details={"message": "Database initialized and baseline threat intelligence loaded."},
        client_ip="127.0.0.1"
    )
    db.add(log)
    db.commit()


def setup_db():
    init_database()
    with SessionLocal() as db:
        seed_database_if_empty(db)


if __name__ == "__main__":
    setup_db()
    print("Database initialized successfully.")
