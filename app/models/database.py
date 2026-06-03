"""SQLAlchemy Database Models for Cyber Threat Intelligence Platform.

Defines schemas for IOC records, provider analysis snapshots,
relationships, reports, audit logs, and monitoring watchlists.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class IOCRecord(Base):
    __tablename__ = "ioc_records"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String(512), nullable=False, index=True)
    normalized_value = Column(String(512), nullable=False, unique=True, index=True)
    indicator_type = Column(String(32), nullable=False, index=True)  # IP, DOMAIN, URL, HASH
    defanged_value = Column(String(512), nullable=False)
    
    # Risk and Confidence
    risk_score = Column(Float, default=0.0, index=True)
    risk_category = Column(String(32), default="UNKNOWN", index=True)  # LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    confidence_score = Column(Float, default=0.0)
    threat_classification = Column(String(64), default="UNKNOWN")  # BENIGN, SUSPICIOUS, MALWARE, PHISHING, C2, UNKNOWN
    
    # Metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_analyzed = Column(DateTime, default=datetime.utcnow, index=True)
    analysis_count = Column(Integer, default=1)
    is_monitored = Column(Boolean, default=False, index=True)
    notes = Column(Text, nullable=True)

    # Relationships
    analysis_results = relationship("AnalysisResult", back_populates="ioc", cascade="all, delete-orphan")
    outgoing_relationships = relationship("IOCRelationship", back_populates="source_ioc", foreign_keys="[IOCRelationship.source_ioc_id]", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<IOCRecord(id={self.id}, value='{self.normalized_value}', type='{self.indicator_type}', risk={self.risk_score})>"


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("ioc_records.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(64), nullable=False, index=True)  # VirusTotal, AbuseIPDB, URLhaus, AlienVault, LocalHeuristic, AIML
    analyzed_at = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String(32), default="SUCCESS")  # SUCCESS, FAILED, UNAVAILABLE, NOT_CONFIGURED
    
    is_malicious = Column(Boolean, nullable=True)
    reputation_score = Column(Float, nullable=True)
    detection_count = Column(Integer, default=0)
    total_engines = Column(Integer, default=0)
    source_reliability = Column(Float, default=1.0)  # 0.0 to 1.0
    
    raw_response_json = Column(JSON, nullable=True)
    parsed_summary_json = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationship
    ioc = relationship("IOCRecord", back_populates="analysis_results")

    def __repr__(self):
        return f"<AnalysisResult(provider='{self.provider_name}', status='{self.status}', malicious={self.is_malicious})>"


class IOCRelationship(Base):
    __tablename__ = "ioc_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_ioc_id = Column(Integer, ForeignKey("ioc_records.id", ondelete="CASCADE"), nullable=False, index=True)
    target_value = Column(String(512), nullable=False, index=True)
    target_type = Column(String(32), nullable=False)  # IP, DOMAIN, URL, HASH, CAMPAIGN, MALWARE_FAMILY
    relationship_type = Column(String(64), nullable=False)  # RESOLVES_TO, HOSTS_URL, COMMUNICATES_WITH, DROPPED_BY, ATTRIBUTED_TO
    evidence = Column(Text, nullable=False)
    source_provider = Column(String(64), default="Heuristics")
    confidence = Column(Float, default=0.8)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    source_ioc = relationship("IOCRecord", back_populates="outgoing_relationships", foreign_keys=[source_ioc_id])

    def __repr__(self):
        return f"<IOCRelationship({self.source_ioc_id} --[{self.relationship_type}]--> {self.target_value})>"


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_title = Column(String(256), nullable=False)
    report_type = Column(String(32), nullable=False)  # PDF, JSON, CSV
    file_path = Column(String(512), nullable=True)
    ioc_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    summary_json = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ThreatReport(id={self.id}, title='{self.report_title}', type='{self.report_type}')>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String(64), nullable=True)

    def __repr__(self):
        return f"<AuditLog(action='{self.action}', timestamp='{self.timestamp}')>"


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("ioc_records.id", ondelete="CASCADE"), nullable=False, unique=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    alert_on_change = Column(Boolean, default=True)
    last_risk_score = Column(Float, default=0.0)
    last_checked_at = Column(DateTime, default=datetime.utcnow)
    alert_history = Column(JSON, default=list)

    ioc = relationship("IOCRecord")
