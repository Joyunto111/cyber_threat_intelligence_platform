"""File Hash Intelligence Engine.

Validates MD5, SHA-1, SHA-256 hashes, computes safe in-memory hashes for uploaded
files without execution, matches against signature databases, and queries threat feeds.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.validator import validate_and_normalize_hash, defang_ioc
from app.core.security import calculate_file_hashes_safely
from app.providers import provider_manager
from app.engines.risk_scorer import risk_scorer
from app.engines.ai_engine import ai_engine
from app.engines.correlation import correlation_engine
from app.models.database import IOCRecord, AnalysisResult
from app.models.schemas import FullIOCAnalysisResponse, AIAnalysisResult


class HashIntelligenceEngine:
    """Specialized engine for cryptographic file hash threat investigation."""

    def analyze(self, hash_str: str, db: Optional[Session] = None, use_cache: bool = True) -> FullIOCAnalysisResponse:
        is_valid, norm_hash, hash_type = validate_and_normalize_hash(hash_str)
        if not is_valid or not norm_hash:
            raise ValueError(f"Invalid hash format: {hash_str}. Must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters.")

        # 1. Query all Threat Providers
        provider_results = provider_manager.query_all(norm_hash, "HASH", use_cache=use_cache)

        # 2. Formulate Heuristic Flags
        heuristic_flags = []
        is_known_malware = False
        malware_families = []

        for prov in provider_results:
            if prov.status == "SUCCESS":
                if prov.is_malicious:
                    is_known_malware = True
                    heuristic_flags.append({
                        "name": f"Malware Signature Match ({prov.provider_name})",
                        "points": 50.0,
                        "reason": f"File hash positively identified as malicious by {prov.provider_name}."
                    })
                mf = prov.summary.get("malware_family") or prov.summary.get("malware_families")
                if mf:
                    if isinstance(mf, list):
                        malware_families.extend(mf)
                    else:
                        malware_families.append(mf)

        # 3. AI / ML Insights
        ml_insights = {
            "is_anomaly": is_known_malware,
            "anomaly_details": f"Corroborated malicious payload: {', '.join(set(malware_families)) if malware_families else 'Signature Detection'}"
        }

        # 4. Compute Risk Assessment
        risk_assessment = risk_scorer.calculate_assessment(
            ioc_value=norm_hash,
            ioc_type="HASH",
            provider_results=provider_results,
            heuristic_flags=heuristic_flags,
            ml_insights=ml_insights
        )

        # 5. AI Executive Summary
        summary_text = ai_engine.generate_natural_language_summary(
            ioc_value=norm_hash,
            ioc_type="HASH",
            risk_score=risk_assessment.risk_score,
            risk_category=risk_assessment.risk_category,
            confidence_score=risk_assessment.confidence_score,
            classification=risk_assessment.threat_classification,
            explanations=[e.model_dump() for e in risk_assessment.explanations],
            recommendations=risk_assessment.recommended_actions
        )

        ai_insights_obj = AIAnalysisResult(
            threat_summary=summary_text,
            anomalies_detected=[f"Malware Family: {m}" for m in set(malware_families)]
        )

        # 6. Build Evidence-Based Correlation Links
        extracted_links = []
        for mf_name in set(malware_families):
            extracted_links.append({
                "target_value": mf_name,
                "target_type": "MALWARE_FAMILY",
                "relationship_type": "IDENTIFIED_AS",
                "evidence": "Signature match / threat telemetry report",
                "source_provider": "Threat Intelligence Provider",
                "confidence": 0.95,
                "target_risk": 95.0
            })

        graph = correlation_engine.build_correlation_graph(
            center_ioc=norm_hash,
            center_type="HASH",
            center_risk=risk_assessment.risk_score,
            center_category=risk_assessment.risk_category,
            db=db,
            extracted_links=extracted_links
        )

        # 7. Persist to DB if session exists
        investigation_id = None
        if db:
            record = db.query(IOCRecord).filter(IOCRecord.normalized_value == norm_hash).first()
            if not record:
                record = IOCRecord(
                    indicator_value=hash_str,
                    normalized_value=norm_hash,
                    indicator_type="HASH",
                    defanged_value=defang_ioc(norm_hash, "HASH"),
                    risk_score=risk_assessment.risk_score,
                    risk_category=risk_assessment.risk_category,
                    confidence_score=risk_assessment.confidence_score,
                    threat_classification=risk_assessment.threat_classification,
                    last_analyzed=datetime.utcnow()
                )
                db.add(record)
                db.flush()
            else:
                record.risk_score = risk_assessment.risk_score
                record.risk_category = risk_assessment.risk_category
                record.confidence_score = risk_assessment.confidence_score
                record.threat_classification = risk_assessment.threat_classification
                record.last_analyzed = datetime.utcnow()
                record.analysis_count += 1

            investigation_id = record.id

            for prov in provider_results:
                analysis = AnalysisResult(
                    ioc_id=record.id,
                    provider_name=prov.provider_name,
                    status=prov.status,
                    is_malicious=prov.is_malicious,
                    reputation_score=prov.reputation_score,
                    detection_count=prov.detection_count,
                    total_engines=prov.total_engines,
                    source_reliability=prov.source_reliability,
                    parsed_summary_json=prov.summary,
                    error_message=prov.error_message
                )
                db.add(analysis)

            correlation_engine.persist_relationships(db, record.id, extracted_links)
            db.commit()

        module_details = {
            "hash_algorithm": hash_type,
            "malware_families": list(set(malware_families))
        }

        return FullIOCAnalysisResponse(
            indicator=hash_str,
            normalized=norm_hash,
            defanged=defang_ioc(norm_hash, "HASH"),
            indicator_type="HASH",
            timestamp=datetime.utcnow(),
            risk_assessment=risk_assessment,
            ai_insights=ai_insights_obj,
            provider_results=provider_results,
            module_details=module_details,
            correlation_graph=graph,
            investigation_id=investigation_id
        )

    def analyze_uploaded_file(self, file_stream, filename: str, db: Optional[Session] = None) -> FullIOCAnalysisResponse:
        """Computes hashes safely from an uploaded file stream and executes hash intelligence."""
        hashes_info = calculate_file_hashes_safely(file_stream)
        sha256 = hashes_info["sha256"]

        # Analyze using SHA-256 as primary indicator
        analysis_resp = self.analyze(sha256, db=db)
        
        # Enrich module details with file upload metadata
        analysis_resp.module_details.update({
            "uploaded_filename": filename,
            "md5": hashes_info["md5"],
            "sha1": hashes_info["sha1"],
            "sha256": hashes_info["sha256"],
            "size_bytes": hashes_info["size_bytes"],
            "magic_header_hex": hashes_info["magic_header_hex"],
            "detected_file_type": hashes_info["detected_file_type"]
        })
        return analysis_resp


hash_engine = HashIntelligenceEngine()
