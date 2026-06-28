"""IP Intelligence Engine.

Performs IPv4/IPv6 validation, public/private network classification,
abuse history analysis, geolocation/ASN lookup, reverse DNS, and provider correlation.
"""

import socket
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.validator import validate_and_normalize_ip, defang_ioc
from app.core.security import is_ip_private_or_reserved
from app.providers import provider_manager
from app.providers.local_intel import query_ip_geolocation
from app.engines.risk_scorer import risk_scorer
from app.engines.ai_engine import ai_engine
from app.engines.correlation import correlation_engine
from app.models.database import IOCRecord, AnalysisResult
from app.models.schemas import FullIOCAnalysisResponse, AIAnalysisResult


class IPIntelligenceEngine:
    """Specialized engine for IP address threat investigation."""

    def analyze(self, ip_str: str, db: Optional[Session] = None, use_cache: bool = True) -> FullIOCAnalysisResponse:
        is_valid, norm_ip, version = validate_and_normalize_ip(ip_str)
        if not is_valid or not norm_ip:
            raise ValueError(f"Invalid IP address format: {ip_str}")

        is_private, private_reason = is_ip_private_or_reserved(norm_ip)

        # 1. Geolocation and ASN
        geo_info = query_ip_geolocation(norm_ip)

        # 2. Reverse DNS lookup
        ptr_hostnames = []
        try:
            host, _, _ = socket.gethostbyaddr(norm_ip)
            if host:
                ptr_hostnames.append(host)
        except Exception:
            pass

        # 3. Query all threat providers
        provider_results = provider_manager.query_all(norm_ip, "IP", use_cache=use_cache)

        # 4. Formulate Heuristic Flags
        heuristic_flags = []
        if is_private:
            heuristic_flags.append({
                "name": "Private/Internal IP Space",
                "points": 5.0,
                "reason": f"Address is non-routable: {private_reason}"
            })

        # Check for Tor / proxy markers in geo or provider summaries
        isp_lower = str(geo_info.get("isp", "")).lower()
        if "tor" in isp_lower or "vpn" in isp_lower or "proxy" in isp_lower:
            heuristic_flags.append({
                "name": "Anonymization Infrastructure",
                "points": 35.0,
                "reason": f"IP is associated with anonymization network ({geo_info.get('isp')})"
            })

        # 5. AI / ML Insights
        ml_anomalies = ai_engine.detect_anomalies(norm_ip, "IP")
        ml_insights = {
            "is_anomaly": len(ml_anomalies) > 0,
            "anomaly_details": ", ".join(ml_anomalies)
        }

        # 6. Calculate Risk Assessment
        risk_assessment = risk_scorer.calculate_assessment(
            ioc_value=norm_ip,
            ioc_type="IP",
            provider_results=provider_results,
            heuristic_flags=heuristic_flags,
            ml_insights=ml_insights
        )

        # 7. AI Executive Summary
        summary_text = ai_engine.generate_natural_language_summary(
            ioc_value=norm_ip,
            ioc_type="IP",
            risk_score=risk_assessment.risk_score,
            risk_category=risk_assessment.risk_category,
            confidence_score=risk_assessment.confidence_score,
            classification=risk_assessment.threat_classification,
            explanations=[e.model_dump() for e in risk_assessment.explanations],
            recommendations=risk_assessment.recommended_actions
        )

        ai_analysis_result = AIAnalysisResult(
            threat_summary=summary_text,
            anomalies_detected=ml_anomalies
        )

        # 8. Build Correlations
        extracted_links = []
        for ptr in ptr_hostnames:
            extracted_links.append({
                "target_value": ptr,
                "target_type": "DOMAIN",
                "relationship_type": "RESOLVES_PTR",
                "evidence": f"Reverse DNS PTR record for {norm_ip}",
                "source_provider": "DNS Resolver",
                "confidence": 0.95
            })

        graph = correlation_engine.build_correlation_graph(
            center_ioc=norm_ip,
            center_type="IP",
            center_risk=risk_assessment.risk_score,
            center_category=risk_assessment.risk_category,
            db=db,
            extracted_links=extracted_links
        )

        # 9. Persist to DB if session provided
        investigation_id = None
        if db:
            record = db.query(IOCRecord).filter(IOCRecord.normalized_value == norm_ip).first()
            if not record:
                record = IOCRecord(
                    indicator_value=ip_str,
                    normalized_value=norm_ip,
                    indicator_type="IP",
                    defanged_value=defang_ioc(norm_ip, "IP"),
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

            # Save snapshot analysis results
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
            "version": version,
            "is_private": is_private,
            "private_reason": private_reason,
            "ptr_hostnames": ptr_hostnames,
            "geolocation": geo_info
        }

        return FullIOCAnalysisResponse(
            indicator=ip_str,
            normalized=norm_ip,
            defanged=defang_ioc(norm_ip, "IP"),
            indicator_type="IP",
            timestamp=datetime.utcnow(),
            risk_assessment=risk_assessment,
            ai_insights=ai_analysis_result,
            provider_results=provider_results,
            module_details=module_details,
            correlation_graph=graph,
            investigation_id=investigation_id
        )


ip_engine = IPIntelligenceEngine()
