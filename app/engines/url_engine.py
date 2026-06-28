"""URL Intelligence Engine.

Performs URL normalization, phishing heuristics, malware extension detection,
SSRF-safe HTTP header probing (no rendering), and threat provider lookups.
"""

from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.validator import validate_and_normalize_url, defang_ioc, detect_ioc_type
from app.core.security import safe_fetch_url_metadata, SSRFSecurityException
from app.providers import provider_manager
from app.engines.risk_scorer import risk_scorer
from app.engines.ai_engine import ai_engine
from app.engines.correlation import correlation_engine
from app.models.database import IOCRecord, AnalysisResult
from app.models.schemas import FullIOCAnalysisResponse, AIAnalysisResult


class URLIntelligenceEngine:
    """Specialized engine for URL threat investigation."""

    def analyze(self, url_str: str, db: Optional[Session] = None, use_cache: bool = True) -> FullIOCAnalysisResponse:
        is_valid, norm_url = validate_and_normalize_url(url_str)
        if not is_valid or not norm_url:
            raise ValueError(f"Invalid URL structure: {url_str}")

        parsed = urlparse(norm_url)
        host = parsed.hostname or ""

        # 1. Phishing & Lexical Evaluations via AI/Heuristics
        phishing_result = ai_engine.evaluate_phishing_url(norm_url)
        anomalies = ai_engine.detect_anomalies(norm_url, "URL")

        # 2. SSRF-Safe Probe (Fetch HTTP headers & redirect chain without executing content)
        http_probe = {}
        ssrf_flag = None
        try:
            http_probe = safe_fetch_url_metadata(norm_url)
        except SSRFSecurityException as e:
            ssrf_flag = str(e)
            http_probe = {
                "reachable": False,
                "error": f"Security restriction: {str(e)}",
                "ssrf_blocked": True
            }
        except Exception as e:
            http_probe = {
                "reachable": False,
                "error": f"Probe error: {str(e)}"
            }

        # 3. Query all Threat Providers
        provider_results = provider_manager.query_all(norm_url, "URL", use_cache=use_cache)

        # 4. Formulate Heuristic Flags
        heuristic_flags = []
        if ssrf_flag:
            heuristic_flags.append({
                "name": "SSRF / Restricted Target",
                "points": 50.0,
                "reason": f"Target blocked by SSRF filter: {ssrf_flag}"
            })

        if phishing_result.get("is_phishing"):
            heuristic_flags.append({
                "name": "Phishing Lexical Structure",
                "points": 35.0,
                "reason": f"Phishing markers: {', '.join(phishing_result.get('flags', []))}"
            })

        for anomaly in anomalies:
            heuristic_flags.append({
                "name": "Suspicious URL Payload Indicator",
                "points": 30.0,
                "reason": anomaly
            })

        # Check redirect hops
        redirect_count = http_probe.get("redirect_count", 0)
        if redirect_count >= 2:
            heuristic_flags.append({
                "name": "Multiple HTTP Redirects",
                "points": 15.0,
                "reason": f"URL redirected {redirect_count} times before reaching final endpoint."
            })

        # 5. ML Insights bundle
        ml_insights = {
            "is_anomaly": len(anomalies) > 0 or bool(ssrf_flag),
            "anomaly_details": ", ".join(anomalies + ([ssrf_flag] if ssrf_flag else [])),
            "phishing_prediction": phishing_result
        }

        # 6. Compute Risk Assessment
        risk_assessment = risk_scorer.calculate_assessment(
            ioc_value=norm_url,
            ioc_type="URL",
            provider_results=provider_results,
            heuristic_flags=heuristic_flags,
            ml_insights=ml_insights
        )

        # 7. AI Executive Summary
        summary_text = ai_engine.generate_natural_language_summary(
            ioc_value=norm_url,
            ioc_type="URL",
            risk_score=risk_assessment.risk_score,
            risk_category=risk_assessment.risk_category,
            confidence_score=risk_assessment.confidence_score,
            classification=risk_assessment.threat_classification,
            explanations=[e.model_dump() for e in risk_assessment.explanations],
            recommendations=risk_assessment.recommended_actions
        )

        ai_insights_obj = AIAnalysisResult(
            threat_summary=summary_text,
            phishing_prediction=phishing_result,
            anomalies_detected=anomalies
        )

        # 8. Build Evidence-Based Correlation Links
        extracted_links = []
        if host:
            host_type, _ = detect_ioc_type(host)
            extracted_links.append({
                "target_value": host,
                "target_type": host_type if host_type != "UNKNOWN" else "DOMAIN",
                "relationship_type": "HOSTED_ON",
                "evidence": f"URL hostname extraction from {norm_url}",
                "source_provider": "URL Parser",
                "confidence": 1.0,
                "target_risk": risk_assessment.risk_score * 0.9
            })

        # Add destination redirect host if redirected to different domain
        final_url = http_probe.get("final_url")
        if final_url and final_url != norm_url:
            final_host = urlparse(final_url).hostname
            if final_host and final_host != host:
                fhost_type, _ = detect_ioc_type(final_host)
                extracted_links.append({
                    "target_value": final_host,
                    "target_type": fhost_type if fhost_type != "UNKNOWN" else "DOMAIN",
                    "relationship_type": "REDIRECTS_TO_HOST",
                    "evidence": f"HTTP Redirect chain ({redirect_count} hops)",
                    "source_provider": "HTTP Probe",
                    "confidence": 0.95,
                    "target_risk": risk_assessment.risk_score
                })

        graph = correlation_engine.build_correlation_graph(
            center_ioc=norm_url,
            center_type="URL",
            center_risk=risk_assessment.risk_score,
            center_category=risk_assessment.risk_category,
            db=db,
            extracted_links=extracted_links
        )

        # 9. Persist to DB if session exists
        investigation_id = None
        if db:
            record = db.query(IOCRecord).filter(IOCRecord.normalized_value == norm_url).first()
            if not record:
                record = IOCRecord(
                    indicator_value=url_str,
                    normalized_value=norm_url,
                    indicator_type="URL",
                    defanged_value=defang_ioc(norm_url, "URL"),
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
            "parsed_components": {
                "scheme": parsed.scheme,
                "host": host,
                "port": parsed.port,
                "path": parsed.path,
                "query": parsed.query
            },
            "phishing_evaluation": phishing_result,
            "http_probe": http_probe
        }

        return FullIOCAnalysisResponse(
            indicator=url_str,
            normalized=norm_url,
            defanged=defang_ioc(norm_url, "URL"),
            indicator_type="URL",
            timestamp=datetime.utcnow(),
            risk_assessment=risk_assessment,
            ai_insights=ai_insights_obj,
            provider_results=provider_results,
            module_details=module_details,
            correlation_graph=graph,
            investigation_id=investigation_id
        )


url_engine = URLIntelligenceEngine()
