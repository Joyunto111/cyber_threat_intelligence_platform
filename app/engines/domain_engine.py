"""Domain Intelligence Engine.

Performs domain normalization, DNS record resolution (A, AAAA, MX, NS, TXT, CNAME),
WHOIS/RDAP lookups, DGA detection, typosquatting checks, and provider queries.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.validator import validate_and_normalize_domain, defang_ioc
from app.providers import provider_manager
from app.providers.local_intel import query_dns_records, query_rdap_whois
from app.engines.risk_scorer import risk_scorer
from app.engines.ai_engine import ai_engine
from app.engines.correlation import correlation_engine
from app.models.database import IOCRecord, AnalysisResult
from app.models.schemas import FullIOCAnalysisResponse, AIAnalysisResult


class DomainIntelligenceEngine:
    """Specialized engine for domain threat investigation."""

    def analyze(self, domain_str: str, db: Optional[Session] = None, use_cache: bool = True) -> FullIOCAnalysisResponse:
        is_valid, norm_domain = validate_and_normalize_domain(domain_str)
        if not is_valid or not norm_domain:
            raise ValueError(f"Invalid domain format: {domain_str}")

        # 1. DNS Records Resolution
        dns_records = query_dns_records(norm_domain)

        # 2. RDAP / WHOIS Lookup
        rdap_info = query_rdap_whois(norm_domain)

        # 3. AI / ML Evaluations: DGA detection and Anomaly checks
        dga_result = ai_engine.evaluate_dga_domain(norm_domain)
        anomalies = ai_engine.detect_anomalies(norm_domain, "DOMAIN")

        # 4. Query all Threat Providers
        provider_results = provider_manager.query_all(norm_domain, "DOMAIN", use_cache=use_cache)

        # 5. Formulate Heuristic Flags
        heuristic_flags = []
        if dga_result.get("is_dga"):
            heuristic_flags.append({
                "name": "Synthetic DGA Domain Pattern",
                "points": 35.0,
                "reason": f"DGA lexical signals: {', '.join(dga_result.get('signals', []))}"
            })

        for anomaly in anomalies:
            heuristic_flags.append({
                "name": "Domain Anomaly",
                "points": 25.0,
                "reason": anomaly
            })

        # Check if domain has zero DNS records (potential dead C2 or unregistered staging domain)
        has_any_dns = any(len(records) > 0 for records in dns_records.values())
        if not has_any_dns:
            heuristic_flags.append({
                "name": "Unresolvable Domain (NXDOMAIN/No Records)",
                "points": 10.0,
                "reason": "Domain currently has no active DNS A, AAAA, MX, or NS records."
            })

        # 6. ML Insights bundle
        ml_insights = {
            "is_anomaly": len(anomalies) > 0,
            "anomaly_details": ", ".join(anomalies),
            "dga_prediction": dga_result
        }

        # 7. Compute Risk Assessment
        risk_assessment = risk_scorer.calculate_assessment(
            ioc_value=norm_domain,
            ioc_type="DOMAIN",
            provider_results=provider_results,
            heuristic_flags=heuristic_flags,
            ml_insights=ml_insights
        )

        # 8. AI Executive Summary
        summary_text = ai_engine.generate_natural_language_summary(
            ioc_value=norm_domain,
            ioc_type="DOMAIN",
            risk_score=risk_assessment.risk_score,
            risk_category=risk_assessment.risk_category,
            confidence_score=risk_assessment.confidence_score,
            classification=risk_assessment.threat_classification,
            explanations=[e.model_dump() for e in risk_assessment.explanations],
            recommendations=risk_assessment.recommended_actions
        )

        ai_insights_obj = AIAnalysisResult(
            threat_summary=summary_text,
            dga_prediction=dga_result,
            anomalies_detected=anomalies
        )

        # 9. Build Evidence-Based Correlation Links
        extracted_links = []
        # Link A & AAAA resolved IPs
        for ip_addr in dns_records.get("A", []) + dns_records.get("AAAA", []):
            extracted_links.append({
                "target_value": ip_addr,
                "target_type": "IP",
                "relationship_type": "RESOLVES_TO_IP",
                "evidence": f"DNS A/AAAA resolution from {norm_domain}",
                "source_provider": "DNS Resolver",
                "confidence": 0.95,
                "target_risk": risk_assessment.risk_score * 0.85
            })

        # Link Mail Servers (MX)
        for mx in dns_records.get("MX", []):
            clean_mx = mx.split()[-1].rstrip(".")
            extracted_links.append({
                "target_value": clean_mx,
                "target_type": "DOMAIN",
                "relationship_type": "MAIL_SERVER",
                "evidence": f"DNS MX record for {norm_domain}",
                "source_provider": "DNS Resolver",
                "confidence": 0.90,
                "target_risk": 10.0
            })

        # Link Name Servers (NS)
        for ns in dns_records.get("NS", []):
            clean_ns = ns.rstrip(".")
            extracted_links.append({
                "target_value": clean_ns,
                "target_type": "DOMAIN",
                "relationship_type": "AUTHORITATIVE_NAMESERVER",
                "evidence": f"DNS NS delegation for {norm_domain}",
                "source_provider": "DNS Resolver",
                "confidence": 0.90,
                "target_risk": 10.0
            })

        graph = correlation_engine.build_correlation_graph(
            center_ioc=norm_domain,
            center_type="DOMAIN",
            center_risk=risk_assessment.risk_score,
            center_category=risk_assessment.risk_category,
            db=db,
            extracted_links=extracted_links
        )

        # 10. Persist to DB if session exists
        investigation_id = None
        if db:
            record = db.query(IOCRecord).filter(IOCRecord.normalized_value == norm_domain).first()
            if not record:
                record = IOCRecord(
                    indicator_value=domain_str,
                    normalized_value=norm_domain,
                    indicator_type="DOMAIN",
                    defanged_value=defang_ioc(norm_domain, "DOMAIN"),
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
            "dns_records": dns_records,
            "rdap_info": rdap_info,
            "dga_evaluation": dga_result,
            "anomalies": anomalies
        }

        return FullIOCAnalysisResponse(
            indicator=domain_str,
            normalized=norm_domain,
            defanged=defang_ioc(norm_domain, "DOMAIN"),
            indicator_type="DOMAIN",
            timestamp=datetime.utcnow(),
            risk_assessment=risk_assessment,
            ai_insights=ai_insights_obj,
            provider_results=provider_results,
            module_details=module_details,
            correlation_graph=graph,
            investigation_id=investigation_id
        )


domain_engine = DomainIntelligenceEngine()
