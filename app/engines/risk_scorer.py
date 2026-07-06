"""Explainable Threat Risk and Confidence Scoring Engine.

Computes a deterministic, evidence-based Threat Risk Score (0-100) and
a separate Confidence Score (0-100). Provides explainable point breakdowns
and actionable defensive recommendations based on configurable weights.
"""

from typing import List, Dict, Any, Tuple
from app.models.schemas import RiskAssessment, ScoreExplanation, ProviderResult
from app.config import settings


class RiskScoringEngine:
    """Calculates explainable risk scores and confidence metrics."""

    def __init__(self):
        pass

    def calculate_assessment(
        self,
        ioc_value: str,
        ioc_type: str,
        provider_results: List[ProviderResult],
        heuristic_flags: List[Dict[str, Any]],
        ml_insights: Dict[str, Any]
    ) -> RiskAssessment:
        """Computes risk score, confidence score, category, explanations, and defense actions."""
        weights = settings.get_scoring_weights()
        explanations: List[ScoreExplanation] = []
        recommended_actions: List[str] = []

        # 1. Reputation Component (from configured providers)
        reputation_points = 0.0
        reputation_contributions = 0
        
        for prov in provider_results:
            if prov.status == "SUCCESS" and prov.reputation_score is not None:
                reputation_contributions += 1
                score_val = prov.reputation_score
                if prov.is_malicious:
                    pts = min(100.0, score_val)
                    reputation_points = max(reputation_points, pts)
                    explanations.append(ScoreExplanation(
                        factor=f"Provider Detection ({prov.provider_name})",
                        points_impact=round(pts * weights["reputation"], 1),
                        evidence=f"Flagged as malicious with score {score_val}/100 ({prov.detection_count} detections).",
                        source=prov.provider_name
                    ))
                elif score_val > 0:
                    pts = score_val
                    reputation_points = max(reputation_points, pts)
                    explanations.append(ScoreExplanation(
                        factor=f"Suspicious Indicators ({prov.provider_name})",
                        points_impact=round(pts * weights["reputation"], 1),
                        evidence=f"Low-level suspicious activity observed (score {score_val}).",
                        source=prov.provider_name
                    ))

        # 2. Heuristic Analysis Component
        heuristic_points = 0.0
        for h in heuristic_flags:
            h_weight = h.get("points", 15.0)
            heuristic_points += h_weight
            explanations.append(ScoreExplanation(
                factor=h.get("name", "Heuristic Signal"),
                points_impact=round(h_weight * weights["heuristics"], 1),
                evidence=h.get("reason", "Suspicious structural or lexical pattern detected."),
                source="Heuristic Inspection Engine"
            ))
        heuristic_points = min(100.0, heuristic_points)

        # 3. Community Intelligence Component (e.g. AlienVault Pulses, AbuseIPDB reports)
        community_points = 0.0
        for prov in provider_results:
            if prov.provider_name in ("AlienVault OTX", "AbuseIPDB") and prov.status == "SUCCESS":
                if prov.detection_count > 0:
                    pts = min(100.0, prov.detection_count * 12.0)
                    community_points = max(community_points, pts)
                    explanations.append(ScoreExplanation(
                        factor=f"Community Threat Corroboration ({prov.provider_name})",
                        points_impact=round(pts * weights["community"], 1),
                        evidence=f"Referenced in {prov.detection_count} independent reports or threat pulses.",
                        source=prov.provider_name
                    ))

        # 4. AI/ML Prediction Component
        ai_points = 0.0
        if ml_insights.get("is_anomaly", False):
            ai_points += 40.0
            explanations.append(ScoreExplanation(
                factor="AI/ML Anomaly Detection",
                points_impact=round(40.0 * weights["ai_ml"], 1),
                evidence=f"Machine learning anomaly flagged: {ml_insights.get('anomaly_details', 'Unusual patterns')}.",
                source="Machine Learning Model (Heuristic Indicator)"
            ))

        dga = ml_insights.get("dga_prediction", {})
        if dga.get("is_dga", False):
            dga_conf = dga.get("confidence", 0.7) * 60.0
            ai_points += dga_conf
            explanations.append(ScoreExplanation(
                factor="DGA Domain Classifier",
                points_impact=round(dga_conf * weights["ai_ml"], 1),
                evidence=f"Domain Generation Algorithm model predicted synthetic generation (Confidence {dga.get('confidence', 0)*100:.1f}%).",
                source="AI Classifier (Heuristic Indicator)"
            ))

        phish = ml_insights.get("phishing_prediction", {})
        if phish.get("is_phishing", False):
            phish_conf = phish.get("confidence", 0.7) * 60.0
            ai_points += phish_conf
            explanations.append(ScoreExplanation(
                factor="Phishing URL Classifier",
                points_impact=round(phish_conf * weights["ai_ml"], 1),
                evidence=f"Lexical URL classifier predicted phishing structure (Confidence {phish.get('confidence', 0)*100:.1f}%).",
                source="AI Classifier (Heuristic Indicator)"
            ))
        ai_points = min(100.0, ai_points)

        # Compute Final Weighted Risk Score
        raw_weighted_risk = (
            (reputation_points * weights["reputation"]) +
            (heuristic_points * weights["heuristics"]) +
            (community_points * weights["community"]) +
            (ai_points * weights["ai_ml"])
        )
        
        # If any verified provider confirms critical malware/C2, score reflects severity
        for prov in provider_results:
            if prov.is_malicious and prov.status == "SUCCESS" and prov.reputation_score:
                if prov.reputation_score >= 95:
                    raw_weighted_risk = max(raw_weighted_risk, prov.reputation_score)
                elif prov.reputation_score >= 80:
                    raw_weighted_risk = max(raw_weighted_risk, 85.0)

        # Elevate risk floor if direct SSRF / restricted internal network targeted
        if any("SSRF" in h.get("name", "") for h in heuristic_flags):
            raw_weighted_risk = max(raw_weighted_risk, 45.0)

        risk_score = round(min(100.0, max(0.0, raw_weighted_risk)), 1)

        # Categorization: Low (0-29), Medium (30-69), High (70-89), Critical (90-100)
        if risk_score >= 90.0:
            category = "CRITICAL"
        elif risk_score >= 70.0:
            category = "HIGH"
        elif risk_score >= 30.0:
            category = "MEDIUM"
        else:
            category = "LOW"

        # Calculate Separate Confidence Score (0-100)
        # Based on: coverage of active sources, data completeness, corroborating evidence
        confidence = self._compute_confidence_score(provider_results, heuristic_flags, ml_insights)

        # Determine Threat Classification
        classification = self._determine_classification(risk_score, provider_results, heuristic_flags, ml_insights)

        # Generate Actionable Recommendations
        recommended_actions = self._generate_recommendations(ioc_type, category, classification)

        return RiskAssessment(
            risk_score=risk_score,
            risk_category=category,
            confidence_score=confidence,
            threat_classification=classification,
            explanations=explanations,
            recommended_actions=recommended_actions,
            weights_used=weights
        )

    def _compute_confidence_score(
        self,
        provider_results: List[ProviderResult],
        heuristic_flags: List[Dict[str, Any]],
        ml_insights: Dict[str, Any]
    ) -> float:
        """Computes confidence score based on source availability and corroboration.

        A missing API is never treated as proof of safety.
        """
        active_providers = [p for p in provider_results if p.status == "SUCCESS"]
        if not active_providers and not heuristic_flags:
            return 20.0  # Inconclusive / low confidence

        confidence_base = 35.0
        
        # Additional confidence per successful provider
        for p in active_providers:
            confidence_base += (p.source_reliability * 15.0)

        # Corroboration bonus: if 2+ providers agree on malicious or benign status
        malicious_agreements = sum(1 for p in active_providers if p.is_malicious is True)
        if malicious_agreements >= 2:
            confidence_base += 20.0

        if heuristic_flags:
            confidence_base += 10.0

        return round(min(100.0, max(15.0, confidence_base)), 1)

    def _determine_classification(
        self,
        risk_score: float,
        provider_results: List[ProviderResult],
        heuristic_flags: List[Dict[str, Any]],
        ml_insights: Dict[str, Any]
    ) -> str:
        """Assigns meaningful threat classification tag."""
        if risk_score < 30.0:
            return "BENIGN / LOW_RISK"

        # Check provider summaries for specific keywords
        for p in provider_results:
            if p.status == "SUCCESS" and p.summary:
                summary_str = str(p.summary).lower()
                if "ransomware" in summary_str:
                    return "RANSOMWARE"
                if "c2" in summary_str or "command and control" in summary_str:
                    return "COMMAND_AND_CONTROL"
                if "trojan" in summary_str or "emotet" in summary_str:
                    return "TROJAN_LOADER"
                if "phish" in summary_str:
                    return "PHISHING"
                if "tor" in summary_str:
                    return "ANONYMIZATION_PROXY"

        if ml_insights.get("phishing_prediction", {}).get("is_phishing"):
            return "SUSPECTED_PHISHING"
        if ml_insights.get("dga_prediction", {}).get("is_dga"):
            return "SUSPECTED_DGA_BOTNET"

        if risk_score >= 90.0:
            return "MALICIOUS_THREAT"
        elif risk_score >= 70.0:
            return "SUSPICIOUS_HIGH"
        return "SUSPICIOUS_ACTIVITY"

    def _generate_recommendations(self, ioc_type: str, category: str, classification: str) -> List[str]:
        """Provides specific SOC playbook defensive recommendations."""
        actions: List[str] = []
        
        if category in ("CRITICAL", "HIGH"):
            if ioc_type == "IP":
                actions.append("Block IP immediately at perimeter firewalls and edge Web Application Firewalls (WAF).")
                actions.append("Search internal SIEM/NetFlow logs for outbound sessions connecting to this IP in the last 30 days.")
                actions.append("Isolate any internal endpoint that established bidirectional TCP sessions with this indicator.")
            elif ioc_type == "DOMAIN":
                actions.append("Implement internal DNS sinkholing to redirect lookups for this domain to a safe monitoring sinkhole.")
                actions.append("Blacklist domain across Secure Web Gateways (SWG) and email security gateways.")
                actions.append("Query EDR telemetry for DNS queries resolving this domain.")
            elif ioc_type == "URL":
                actions.append("Submit URL for immediate domain/URL filtering block across corporate proxy and CASB.")
                actions.append("Inspect email inbound logs to identify recipients who received messages containing this link.")
                actions.append("Purge associated phishing emails from user inboxes via automated M365/Google Workspace remediation.")
            elif ioc_type == "HASH":
                actions.append("Deploy hash ban rule across EDR fleet (CrowdStrike, Microsoft Defender, SentinelOne).")
                actions.append("Initiate immediate endpoint containment on any host where this file hash was detected.")
                actions.append("Collect file sample in an isolated sandbox for behavioral memory dump and persistence analysis.")
        elif category == "MEDIUM":
            actions.append("Add indicator to active threat watchlist for automated monitoring.")
            actions.append("Increase logging verbosity for network traffic involving this indicator.")
            actions.append("Review authentication and access logs from involved IP or domain.")
        else:
            actions.append("No immediate containment required. Maintain routine telemetry logging.")
            actions.append("Re-evaluate indicator if associated with newly observed suspicious alerts.")

        return actions


# Global singleton risk scoring engine
risk_scorer = RiskScoringEngine()
