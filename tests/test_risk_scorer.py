"""Risk Scoring Engine Test Suite."""

import pytest
from app.engines.risk_scorer import risk_scorer
from app.models.schemas import ProviderResult


def test_risk_scoring_critical_malware():
    # Simulated provider with verified high detection
    vt_res = ProviderResult(
        provider_name="VirusTotal",
        status="SUCCESS",
        is_malicious=True,
        reputation_score=95.0,
        detection_count=45,
        total_engines=70,
        source_reliability=0.95,
        summary={"malware_family": "LockBit"}
    )
    
    heuristics = [{
        "name": "Ransomware Signature",
        "points": 50.0,
        "reason": "Known ransomware binary"
    }]

    ml_insights = {"is_anomaly": True, "anomaly_details": "Known ransomware sample"}

    assessment = risk_scorer.calculate_assessment(
        ioc_value="51144f172f611ecb104c264368f44135",
        ioc_type="HASH",
        provider_results=[vt_res],
        heuristic_flags=heuristics,
        ml_insights=ml_insights
    )

    assert assessment.risk_score >= 85.0
    assert assessment.risk_category in ("CRITICAL", "HIGH")
    assert assessment.confidence_score >= 50.0
    assert len(assessment.explanations) > 0
    assert len(assessment.recommended_actions) > 0
    assert any("EDR" in act or "containment" in act.lower() for act in assessment.recommended_actions)


def test_risk_scoring_benign():
    vt_res = ProviderResult(
        provider_name="VirusTotal",
        status="SUCCESS",
        is_malicious=False,
        reputation_score=0.0,
        detection_count=0,
        total_engines=70,
        source_reliability=0.95
    )

    assessment = risk_scorer.calculate_assessment(
        ioc_value="8.8.8.8",
        ioc_type="IP",
        provider_results=[vt_res],
        heuristic_flags=[],
        ml_insights={}
    )

    assert assessment.risk_score < 30.0
    assert assessment.risk_category == "LOW"


def test_confidence_remains_separate_from_risk():
    # If no providers respond, risk may be 0 but confidence should reflect low data availability
    unavail_res = ProviderResult(
        provider_name="VirusTotal",
        status="NOT_CONFIGURED",
        coverage_available=True
    )

    assessment = risk_scorer.calculate_assessment(
        ioc_value="example.com",
        ioc_type="DOMAIN",
        provider_results=[unavail_res],
        heuristic_flags=[],
        ml_insights={}
    )

    # Missing API result must NEVER be treated as proof of safety
    assert assessment.confidence_score <= 35.0
