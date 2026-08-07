"""Threat Intelligence Engines Test Suite."""

import pytest
from app.engines.ip_engine import ip_engine
from app.engines.domain_engine import domain_engine
from app.engines.url_engine import url_engine
from app.engines.hash_engine import hash_engine


def test_ip_engine_local_analysis(db_session):
    # Analyze known C2 bulletproof host from local database
    res = ip_engine.analyze("194.26.29.112", db=db_session, use_cache=False)
    
    assert res.indicator_type == "IP"
    assert res.normalized == "194.26.29.112"
    assert res.risk_assessment.risk_score >= 80.0
    assert res.risk_assessment.risk_category in ("HIGH", "CRITICAL")
    assert res.investigation_id is not None
    assert len(res.provider_results) > 0


def test_domain_engine_local_analysis(db_session):
    # Analyze known malicious domain
    res = domain_engine.analyze("malicious-payload-cdn.net", db=db_session, use_cache=False)
    
    assert res.indicator_type == "DOMAIN"
    assert res.risk_assessment.risk_score >= 70.0
    assert "AgentTesla" in str(res.provider_results)
    assert res.correlation_graph is not None


def test_url_engine_ssrf_blocking(db_session):
    # Attempting to analyze an internal AWS metadata IP URL
    res = url_engine.analyze("http://169.254.169.254/latest/meta-data/", db=db_session, use_cache=False)
    
    # SSRF protection must trigger and flag the risk
    assert res.module_details["http_probe"].get("ssrf_blocked") is True
    assert res.risk_assessment.risk_score >= 30.0


def test_hash_engine_wannacry_analysis(db_session):
    # Analyze known WannaCry hash
    res = hash_engine.analyze("ed018450a7d5fa75599e744db607d61e", db=db_session, use_cache=False)
    
    assert res.indicator_type == "HASH"
    assert res.risk_assessment.risk_score >= 95.0
    assert res.risk_assessment.risk_category == "CRITICAL"
    assert "WannaCry" in res.risk_assessment.threat_classification or any("WannaCry" in n.label for n in res.correlation_graph.nodes)
