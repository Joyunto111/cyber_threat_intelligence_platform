"""AI and Machine Learning Engine Test Suite."""

import pytest
from app.engines.ai_engine import ai_engine, shannon_entropy, levenshtein_distance


def test_shannon_entropy():
    # Low entropy (repetitive)
    low_ent = shannon_entropy("aaaaaaa")
    assert low_ent == 0.0

    # High entropy (random hex or DGA string)
    high_ent = shannon_entropy("q1w2e3r4t5y6u7i8o9p0")
    assert high_ent > 4.0


def test_dga_domain_detection():
    # Synthetic random DGA domain
    dga_eval = ai_engine.evaluate_dga_domain("xk99vqm7z104bcv.com")
    assert dga_eval["is_dga"] is True
    assert dga_eval["confidence"] >= 0.55

    # Human-readable legitimate domain
    legit_eval = ai_engine.evaluate_dga_domain("google.com")
    assert legit_eval["is_dga"] is False


def test_phishing_url_lexical_analysis():
    # Phishing URL containing credential harvesting markers
    phish_url = "http://192.168.1.10/paypal-security-update/login.php?verify=1"
    res = ai_engine.evaluate_phishing_url(phish_url)
    assert res["is_phishing"] is True
    assert len(res["flags"]) >= 1


def test_brand_typosquatting_detection():
    # Typosquatted brand
    anomalies = ai_engine.detect_anomalies("paypa1.com", "DOMAIN")
    assert any("paypal" in a.lower() for a in anomalies)


def test_natural_language_summary():
    summary = ai_engine.generate_natural_language_summary(
        ioc_value="194.26.29.112",
        ioc_type="IP",
        risk_score=95.0,
        risk_category="CRITICAL",
        confidence_score=92.0,
        classification="COMMAND_AND_CONTROL",
        explanations=[{"factor": "Known C2", "evidence": "Confirmed Cobalt Strike listener", "source": "Local Feeds"}],
        recommendations=["Block IP at perimeter firewalls"]
    )
    assert "CRITICAL" in summary
    assert "95.0" in summary or "95" in summary
    assert "194.26.29.112" in summary
