"""Threat Reports Generator Test Suite."""

import os
import json
import pytest
from app.reports.pdf_generator import pdf_generator
from app.reports.json_generator import json_generator, csv_generator


@pytest.fixture
def sample_analysis_payload():
    return [{
        "indicator": "194.26.29.112",
        "normalized": "194.26.29.112",
        "defanged": "194[.]26[.]29[.]112",
        "indicator_type": "IP",
        "timestamp": "2026-11-08T00:00:00Z",
        "risk_assessment": {
            "risk_score": 95.0,
            "risk_category": "CRITICAL",
            "confidence_score": 90.0,
            "threat_classification": "COMMAND_AND_CONTROL",
            "explanations": [
                {
                    "factor": "Bulletproof C2",
                    "points_impact": 50.0,
                    "evidence": "Known bulletproof hosting associated with Cobalt Strike",
                    "source": "Local Threat KnowledgeBase"
                }
            ],
            "recommended_actions": [
                "Block IP at perimeter firewalls",
                "Isolate internal communicating endpoints"
            ]
        },
        "provider_results": [
            {
                "provider_name": "Local Threat KnowledgeBase",
                "status": "SUCCESS",
                "is_malicious": True,
                "reputation_score": 95.0,
                "detection_count": 1
            }
        ]
    }]


def test_pdf_report_generation(sample_analysis_payload):
    pdf_path = pdf_generator.generate(sample_analysis_payload, title="Automated Unit Test Threat Report")
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000  # ReportLab PDF created with content


def test_json_report_generation(sample_analysis_payload):
    json_path = json_generator.generate(sample_analysis_payload, title="Automated Unit Test Threat Report")
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "metadata" in data
    assert "indicators" in data
    assert len(data["indicators"]) == 1


def test_csv_report_generation(sample_analysis_payload):
    csv_path = csv_generator.generate(sample_analysis_payload)
    assert os.path.exists(csv_path)
    with open(csv_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) >= 2  # Header + row
    assert "194.26.29.112" in lines[1]
    assert "CRITICAL" in lines[1]
