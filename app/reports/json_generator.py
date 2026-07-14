"""JSON and CSV Threat Report Generators."""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class JSONReportGenerator:
    """Generates structured machine-readable JSON threat reports."""

    def generate(self, analyses: List[Dict[str, Any]], title: str = "Cyber Threat Intelligence Assessment") -> str:
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"CTI_Report_{timestamp_str}.json"
        file_path = REPORTS_DIR / filename

        report_payload = {
            "metadata": {
                "report_title": title,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "generator": "Cyber Threat Intelligence Analysis Platform",
                "indicator_count": len(analyses),
                "disclaimer": (
                    "Threat intelligence data is gathered from official feeds, DNS infrastructure, "
                    "and heuristic models. The absence of an external API detection must never be treated "
                    "as proof that an indicator is benign. Machine learning predictions are heuristic indicators."
                )
            },
            "indicators": analyses
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2, default=str)

        return str(file_path)


class CSVReportGenerator:
    """Generates RFC-4180 compliant CSV threat reports for SIEM and SOC triage."""

    def generate(self, analyses: List[Dict[str, Any]]) -> str:
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"CTI_Report_{timestamp_str}.csv"
        file_path = REPORTS_DIR / filename

        headers = [
            "Indicator", "Normalized", "Defanged", "Type",
            "RiskScore", "RiskCategory", "ConfidenceScore", "ThreatClassification",
            "ProviderDetections", "PrimarySource", "RecommendedActions", "Timestamp"
        ]

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for item in analyses:
                risk = item.get("risk_assessment", {})
                providers = item.get("provider_results", [])
                
                det_count = sum(p.get("detection_count", 0) for p in providers if p.get("status") == "SUCCESS")
                top_sources = [p.get("provider_name") for p in providers if p.get("is_malicious")]
                top_src_str = ", ".join(top_sources) if top_sources else "Local/Heuristics"

                actions = " | ".join(risk.get("recommended_actions", []))

                writer.writerow([
                    item.get("indicator"),
                    item.get("normalized"),
                    item.get("defanged"),
                    item.get("indicator_type"),
                    risk.get("risk_score"),
                    risk.get("risk_category"),
                    risk.get("confidence_score"),
                    risk.get("threat_classification"),
                    det_count,
                    top_src_str,
                    actions,
                    item.get("timestamp") or datetime.utcnow().isoformat()
                ])

        return str(file_path)


json_generator = JSONReportGenerator()
csv_generator = CSVReportGenerator()
