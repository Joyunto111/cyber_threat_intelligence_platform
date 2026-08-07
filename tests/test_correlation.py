"""IOC Correlation Engine Test Suite."""

import pytest
from app.engines.correlation import correlation_engine


def test_correlation_graph_construction(db_session):
    extracted_links = [
        {
            "target_value": "1.2.3.4",
            "target_type": "IP",
            "relationship_type": "RESOLVES_TO",
            "evidence": "DNS A Record query",
            "source_provider": "DNS Resolver",
            "confidence": 0.95
        },
        {
            "target_value": "Operation DarkStorm",
            "target_type": "CAMPAIGN",
            "relationship_type": "ATTRIBUTED_TO",
            "evidence": "Adversary infrastructure overlap",
            "source_provider": "AlienVault OTX",
            "confidence": 0.90
        }
    ]

    graph = correlation_engine.build_correlation_graph(
        center_ioc="test-threat.com",
        center_type="DOMAIN",
        center_risk=85.0,
        center_category="HIGH",
        db=db_session,
        extracted_links=extracted_links
    )

    assert len(graph.nodes) >= 3
    assert len(graph.edges) >= 2
    
    # Check node attributes
    node_labels = [n.label for n in graph.nodes]
    assert "test-threat.com" in node_labels
    assert "1.2.3.4" in node_labels
    assert "Operation DarkStorm" in node_labels

    # Check edge attributes
    edge = graph.edges[0]
    assert edge.evidence != ""
    assert edge.source_provider != ""
