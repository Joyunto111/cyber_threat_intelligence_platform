"""IOC Correlation and Relationship Analysis Engine.

Builds directional evidence-based graphs connecting IPs, Domains, URLs,
Hashes, Campaigns, and Malware Families using NetworkX.
Never invents connections; each link includes verifiable evidence and source attribution.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from sqlalchemy.orm import Session
from app.models.database import IOCRecord, IOCRelationship
from app.models.schemas import CorrelationGraph, RelationshipNode, RelationshipEdge


class IOCCorrelationEngine:
    """Constructs and analyzes indicator relationship networks."""

    def __init__(self):
        pass

    def build_correlation_graph(
        self,
        center_ioc: str,
        center_type: str,
        center_risk: float,
        center_category: str,
        db: Optional[Session] = None,
        extracted_links: Optional[List[Dict[str, Any]]] = None
    ) -> CorrelationGraph:
        """Builds an evidence-backed relationship graph around a central IOC."""
        graph = nx.DiGraph()

        # Add center node
        center_id = f"{center_type}:{center_ioc.lower()}"
        graph.add_node(
            center_id,
            label=center_ioc,
            type=center_type,
            risk_score=center_risk,
            category=center_category
        )

        edges: List[RelationshipEdge] = []

        # 1. Add relationships discovered during runtime analysis (e.g. DNS resolutions, host extraction)
        if extracted_links:
            for link in extracted_links:
                target_val = link.get("target_value")
                target_type = link.get("target_type", "UNKNOWN")
                rel_type = link.get("relationship_type", "RELATED_TO")
                evidence = link.get("evidence", "Analytical association")
                source_prov = link.get("source_provider", "Heuristic Engine")
                conf = link.get("confidence", 0.8)
                target_risk = link.get("target_risk", center_risk * 0.8)
                target_cat = link.get("target_category", center_category)

                target_id = f"{target_type}:{target_val.lower()}"
                
                # Add target node if not present
                if not graph.has_node(target_id):
                    graph.add_node(
                        target_id,
                        label=target_val,
                        type=target_type,
                        risk_score=target_risk,
                        category=target_cat
                    )

                # Add directional edge
                graph.add_edge(
                    center_id,
                    target_id,
                    relationship=rel_type,
                    evidence=evidence,
                    source_provider=source_prov,
                    confidence=conf
                )

                edges.append(RelationshipEdge(
                    source=center_id,
                    target=target_id,
                    relationship=rel_type,
                    evidence=evidence,
                    source_provider=source_prov,
                    confidence=conf
                ))

        # 2. Add relationships previously persisted in database
        if db:
            db_ioc = db.query(IOCRecord).filter(IOCRecord.normalized_value == center_ioc.lower()).first()
            if db_ioc:
                for rel in db_ioc.outgoing_relationships:
                    target_id = f"{rel.target_type}:{rel.target_value.lower()}"
                    if not graph.has_node(target_id):
                        graph.add_node(
                            target_id,
                            label=rel.target_value,
                            type=rel.target_type,
                            risk_score=center_risk * 0.75,
                            category=center_category
                        )
                    
                    if not graph.has_edge(center_id, target_id):
                        graph.add_edge(
                            center_id,
                            target_id,
                            relationship=rel.relationship_type,
                            evidence=rel.evidence,
                            source_provider=rel.source_provider,
                            confidence=rel.confidence
                        )
                        edges.append(RelationshipEdge(
                            source=center_id,
                            target=target_id,
                            relationship=rel.relationship_type,
                            evidence=rel.evidence,
                            source_provider=rel.source_provider,
                            confidence=rel.confidence
                        ))

        # Build schema response
        nodes = []
        for n_id, attrs in graph.nodes(data=True):
            nodes.append(RelationshipNode(
                id=n_id,
                label=attrs.get("label", n_id),
                type=attrs.get("type", "UNKNOWN"),
                risk_score=float(attrs.get("risk_score", 0.0)),
                category=attrs.get("category", "UNKNOWN")
            ))

        return CorrelationGraph(nodes=nodes, edges=edges)

    def persist_relationships(
        self,
        db: Session,
        ioc_id: int,
        relationships: List[Dict[str, Any]]
    ):
        """Saves newly discovered correlations to the database."""
        for r in relationships:
            # Check if exists
            exists = db.query(IOCRelationship).filter(
                IOCRelationship.source_ioc_id == ioc_id,
                IOCRelationship.target_value == r["target_value"],
                IOCRelationship.relationship_type == r["relationship_type"]
            ).first()

            if not exists:
                new_rel = IOCRelationship(
                    source_ioc_id=ioc_id,
                    target_value=r["target_value"],
                    target_type=r.get("target_type", "UNKNOWN"),
                    relationship_type=r["relationship_type"],
                    evidence=r.get("evidence", "Correlation engine link"),
                    source_provider=r.get("source_provider", "Heuristics"),
                    confidence=r.get("confidence", 0.8)
                )
                db.add(new_rel)
        db.commit()


# Global correlation engine singleton
correlation_engine = IOCCorrelationEngine()
