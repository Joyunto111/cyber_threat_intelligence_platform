"""Interactive IOC Correlation Network Graph Visualizer using NetworkX and Plotly."""

import networkx as nx
import plotly.graph_objects as go
from typing import Dict, Any, List


def render_correlation_network_graph(graph_data: Dict[str, Any]) -> go.Figure:
    """Converts CorrelationGraph schema data into an interactive Plotly 2D graph."""
    nodes_raw = graph_data.get("nodes", [])
    edges_raw = graph_data.get("edges", [])

    if not nodes_raw:
        fig = go.Figure()
        fig.add_annotation(text="No relationship nodes available", showarrow=False, font=dict(color="#9ca3af"))
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        return fig

    # Build NetworkX graph
    G = nx.DiGraph()
    for n in nodes_raw:
        n_id = n.get("id") if isinstance(n, dict) else n.id
        n_label = n.get("label") if isinstance(n, dict) else n.label
        n_type = n.get("type") if isinstance(n, dict) else n.type
        n_risk = n.get("risk_score", 0.0) if isinstance(n, dict) else n.risk_score
        n_cat = n.get("category", "UNKNOWN") if isinstance(n, dict) else n.category

        G.add_node(n_id, label=n_label, type=n_type, risk=n_risk, category=n_cat)

    for e in edges_raw:
        src = e.get("source") if isinstance(e, dict) else e.source
        tgt = e.get("target") if isinstance(e, dict) else e.target
        rel = e.get("relationship") if isinstance(e, dict) else e.relationship
        evi = e.get("evidence") if isinstance(e, dict) else e.evidence
        prov = e.get("source_provider") if isinstance(e, dict) else e.source_provider

        G.add_edge(src, tgt, relationship=rel, evidence=evi, provider=prov)

    # Compute Layout
    pos = nx.spring_layout(G, k=0.9, iterations=50, seed=42)

    # Prepare Edges Scatter
    edge_x = []
    edge_y = []
    edge_hover_x = []
    edge_hover_y = []
    edge_hover_text = []

    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
        # Midpoint for edge text / tooltip
        mid_x = (x0 + x1) / 2
        mid_y = (y0 + y1) / 2
        edge_hover_x.append(mid_x)
        edge_hover_y.append(mid_y)
        edge_hover_text.append(f"Relationship: <b>{edge[2].get('relationship')}</b><br>Evidence: {edge[2].get('evidence')}<br>Source: {edge[2].get('provider')}")

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#475569'),
        hoverinfo='none',
        mode='lines'
    )

    edge_hover_trace = go.Scatter(
        x=edge_hover_x, y=edge_hover_y,
        mode='markers',
        hoverinfo='text',
        hovertext=edge_hover_text,
        marker=dict(size=8, color='#0284c7', opacity=0.7)
    )

    # Prepare Nodes Scatter
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        attrs = G.nodes[node]
        risk = attrs.get("risk", 0.0)
        cat = attrs.get("category", "UNKNOWN")
        ntype = attrs.get("type", "UNKNOWN")
        label = attrs.get("label", node)

        # Color mapping by risk
        if cat == "CRITICAL" or risk >= 90:
            color = "#ef4444"
        elif cat == "HIGH" or risk >= 70:
            color = "#f97316"
        elif cat == "MEDIUM" or risk >= 30:
            color = "#eab308"
        else:
            color = "#10b981"

        node_color.append(color)
        node_size.append(26 if ntype in ("IP", "DOMAIN", "HASH", "URL") else 32)

        tooltip = (
            f"<b>{label}</b><br>"
            f"Type: {ntype}<br>"
            f"Risk Score: <b>{risk:.1f}/100</b> ({cat})<br>"
            f"Connections: {G.degree(node)}"
        )
        node_text.append(tooltip)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        hovertext=node_text,
        text=[G.nodes[n].get("label", n)[:18] for n in G.nodes()],
        textposition="top center",
        textfont=dict(color='#cbd5e1', size=10, family='JetBrains Mono'),
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=2, color='#ffffff')
        )
    )

    fig = go.Figure(data=[edge_trace, edge_hover_trace, node_trace])
    fig.update_layout(
        title=dict(text="IOC Correlation & Attribution Network", font=dict(color='#f3f4f6', size=16)),
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=10, r=10, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=520
    )
    return fig
