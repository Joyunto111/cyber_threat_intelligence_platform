"""Plotly Data Visualizations and Cyber Risk Gauges."""

import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, Any, List


def render_risk_gauge(score: float, category: str) -> go.Figure:
    """Renders a cybersecurity risk gauge (0-100) with color thresholds."""
    bar_color = "#10b981"
    if category == "CRITICAL":
        bar_color = "#ef4444"
    elif category == "HIGH":
        bar_color = "#f97316"
    elif category == "MEDIUM":
        bar_color = "#eab308"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Threat Risk Score ({category})", 'font': {'size': 16, 'color': '#f9fafb'}},
        number={'suffix': "/100", 'font': {'size': 32, 'color': bar_color, 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#4b5563"},
            'bar': {'color': bar_color, 'thickness': 0.28},
            'bgcolor': "#111827",
            'borderwidth': 1,
            'bordercolor': "#374151",
            'steps': [
                {'range': [0, 29], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [29, 69], 'color': 'rgba(234, 179, 8, 0.15)'},
                {'range': [69, 89], 'color': 'rgba(249, 115, 22, 0.15)'},
                {'range': [89, 100], 'color': 'rgba(239, 68, 68, 0.15)'}
            ],
            'threshold': {
                'line': {'color': "#ffffff", 'width': 3},
                'thickness': 0.8,
                'value': score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=220,
        margin=dict(l=20, r=20, t=40, b=10),
        font={'color': '#e5e7eb'}
    )
    return fig


def render_ioc_distribution_donut(distribution: Dict[str, int]) -> go.Figure:
    """Renders a donut chart of IOC type breakdown."""
    labels = list(distribution.keys())
    values = list(distribution.values())

    if not values or sum(values) == 0:
        labels = ["No Data"]
        values = [1]

    colors = ["#38bdf8", "#818cf8", "#c084fc", "#f472b6"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color='#111827', width=2)),
        textinfo='label+percent',
        hoverinfo='label+value'
    )])

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=True,
        legend=dict(font=dict(color='#9ca3af')),
        font=dict(color='#e5e7eb')
    )
    return fig


def render_severity_bar_chart(malicious: int, suspicious: int, low_unknown: int) -> go.Figure:
    """Renders a threat classification horizontal bar chart."""
    categories = ["Critical / High Risk", "Suspicious (Medium)", "Low Risk / Clean"]
    counts = [malicious, suspicious, low_unknown]
    colors = ["#ef4444", "#eab308", "#10b981"]

    fig = go.Figure(go.Bar(
        x=counts,
        y=categories,
        orientation='h',
        marker=dict(color=colors, line=dict(color='#1f2937', width=1)),
        text=counts,
        textposition='auto',
        textfont=dict(color='#ffffff', family='JetBrains Mono')
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=200,
        margin=dict(l=10, r=20, t=10, b=10),
        xaxis=dict(showgrid=True, gridcolor='#1f2937', color='#9ca3af'),
        yaxis=dict(color='#f3f4f6'),
        font=dict(color='#e5e7eb')
    )
    return fig
