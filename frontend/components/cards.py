"""Reusable UI Card and Badge Components."""

from typing import Any
import streamlit as st


def render_metric_card(title: str, value: Any, subtitle: str = ""):
    sub_html = f"<div style='font-size:0.75rem; color:#6b7280; margin-top:4px;'>{subtitle}</div>" if subtitle else ""
    html = f"""
    <div class="metric-card">
        <div class="metric-title">{title}</div>
        <div class="metric-value">{value}</div>
        {sub_html}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def get_risk_badge_html(category: str) -> str:
    cat = (category or "UNKNOWN").upper()
    css_class = f"badge-{cat.lower()}"
    return f"<span class='badge {css_class}'>{cat}</span>"


def render_ioc_summary_banner(
    indicator: str,
    defanged: str,
    ioc_type: str,
    risk_score: float,
    risk_category: str,
    confidence_score: float,
    classification: str
):
    badge = get_risk_badge_html(risk_category)
    
    score_color = "#10b981"
    if risk_category == "CRITICAL":
        score_color = "#ef4444"
    elif risk_category == "HIGH":
        score_color = "#f97316"
    elif risk_category == "MEDIUM":
        score_color = "#eab308"

    html = f"""
    <div style="background:#111827; border:1px solid #1f2937; border-radius:10px; padding:20px; margin-bottom:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <div>
                <div style="font-size:0.8rem; color:#9ca3af; text-transform:uppercase; font-weight:600;">{ioc_type} Assessment</div>
                <div style="font-size:1.4rem; font-weight:700; color:#f9fafb; font-family:'JetBrains Mono', monospace; word-break:break-all;">{indicator}</div>
                <div style="font-size:0.85rem; color:#60a5fa; font-family:'JetBrains Mono', monospace; margin-top:2px;">Defanged: {defanged}</div>
            </div>
            <div style="display:flex; gap:18px; align-items:center;">
                <div style="text-align:right;">
                    <div style="font-size:0.75rem; color:#9ca3af; text-transform:uppercase;">Threat Risk</div>
                    <div style="font-size:1.8rem; font-weight:800; color:{score_color}; font-family:'JetBrains Mono', monospace;">
                        {risk_score}<span style="font-size:1rem; color:#6b7280;">/100</span>
                    </div>
                </div>
                <div>{badge}</div>
            </div>
        </div>
        <div style="margin-top:14px; padding-top:12px; border-top:1px solid #1f2937; display:flex; gap:20px; font-size:0.85rem; color:#9ca3af;">
            <div><b>Classification:</b> <span style="color:#f3f4f6;">{classification}</span></div>
            <div><b>Confidence:</b> <span style="color:#38bdf8;">{confidence_score}%</span></div>
            <div><b>Model:</b> <span style="color:#a78bfa;">Explainable Multi-Layered</span></div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_executive_summary(summary_text: str):
    st.markdown(f"""
    <div class="summary-box">
        {summary_text}
    </div>
    """, unsafe_allow_html=True)
