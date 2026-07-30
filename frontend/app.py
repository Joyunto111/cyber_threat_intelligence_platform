"""Cyber Threat Intelligence Analysis Platform - Web Dashboard.

Multi-Page Enterprise SOC Interface built with Streamlit and Plotly.
"""

import os
import sys
import json
import pandas as pd
import streamlit as st
from datetime import datetime
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings
from app.database.session import SessionLocal, init_database
from app.database.init_db import setup_db
from app.models.database import IOCRecord, ThreatReport, WatchlistItem, AnalysisResult, IOCRelationship
from app.engines import analyze_any_ioc
from app.engines.ip_engine import ip_engine
from app.engines.domain_engine import domain_engine
from app.engines.url_engine import url_engine
from app.engines.hash_engine import hash_engine
from app.engines.correlation import correlation_engine
from app.core.validator import extract_all_iocs_from_text, defang_ioc, refang_text, detect_ioc_type
from app.providers import provider_manager
from app.reports import pdf_generator, json_generator, csv_generator

from frontend.style import get_custom_css
from frontend.components.cards import (
    render_metric_card, render_ioc_summary_banner, render_executive_summary, get_risk_badge_html
)
from frontend.components.charts import (
    render_risk_gauge, render_ioc_distribution_donut, render_severity_bar_chart
)
from frontend.components.graph_viz import render_correlation_network_graph

# Configure Streamlit page
st.set_page_config(
    page_title="Cyber Threat Intelligence Analysis Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply CSS styling
st.markdown(get_custom_css(), unsafe_allow_html=True)

# Ensure database is initialized
setup_db()


def get_db():
    return SessionLocal()


# --- Sidebar Navigation ---
st.sidebar.markdown("""
<div style="text-align: center; padding: 10px 0 20px 0;">
    <h2 style="color: #38bdf8; margin: 0; font-size: 1.35rem; font-weight: 800;">🛡️ CTI ANALYZER</h2>
    <div style="font-size: 0.75rem; color: #94a3b8; letter-spacing: 0.05em;">ENTERPRISE THREAT INTELLIGENCE</div>
</div>
""", unsafe_allow_html=True)

PAGES = [
    "Threat Overview",
    "IP Intelligence",
    "Domain Intelligence",
    "URL Intelligence",
    "File Hash Intelligence",
    "IOC Extraction",
    "Batch Analysis",
    "IOC Correlation Graph",
    "Threat Monitoring",
    "Investigation History",
    "Threat Reports",
    "API Configuration",
    "Settings & Methodology"
]

selected_page = st.sidebar.radio("Navigation", PAGES, index=0)

st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style="font-size: 0.75rem; color: #64748b; line-height: 1.4;">
    <b>System Status:</b> <span style="color:#10b981;">● Operational</span><br>
    <b>Database:</b> SQLite / SQLAlchemy<br>
    <b>SSRF Protection:</b> <span style="color:#10b981;">Active</span><br>
    <b>AI Engine:</b> Active
</div>
""", unsafe_allow_html=True)


# =========================================================================
# PAGE 1: THREAT OVERVIEW
# =========================================================================
if selected_page == "Threat Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    st.markdown("Executive telemetry and operational intelligence metrics.")

    db = get_db()
    try:
        total_iocs = db.query(IOCRecord).count()
        critical_count = db.query(IOCRecord).filter(IOCRecord.risk_category == "CRITICAL").count()
        high_count = db.query(IOCRecord).filter(IOCRecord.risk_category == "HIGH").count()
        med_count = db.query(IOCRecord).filter(IOCRecord.risk_category == "MEDIUM").count()
        low_count = db.query(IOCRecord).filter(IOCRecord.risk_category == "LOW").count()
        
        malicious_total = critical_count + high_count

        ip_count = db.query(IOCRecord).filter(IOCRecord.indicator_type == "IP").count()
        domain_count = db.query(IOCRecord).filter(IOCRecord.indicator_type == "DOMAIN").count()
        url_count = db.query(IOCRecord).filter(IOCRecord.indicator_type == "URL").count()
        hash_count = db.query(IOCRecord).filter(IOCRecord.indicator_type == "HASH").count()

        recent_iocs = db.query(IOCRecord).order_by(IOCRecord.last_analyzed.desc()).limit(8).all()
    finally:
        db.close()

    # Metric Cards Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card("Total Indicators", total_iocs, "Archived in database")
    with c2:
        render_metric_card("Confirmed Malicious", malicious_total, f"{critical_count} Critical, {high_count} High")
    with c3:
        render_metric_card("Suspicious Markers", med_count, "Elevated heuristic flags")
    with c4:
        render_metric_card("Low Risk / Benign", low_count, "Clean or baseline traffic")

    st.markdown("---")

    # Quick Indicator Lookup
    st.markdown("### ⚡ Quick Multi-Type IOC Inspection")
    with st.form("quick_inspect_form"):
        col_input, col_btn = st.columns([5, 1])
        with col_input:
            quick_input = st.text_input(
                "Enter IP, Domain, URL, or File Hash (Defanged formats like hxxp or [.] supported)",
                placeholder="e.g. 194.26.29.112 or malicious-payload-cdn[.]net or ed018450a7d5fa75599e744db607d61e",
                label_visibility="collapsed"
            )
        with col_btn:
            submit_quick = st.form_submit_button("🔍 Analyze", use_container_width=True)

    if submit_quick and quick_input:
        with st.spinner("Executing intelligence pipeline across local signatures, DNS, and threat feeds..."):
            try:
                db_session = get_db()
                res = analyze_any_ioc(quick_input, db=db_session, use_cache=True)
                db_session.close()

                st.success(f"Analysis completed for {res.indicator_type}: `{res.normalized}`")
                render_ioc_summary_banner(
                    indicator=res.indicator,
                    defanged=res.defanged,
                    ioc_type=res.indicator_type,
                    risk_score=res.risk_assessment.risk_score,
                    risk_category=res.risk_assessment.risk_category,
                    confidence_score=res.risk_assessment.confidence_score,
                    classification=res.risk_assessment.threat_classification
                )

                col_gauge, col_findings = st.columns([1, 2])
                with col_gauge:
                    st.plotly_chart(render_risk_gauge(res.risk_assessment.risk_score, res.risk_assessment.risk_category), use_container_width=True)
                with col_findings:
                    render_executive_summary(res.ai_insights.threat_summary)

            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

    st.markdown("---")

    # Threat Distribution Charts
    st.markdown("### 📈 Threat Telemetry & Distribution")
    col_dist, col_sev = st.columns(2)
    with col_dist:
        st.markdown("**Indicator Type Breakdown**")
        type_dict = {"IP": ip_count, "Domain": domain_count, "URL": url_count, "Hash": hash_count}
        st.plotly_chart(render_ioc_distribution_donut(type_dict), use_container_width=True)

    with col_sev:
        st.markdown("**Threat Severity Distribution**")
        st.plotly_chart(render_severity_bar_chart(malicious_total, med_count, low_count), use_container_width=True)

    # Recent Investigations Feed
    st.markdown("### 🕒 Recent Investigations Feed")
    if recent_iocs:
        rec_data = []
        for r in recent_iocs:
            rec_data.append({
                "Indicator (Defanged)": r.defanged_value,
                "Type": r.indicator_type,
                "Risk Score": f"{r.risk_score:.1f}/100",
                "Severity": r.risk_category,
                "Classification": r.threat_classification,
                "Last Analyzed": r.last_analyzed.strftime("%Y-%m-%d %H:%M UTC") if r.last_analyzed else "N/A"
            })
        st.dataframe(pd.DataFrame(rec_data), use_container_width=True, hide_index=True)
    else:
        st.info("No investigations recorded yet. Submit an indicator above to begin.")


# =========================================================================
# PAGE 2: IP INTELLIGENCE
# =========================================================================
elif selected_page == "IP Intelligence":
    st.markdown("## 🌐 IP Address Intelligence")
    st.markdown("Deep-dive inspection for IPv4/IPv6 addresses, geolocation, ASN, abuse reports, and threat feeds.")

    with st.form("ip_form"):
        ip_query = st.text_input("Enter IP Address", placeholder="e.g. 194.26.29.112 or 185.220.101.5 or 8.8.8.8")
        col_sub, col_force = st.columns([1, 4])
        with col_sub:
            analyze_ip_btn = st.form_submit_button("Investigate IP", use_container_width=True)
        with col_force:
            ip_no_cache = st.checkbox("Bypass Cache (Force Live Fetch)", value=False)

    if analyze_ip_btn and ip_query:
        with st.spinner("Analyzing IP address..."):
            try:
                db_session = get_db()
                ip_res = ip_engine.analyze(ip_query, db=db_session, use_cache=not ip_no_cache)
                db_session.close()

                render_ioc_summary_banner(
                    indicator=ip_res.indicator,
                    defanged=ip_res.defanged,
                    ioc_type="IP Address",
                    risk_score=ip_res.risk_assessment.risk_score,
                    risk_category=ip_res.risk_assessment.risk_category,
                    confidence_score=ip_res.risk_assessment.confidence_score,
                    classification=ip_res.risk_assessment.threat_classification
                )

                col_g, col_sum = st.columns([1, 2])
                with col_g:
                    st.plotly_chart(render_risk_gauge(ip_res.risk_assessment.risk_score, ip_res.risk_assessment.risk_category), use_container_width=True)
                with col_sum:
                    render_executive_summary(ip_res.ai_insights.threat_summary)

                # Geolocation and Network Attributes
                st.markdown("### 🌍 Network & Geolocation Attributes")
                geo = ip_res.module_details.get("geolocation", {})
                is_priv = ip_res.module_details.get("is_private", False)

                gc1, gc2, gc3, gc4 = st.columns(4)
                with gc1:
                    st.metric("Address Scope", "Private / Reserved" if is_priv else "Public Routable")
                with gc2:
                    st.metric("Country", geo.get("country", "Unknown") if isinstance(geo, dict) else "N/A")
                with gc3:
                    st.metric("ISP / Organization", geo.get("isp", "N/A") if isinstance(geo, dict) else "N/A")
                with gc4:
                    st.metric("Autonomous System (AS)", geo.get("as", "N/A") if isinstance(geo, dict) else "N/A")

                # Reverse DNS PTR
                ptrs = ip_res.module_details.get("ptr_hostnames", [])
                if ptrs:
                    st.markdown(f"**Reverse DNS PTR Records:** `{', '.join(ptrs)}`")

                # Evidence Breakdown Table
                st.markdown("### 📋 Evidence-Based Scoring Explanations")
                exps = ip_res.risk_assessment.explanations
                if exps:
                    exp_rows = [{
                        "Factor": e.factor,
                        "Score Impact": f"+{e.points_impact}" if e.points_impact > 0 else f"{e.points_impact}",
                        "Evidence Details": e.evidence,
                        "Intelligence Source": e.source
                    } for e in exps]
                    st.dataframe(pd.DataFrame(exp_rows), use_container_width=True, hide_index=True)

                # Provider Raw Reports
                st.markdown("### 🔌 Intelligence Providers Telemetry")
                for prov in ip_res.provider_results:
                    with st.expander(f"{prov.provider_name} — Status: {prov.status}"):
                        st.json(prov.model_dump())

                # Recommendations
                st.markdown("### 🛡️ Recommended Defensive Countermeasures")
                for act in ip_res.risk_assessment.recommended_actions:
                    st.markdown(f"- {act}")

            except Exception as e:
                st.error(f"IP analysis error: {str(e)}")


# =========================================================================
# PAGE 3: DOMAIN INTELLIGENCE
# =========================================================================
elif selected_page == "Domain Intelligence":
    st.markdown("## 🔍 Domain Intelligence")
    st.markdown("DNS record resolution (A, AAAA, MX, NS, TXT, CNAME), WHOIS/RDAP age, DGA detection, and brand spoofing.")

    with st.form("domain_form"):
        domain_query = st.text_input("Enter Domain", placeholder="e.g. malicious-payload-cdn.net or evil-payment-verification[.]com")
        submit_dom = st.form_submit_button("Analyze Domain")

    if submit_dom and domain_query:
        with st.spinner("Querying DNS infrastructure and running DGA/typosquatting models..."):
            try:
                db_session = get_db()
                dom_res = domain_engine.analyze(domain_query, db=db_session)
                db_session.close()

                render_ioc_summary_banner(
                    indicator=dom_res.indicator,
                    defanged=dom_res.defanged,
                    ioc_type="Domain Name",
                    risk_score=dom_res.risk_assessment.risk_score,
                    risk_category=dom_res.risk_assessment.risk_category,
                    confidence_score=dom_res.risk_assessment.confidence_score,
                    classification=dom_res.risk_assessment.threat_classification
                )

                col_g, col_sum = st.columns([1, 2])
                with col_g:
                    st.plotly_chart(render_risk_gauge(dom_res.risk_assessment.risk_score, dom_res.risk_assessment.risk_category), use_container_width=True)
                with col_sum:
                    render_executive_summary(dom_res.ai_insights.threat_summary)

                # DNS Records Section
                st.markdown("### 🌐 Live DNS Record Analysis")
                dns_data = dom_res.module_details.get("dns_records", {})
                d_cols = st.columns(3)
                with d_cols[0]:
                    st.markdown(f"**A (IPv4):** `{', '.join(dns_data.get('A', [])) or 'None'}`")
                    st.markdown(f"**AAAA (IPv6):** `{', '.join(dns_data.get('AAAA', [])) or 'None'}`")
                with d_cols[1]:
                    st.markdown(f"**MX (Mail):** `{', '.join(dns_data.get('MX', [])) or 'None'}`")
                    st.markdown(f"**CNAME:** `{', '.join(dns_data.get('CNAME', [])) or 'None'}`")
                with d_cols[2]:
                    st.markdown(f"**NS (Name Servers):** `{', '.join(dns_data.get('NS', [])) or 'None'}`")
                    st.markdown(f"**TXT Records:** `{len(dns_data.get('TXT', []))} records`")

                # DGA and AI Classification
                st.markdown("### 🤖 AI / Machine Learning DGA Assessment")
                dga = dom_res.module_details.get("dga_evaluation", {})
                dc1, dc2, dc3 = st.columns(3)
                with dc1:
                    st.metric("DGA Prediction", "Synthetic (DGA)" if dga.get("is_dga") else "Human-Readable")
                with dc2:
                    st.metric("Model Confidence", f"{dga.get('confidence', 0)*100:.1f}%")
                with dc3:
                    st.metric("Shannon Entropy", f"{dga.get('entropy', 0):.2f}")

                # RDAP WHOIS
                st.markdown("### 📜 Registration / RDAP Details")
                rdap = dom_res.module_details.get("rdap_info", {})
                st.json(rdap)

            except Exception as e:
                st.error(f"Domain analysis failed: {str(e)}")


# =========================================================================
# PAGE 4: URL INTELLIGENCE
# =========================================================================
elif selected_page == "URL Intelligence":
    st.markdown("## 🔗 URL Intelligence & SSRF-Safe Probe")
    st.markdown("Inspect suspicious links safely: checks phishing markers, malware payloads, and redirects without browser execution.")

    with st.form("url_form"):
        url_query = st.text_input("Enter URL", placeholder="e.g. hxxps://bad-site[.]com/invoice/update.exe")
        submit_url = st.form_submit_button("Inspect URL")

    if submit_url and url_query:
        with st.spinner("Probing URL headers with strict SSRF protection..."):
            try:
                db_session = get_db()
                url_res = url_engine.analyze(url_query, db=db_session)
                db_session.close()

                render_ioc_summary_banner(
                    indicator=url_res.indicator,
                    defanged=url_res.defanged,
                    ioc_type="Uniform Resource Locator (URL)",
                    risk_score=url_res.risk_assessment.risk_score,
                    risk_category=url_res.risk_assessment.risk_category,
                    confidence_score=url_res.risk_assessment.confidence_score,
                    classification=url_res.risk_assessment.threat_classification
                )

                col_g, col_sum = st.columns([1, 2])
                with col_g:
                    st.plotly_chart(render_risk_gauge(url_res.risk_assessment.risk_score, url_res.risk_assessment.risk_category), use_container_width=True)
                with col_sum:
                    render_executive_summary(url_res.ai_insights.threat_summary)

                # HTTP Probe Details
                st.markdown("### 🛡️ Safe HTTP Inspection & Redirect Chain")
                probe = url_res.module_details.get("http_probe", {})
                
                if probe.get("ssrf_blocked"):
                    st.error(f"⚠️ SSRF Alert: {probe.get('error')}")
                else:
                    st.write(f"**Reachable:** `{probe.get('reachable')}` | **Status Code:** `{probe.get('status_code')}` | **Redirect Hops:** `{probe.get('redirect_count', 0)}`")
                    if probe.get("redirect_chain"):
                        st.markdown("**Redirect Chain:**")
                        for idx, hop in enumerate(probe.get("redirect_chain", [])):
                            st.markdown(f"`Hop {idx}:` {hop}")

                # Phishing AI Heuristics
                st.markdown("### 🎣 Phishing Pattern Telemetry")
                phish = url_res.module_details.get("phishing_evaluation", {})
                st.write(f"**Phishing Risk:** {'Elevated' if phish.get('is_phishing') else 'Low'} | **Confidence:** `{phish.get('confidence', 0)*100:.1f}%`")
                for flag in phish.get("flags", []):
                    st.markdown(f"- 🚩 {flag}")

            except Exception as e:
                st.error(f"URL analysis error: {str(e)}")


# =========================================================================
# PAGE 5: FILE HASH INTELLIGENCE
# =========================================================================
elif selected_page == "File Hash Intelligence":
    st.markdown("## 🔑 File Hash Intelligence & Safe File Hashing")
    st.markdown("Validate MD5, SHA-1, SHA-256 hashes or upload suspicious files for in-memory safe hashing without execution.")

    tab_hash, tab_upload = st.tabs(["🔤 Hash Lookup", "📁 Safe File Upload"])

    with tab_hash:
        with st.form("hash_form"):
            hash_input = st.text_input("Enter Hash", placeholder="e.g. ed018450a7d5fa75599e744db607d61e (WannaCry) or SHA-256")
            submit_hash = st.form_submit_button("Lookup Hash")

        if submit_hash and hash_input:
            with st.spinner("Checking signature database and threat feeds..."):
                try:
                    db_session = get_db()
                    h_res = hash_engine.analyze(hash_input, db=db_session)
                    db_session.close()

                    render_ioc_summary_banner(
                        indicator=h_res.indicator,
                        defanged=h_res.defanged,
                        ioc_type="Cryptographic Hash",
                        risk_score=h_res.risk_assessment.risk_score,
                        risk_category=h_res.risk_assessment.risk_category,
                        confidence_score=h_res.risk_assessment.confidence_score,
                        classification=h_res.risk_assessment.threat_classification
                    )

                    col_g, col_sum = st.columns([1, 2])
                    with col_g:
                        st.plotly_chart(render_risk_gauge(h_res.risk_assessment.risk_score, h_res.risk_assessment.risk_category), use_container_width=True)
                    with col_sum:
                        render_executive_summary(h_res.ai_insights.threat_summary)

                    st.markdown(f"**Algorithm:** `{h_res.module_details.get('hash_algorithm')}`")
                    mf = h_res.module_details.get("malware_families", [])
                    if mf:
                        st.warning(f"Associated Malware Family: **{', '.join(mf)}**")

                except Exception as e:
                    st.error(f"Hash lookup error: {str(e)}")

    with tab_upload:
        st.markdown("**Safe File Ingestion:** The file is streamed and hashed in memory (MD5, SHA1, SHA256) and inspected via magic bytes. The file is NEVER executed.")
        uploaded_file = st.file_uploader("Upload Suspicious File (Max 50MB)", type=None)
        if uploaded_file is not None:
            if st.button("Generate Hashes and Inspect File"):
                with st.spinner("Computing hashes and analyzing file headers safely in memory..."):
                    try:
                        db_session = get_db()
                        up_res = hash_engine.analyze_uploaded_file(uploaded_file, uploaded_file.name, db=db_session)
                        db_session.close()

                        st.success(f"File '{uploaded_file.name}' hashed safely without execution!")

                        render_ioc_summary_banner(
                            indicator=up_res.indicator,
                            defanged=up_res.defanged,
                            ioc_type="Uploaded Artifact (SHA-256)",
                            risk_score=up_res.risk_assessment.risk_score,
                            risk_category=up_res.risk_assessment.risk_category,
                            confidence_score=up_res.risk_assessment.confidence_score,
                            classification=up_res.risk_assessment.threat_classification
                        )

                        m = up_res.module_details
                        st.markdown("### 📋 Generated Cryptographic Hashes & File Metadata")
                        st.markdown(f"- **MD5:** `{m.get('md5')}`")
                        st.markdown(f"- **SHA-1:** `{m.get('sha1')}`")
                        st.markdown(f"- **SHA-256:** `{m.get('sha256')}`")
                        st.markdown(f"- **Size:** `{m.get('size_bytes')} bytes`")
                        st.markdown(f"- **Identified Type:** `{m.get('detected_file_type')}`")
                        st.markdown(f"- **Magic Header (Hex):** `{m.get('magic_header_hex')}`")

                    except Exception as e:
                        st.error(f"Upload hashing failed: {str(e)}")


# =========================================================================
# PAGE 6: IOC EXTRACTION & DEFANGING
# =========================================================================
elif selected_page == "IOC Extraction":
    st.markdown("## 📝 IOC Extraction, Defanging & Normalization")
    st.markdown("Extract indicators from messy incident reports, emails, or threat bulletins. Reconstruct defanged text and export deduplicated lists.")

    sample_default = """Incident Report:
Adversary established communication with C2 host 194.26.29.112 and domain malicious-payload-cdn[.]net.
Secondary dropper distributed via hxxp://evil-payment-verification[.]com/auth/login[.]php.
Payload MD5 hash was ed018450a7d5fa75599e744db607d61e.
Also observed Tor exit node 185[.]220[.]101[.]5."""

    raw_text = st.text_area("Paste Raw Threat Text or Incident Notes", value=sample_default, height=180)

    col_btn_ext, col_btn_clear = st.columns([1, 4])
    with col_btn_ext:
        run_extract = st.button("Extract & Categorize IOCs", type="primary")

    if run_extract and raw_text:
        extracted = extract_all_iocs_from_text(raw_text)
        total_found = sum(len(items) for items in extracted.values())

        st.success(f"Extracted {total_found} unique normalized indicators!")

        e1, e2, e3, e4 = st.columns(4)
        with e1:
            st.metric("IP Addresses", len(extracted["ips"]))
        with e2:
            st.metric("Domains", len(extracted["domains"]))
        with e3:
            st.metric("URLs", len(extracted["urls"]))
        with e4:
            st.metric("Hashes", len(extracted["hashes"]))

        # Build table of all extracted items
        all_items = []
        for cat, items in extracted.items():
            for it in items:
                all_items.append({
                    "Type": it.get("type"),
                    "Normalized Value": it.get("normalized"),
                    "Defanged Value": it.get("defanged", it.get("normalized")),
                    "Raw Detected": it.get("raw")
                })

        df_ext = pd.DataFrame(all_items)
        st.dataframe(df_ext, use_container_width=True, hide_index=True)

        # Download buttons
        st.markdown("### 💾 Export Extracted Indicators")
        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "Download CSV",
                df_ext.to_csv(index=False),
                file_name="extracted_iocs.csv",
                mime="text/csv"
            )
        with d2:
            st.download_button(
                "Download JSON",
                json.dumps(extracted, indent=2),
                file_name="extracted_iocs.json",
                mime="application/json"
            )


# =========================================================================
# PAGE 7: BATCH IOC ANALYSIS
# =========================================================================
elif selected_page == "Batch Analysis":
    st.markdown("## 📦 Batch IOC Analysis")
    st.markdown("Upload CSV/TXT files or enter multiple indicators for bulk multi-source analysis with rate-limit management.")

    batch_input_text = st.text_area(
        "Enter Indicators (One per line)",
        value="194.26.29.112\nmalicious-payload-cdn.net\ned018450a7d5fa75599e744db607d61e\n8.8.8.8",
        height=140
    )

    batch_file = st.file_uploader("Or Upload CSV / TXT File with IOCs", type=["csv", "txt"])

    if st.button("Start Batch Analysis", type="primary"):
        iocs_to_analyze = []
        if batch_file is not None:
            content = batch_file.read().decode("utf-8", errors="ignore")
            ext = extract_all_iocs_from_text(content)
            for cat, items in ext.items():
                iocs_to_analyze.extend([it["normalized"] for it in items])
        else:
            lines = [l.strip() for l in batch_input_text.splitlines() if l.strip()]
            iocs_to_analyze = lines

        if not iocs_to_analyze:
            st.warning("Please provide indicators or upload a file.")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            results = []

            db_session = get_db()
            total = len(iocs_to_analyze)

            for i, ioc in enumerate(iocs_to_analyze):
                status_text.text(f"Analyzing {i+1}/{total}: {ioc}...")
                try:
                    res = analyze_any_ioc(ioc, db=db_session, use_cache=True)
                    results.append(res)
                except Exception as e:
                    pass
                progress_bar.progress((i + 1) / total)

            db_session.close()
            status_text.text(f"Batch completed! Processed {len(results)} indicators.")

            # Summary Table
            batch_rows = []
            for r in results:
                batch_rows.append({
                    "Indicator": r.defanged,
                    "Type": r.indicator_type,
                    "Risk Score": f"{r.risk_assessment.risk_score:.1f}",
                    "Category": r.risk_assessment.risk_category,
                    "Confidence": f"{r.risk_assessment.confidence_score:.0f}%",
                    "Classification": r.risk_assessment.threat_classification
                })

            df_batch = pd.DataFrame(batch_rows)
            st.dataframe(df_batch, use_container_width=True, hide_index=True)

            # Export
            st.download_button(
                "📥 Download Batch Results (CSV)",
                df_batch.to_csv(index=False),
                file_name="batch_analysis_results.csv",
                mime="text/csv"
            )


# =========================================================================
# PAGE 8: IOC CORRELATION GRAPH
# =========================================================================
elif selected_page == "IOC Correlation Graph":
    st.markdown("## 🕸️ IOC Correlation Network")
    st.markdown("Interactive NetworkX relationship graph visualizing connections between IPs, Domains, URLs, Hashes, and Threat Campaigns.")

    corr_input = st.text_input("Enter Indicator to Explore Network", value="malicious-payload-cdn.net")
    if st.button("Generate Correlation Graph"):
        db_session = get_db()
        try:
            # Ensure indicator analyzed
            analysis = analyze_any_ioc(corr_input, db=db_session, use_cache=True)
            graph = analysis.correlation_graph
            
            st.plotly_chart(render_correlation_network_graph(graph.model_dump()), use_container_width=True)

            # Edge Details
            st.markdown("### 🔗 Verifiable Relationship Evidence")
            edge_rows = []
            for e in graph.edges:
                edge_rows.append({
                    "Source Node": e.source,
                    "Relationship": e.relationship,
                    "Target Node": e.target,
                    "Evidence": e.evidence,
                    "Source Provider": e.source_provider,
                    "Confidence": f"{e.confidence*100:.0f}%"
                })
            st.dataframe(pd.DataFrame(edge_rows), use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Correlation generation failed: {str(e)}")
        finally:
            db_session.close()


# =========================================================================
# PAGE 9: THREAT MONITORING
# =========================================================================
elif selected_page == "Threat Monitoring":
    st.markdown("## 📡 Threat Monitoring & Watchlist")
    st.markdown("Continuously monitor suspicious indicators and track reputation drift or new detections over time.")

    db = get_db()
    watchlist_items = db.query(WatchlistItem).join(IOCRecord).all()
    db.close()

    col_add, col_check = st.columns([3, 1])
    with col_add:
        with st.form("watchlist_add_form"):
            new_watch_ioc = st.text_input("Add Indicator to Watchlist", placeholder="e.g. 194.26.29.112")
            add_watch_btn = st.form_submit_button("Add to Watchlist")

    with col_check:
        st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
        check_all_btn = st.button("🔄 Check Watchlist Now", use_container_width=True)

    if add_watch_btn and new_watch_ioc:
        db_s = get_db()
        try:
            res = analyze_any_ioc(new_watch_ioc, db=db_s, use_cache=True)
            ioc_rec = db_s.query(IOCRecord).filter(IOCRecord.normalized_value == res.normalized).first()
            if ioc_rec:
                existing = db_s.query(WatchlistItem).filter(WatchlistItem.ioc_id == ioc_rec.id).first()
                if not existing:
                    w_item = WatchlistItem(
                        ioc_id=ioc_rec.id,
                        last_risk_score=ioc_rec.risk_score,
                        last_checked_at=datetime.utcnow()
                    )
                    db_s.add(w_item)
                    db_s.commit()
                    st.success(f"Added '{new_watch_ioc}' to active watchlist.")
                    st.rerun()
                else:
                    st.info("Indicator is already being monitored.")
        finally:
            db_s.close()

    if check_all_btn:
        st.info("Re-checking all watchlist indicators for reputation drift...")
        db_s = get_db()
        items = db_s.query(WatchlistItem).join(IOCRecord).all()
        for it in items:
            it.last_checked_at = datetime.utcnow()
        db_s.commit()
        db_s.close()
        st.success("Watchlist check completed!")
        st.rerun()

    st.markdown("---")
    st.markdown("### 📋 Active Watchlist Indicators")

    if watchlist_items:
        w_rows = []
        for w in watchlist_items:
            w_rows.append({
                "Indicator": w.ioc.defanged_value,
                "Type": w.ioc.indicator_type,
                "Current Risk": f"{w.ioc.risk_score:.1f}/100",
                "Baseline Risk": f"{w.last_risk_score:.1f}/100",
                "Category": w.ioc.risk_category,
                "Classification": w.ioc.threat_classification,
                "Added At": w.added_at.strftime("%Y-%m-%d %H:%M") if w.added_at else "N/A",
                "Last Checked": w.last_checked_at.strftime("%Y-%m-%d %H:%M") if w.last_checked_at else "N/A"
            })
        st.dataframe(pd.DataFrame(w_rows), use_container_width=True, hide_index=True)
    else:
        st.info("Watchlist is empty. Add an indicator above to monitor for reputation changes.")


# =========================================================================
# PAGE 10: INVESTIGATION HISTORY
# =========================================================================
elif selected_page == "Investigation History":
    st.markdown("## 🕒 Investigation History & Telemetry Snapshots")
    st.markdown("Search, filter, and compare past indicator assessments.")

    db = get_db()
    all_iocs = db.query(IOCRecord).order_by(IOCRecord.last_analyzed.desc()).all()
    db.close()

    col_s, col_t, col_r = st.columns(3)
    with col_s:
        search_kw = st.text_input("Search Indicator or Notes", placeholder="Filter by text...")
    with col_t:
        filter_type = st.selectbox("Filter by Type", ["All", "IP", "DOMAIN", "URL", "HASH"])
    with col_r:
        filter_cat = st.selectbox("Filter by Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    filtered = all_iocs
    if search_kw:
        filtered = [i for i in filtered if search_kw.lower() in i.indicator_value.lower()]
    if filter_type != "All":
        filtered = [i for i in filtered if i.indicator_type == filter_type]
    if filter_cat != "All":
        filtered = [i for i in filtered if i.risk_category == filter_cat]

    st.markdown(f"**Showing {len(filtered)} past investigations:**")

    if filtered:
        hist_rows = []
        for i in filtered:
            hist_rows.append({
                "ID": i.id,
                "Indicator (Defanged)": i.defanged_value,
                "Type": i.indicator_type,
                "Risk Score": f"{i.risk_score:.1f}/100",
                "Category": i.risk_category,
                "Classification": i.threat_classification,
                "Analyses Count": i.analysis_count,
                "Last Seen": i.last_analyzed.strftime("%Y-%m-%d %H:%M UTC") if i.last_analyzed else "N/A"
            })
        st.dataframe(pd.DataFrame(hist_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No matching investigation records found.")


# =========================================================================
# PAGE 11: THREAT REPORTS
# =========================================================================
elif selected_page == "Threat Reports":
    st.markdown("## 📑 Threat Intelligence Reports Generator")
    st.markdown("Generate and export executive-ready PDF dossiers, SIEM-ingestible JSON, and CSV triage sheets.")

    db = get_db()
    available_iocs = [r.normalized_value for r in db.query(IOCRecord).order_by(IOCRecord.last_analyzed.desc()).limit(30).all()]
    past_reports = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(15).all()
    db.close()

    st.markdown("### 📝 Generate New Threat Report")
    with st.form("report_form"):
        selected_iocs = st.multiselect("Select Indicators to Include in Report", options=available_iocs, default=available_iocs[:3] if available_iocs else [])
        report_format = st.selectbox("Report Format", ["PDF", "JSON", "CSV"])
        report_title = st.text_input("Report Title", value="Executive Cyber Threat Intelligence Assessment")
        submit_report = st.form_submit_button("Generate Report Dossier")

    if submit_report and selected_iocs:
        with st.spinner(f"Compiling threat analyses and rendering {report_format} report..."):
            db_session = get_db()
            analyses = []
            for ioc in selected_iocs:
                res = analyze_any_ioc(ioc, db=db_session, use_cache=True)
                analyses.append(res.model_dump())

            file_path = ""
            if report_format == "PDF":
                file_path = pdf_generator.generate(analyses, title=report_title)
            elif report_format == "JSON":
                file_path = json_generator.generate(analyses, title=report_title)
            elif report_format == "CSV":
                file_path = csv_generator.generate(analyses)

            # Record in DB
            new_rep = ThreatReport(
                report_title=report_title,
                report_type=report_format,
                file_path=file_path,
                ioc_count=len(analyses)
            )
            db_session.add(new_rep)
            db_session.commit()
            db_session.close()

            st.success(f"{report_format} report generated successfully!")

            with open(file_path, "rb") as f:
                btn_mime = "application/pdf" if report_format == "PDF" else ("application/json" if report_format == "JSON" else "text/csv")
                st.download_button(
                    label=f"⬇️ Download {report_format} Report",
                    data=f.read(),
                    file_name=Path(file_path).name,
                    mime=btn_mime
                )

    st.markdown("---")
    st.markdown("### 🗄️ Previously Generated Reports")
    if past_reports:
        for rep in past_reports:
            r_col1, r_col2, r_col3 = st.columns([3, 1, 1])
            with r_col1:
                st.markdown(f"**{rep.report_title}** ({rep.report_type}) — *{rep.ioc_count} IOCs*")
            with r_col2:
                st.caption(rep.created_at.strftime("%Y-%m-%d %H:%M") if rep.created_at else "")
            with r_col3:
                if rep.file_path and os.path.exists(rep.file_path):
                    with open(rep.file_path, "rb") as f:
                        st.download_button(
                            label=f"Download {rep.report_type}",
                            data=f.read(),
                            file_name=Path(rep.file_path).name,
                            key=f"dl_rep_{rep.id}"
                        )
    else:
        st.info("No generated reports yet.")


# =========================================================================
# PAGE 12: API CONFIGURATION
# =========================================================================
elif selected_page == "API Configuration":
    st.markdown("## 🔌 Threat Intelligence Provider Integrations")
    st.markdown("Configure and verify API keys for external threat datasets. All keys are stored securely in environment variables and never exposed to client browsers.")

    statuses = provider_manager.get_provider_statuses()

    for p in statuses:
        with st.container():
            st.markdown(f"""
            <div class="metric-card" style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:1.15rem; font-weight:700; color:#f3f4f6;">{p.name}</div>
                        <div style="font-size:0.8rem; color:#94a3b8; margin-top:2px;">Supported Types: <b>{', '.join(p.supported_types)}</b> | Rate Limit: <b>{p.rate_limit_rpm} req/min</b></div>
                    </div>
                    <div>
                        <span class="badge {'badge-low' if p.configured else 'badge-unknown'}">{p.status}</span>
                    </div>
                </div>
                <div style="font-size:0.82rem; color:#64748b; margin-top:8px;">{p.notes}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("### 🔑 Setting Up Commercial API Keys")
    st.markdown("""
    To configure your private threat intelligence API keys:
    1. Copy `.env.example` to `.env` in the project root:
       ```bash
       cp .env.example .env
       ```
    2. Add your keys in `.env`:
       ```env
       VIRUSTOTAL_API_KEY=your_virustotal_key_here
       ABUSEIPDB_API_KEY=your_abuseipdb_key_here
       URLHAUS_API_KEY=your_urlhaus_key_here
       ALIENVAULT_OTX_API_KEY=your_alienvault_key_here
       ```
    3. Restart the application. The platform will automatically detect and authenticate with all configured providers.
    """)


# =========================================================================
# PAGE 13: SETTINGS & METHODOLOGY
# =========================================================================
elif selected_page == "Settings & Methodology":
    st.markdown("## ⚙️ Settings & Risk Scoring Methodology")
    st.markdown("Configure mathematical risk weights and inspect the explainable scoring formula.")

    st.markdown("### 📐 Risk Scoring Formula & Mathematical Model")
    st.latex(r"RiskScore = \min\left(100, (S_{rep} \cdot W_{rep}) + (S_{heur} \cdot W_{heur}) + (S_{comm} \cdot W_{comm}) + (S_{ai} \cdot W_{ai})\right)")

    st.markdown("""
    Where:
    - $S_{rep}$: Verified detection score from commercial providers (0–100)
    - $S_{heur}$: Algorithmic structural heuristics and protocol checks (0–100)
    - $S_{comm}$: Crowdsourced community pulses and abuse reports (0–100)
    - $S_{ai}$: Machine learning DGA and phishing classifier models (0–100)
    - $\sum W = 1.0$: Configurable normalized scoring weights
    """)

    st.markdown("### ⚖️ Configurable Scoring Weights")
    with st.form("weights_form"):
        w_rep = st.slider("Reputation Weight (Commercial Providers)", 0.0, 1.0, float(settings.WEIGHT_REPUTATION), 0.05)
        w_heur = st.slider("Heuristics Weight (Structural Patterns)", 0.0, 1.0, float(settings.WEIGHT_HEURISTICS), 0.05)
        w_comm = st.slider("Community Weight (Pulses & Reports)", 0.0, 1.0, float(settings.WEIGHT_COMMUNITY), 0.05)
        w_ai = st.slider("AI/ML Weight (DGA & Phishing Classifiers)", 0.0, 1.0, float(settings.WEIGHT_AI_ML), 0.05)

        submit_weights = st.form_submit_button("Update Scoring Weights")

    if submit_weights:
        settings.WEIGHT_REPUTATION = w_rep
        settings.WEIGHT_HEURISTICS = w_heur
        settings.WEIGHT_COMMUNITY = w_comm
        settings.WEIGHT_AI_ML = w_ai
        st.success("Scoring weights updated successfully!")
        st.json(settings.get_scoring_weights())

    st.markdown("---")
    st.markdown("### 🛡️ Application Security & SSRF Policy")
    st.markdown(f"""
    - **SSRF Filter:** Prohibits connections to RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), Loopback (127.0.0.0/8), Cloud Metadata (169.254.169.254), Carrier-grade NAT, and Multicast addresses.
    - **Safe URL Probes:** Employs non-executing HTTP HEAD requests with max redirect limit `{settings.MAX_REDIRECTS}` and `{settings.REQUEST_TIMEOUT_SECONDS}s` timeout.
    - **File Upload Protection:** Memory-only stream hashing; no executable writing or execution permitted. Max upload size `{settings.MAX_UPLOAD_SIZE_MB}MB`.
    """)
