# 🛡️ AI-Powered Cyber Threat Intelligence (CTI) Analysis Platform

An enterprise-grade, production-oriented Cyber Threat Intelligence (CTI) platform built for cybersecurity students, SOC analysts, and threat intelligence engineers.

The platform provides an end-to-end operational pipeline to **collect, validate, normalize, analyze, correlate, and visualize Indicators of Compromise (IOCs)** across IP addresses, domains, URLs, and cryptographic file hashes.

---

## 🌟 Key Platform Features

### 1. Robust IOC Validation & Defanging
- **Multi-Type Indicator Support:** IPv4, IPv6, Domain Names, URLs, and Hashes (MD5, SHA-1, SHA-256).
- **Automated Refanging & Defanging:** Safely sanitizes malicious indicators (`hxxp[s]://` ⇄ `http[s]://`, `[.]` ⇄ `.`, `[:]` ⇄ `:`) preventing accidental execution.
- **Bulk Text Extraction:** Scans raw unstructured incident reports, email headers, or chat logs with deduplication.

### 2. Multi-Source Threat Intelligence Integrations
- **VirusTotal API v3:** Analyzes IPs, domains, URLs, and file hashes.
- **AbuseIPDB API v2:** Queries IP abuse confidence scores, report counts, and ISP metadata.
- **URLhaus (abuse.ch):** Detects verified malware hosting URLs, payload distribution hosts, and file hashes.
- **AlienVault OTX v1:** Correlates threat pulses, adversary tags, and targeted sectors.
- **Local Threat KnowledgeBase:** Built-in signature database (WannaCry, LockBit, Emotet, Cobalt Strike C2s, Tor exit nodes) ensuring **100% functionality even when external API keys are missing**.
- **Live Infrastructure Queries:** Real-time DNS record analysis (A, AAAA, MX, NS, TXT, CNAME) via `dnspython`, WHOIS/RDAP registration lookups, and IP geolocation.

### 3. Application Security & Strict SSRF Protection
- **SSRF Prevention:** Enforces strict outbound network boundary controls. Blocks requests to private networks (RFC 1918), loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), and carrier-grade NAT.
- **DNS Rebinding Defense:** Resolves destination hostnames prior to connection.
- **Safe HTTP Probing:** Inspects URL response codes, headers, and redirect chains without rendering HTML or executing JavaScript.
- **Safe File Upload Hashing:** Streams uploaded files in 64KB chunks in-memory to calculate hashes and detect magic byte MIME types. **Uploaded files are never executed.**

### 4. Explainable Threat Risk & Confidence Scoring
- **Risk Score (0–100):** Divided into Low (0–29), Medium (30–69), High (70–89), and Critical (90–100).
- **Separate Confidence Score (0–100):** Reflects source corroboration and data completeness.
- **Methodology Rule:** A missing API result is **never** treated as proof of safety.
- **Evidence-Based Explanations:** Full itemized breakdown of exact points contributed by each intelligence factor.
- **Configurable Weights:** Customize reputation, heuristic, community, and AI/ML weights dynamically.

### 5. AI-Assisted Intelligence Layer
- **DGA Classifier:** Machine learning lexical assessment detecting synthetic botnet domains (evaluates Shannon entropy, vowel-to-consonant ratios, and consonant clustering).
- **Phishing URL Classifier:** Lexical model detecting credential harvesting structures, deceptive subdomains, and obfuscation.
- **Anomaly & Typosquatting Detection:** Measures Levenshtein edit distance against top brands (Google, Microsoft, PayPal, Apple, Amazon, etc.).
- **Natural Language Threat Briefings:** Synthesizes executive briefings and tailored SOC defensive playbooks.

### 6. Interactive Network Correlation Engine
- Directional relationship networks powered by **NetworkX** and visualized with **Plotly**.
- Maps links: `Domain --[RESOLVES_TO]--> IP`, `URL --[HOSTED_ON]--> Domain`, `Hash --[IDENTIFIED_AS]--> MalwareFamily`, and `IOC --[ATTRIBUTED_TO]--> Campaign`.
- Displays verifiable proof citations for every connection.

### 7. Executive Reporting & Exporting
- **PDF Dossiers:** Formatted assessment briefs generated with ReportLab, complete with risk badges, evidence matrices, and SOC playbooks.
- **JSON Reports:** Machine-readable raw telemetry dumps.
- **CSV Reports:** Formatted tabular triage lists for SIEM ingestion.

### 8. Historical Tracking & Threat Monitoring
- SQLite / PostgreSQL persistence with SQLAlchemy.
- Searchable historical investigation archive.
- Monitored Watchlist with reputation delta tracking and shift alerts.

---

## 🗂️ Project Directory Structure

```
cyber_threat_intelligence_platform/
├── app/
│   ├── __init__.py
│   ├── config.py                 # Pydantic BaseSettings, weights, rate limits, timeouts
│   ├── core/
│   │   ├── __init__.py
│   │   ├── exceptions.py         # Custom CTI exception classes
│   │   ├── rate_limiter.py       # Sliding-window rate limiter & in-memory TTL cache
│   │   ├── security.py           # SSRF protection, safe redirects, memory file hashing
│   │   └── validator.py          # IOC validation, regex extraction, defang/refang
│   ├── models/
│   │   ├── __init__.py
│   │   ├── database.py           # SQLAlchemy ORM models (IOCRecord, AnalysisResult, etc.)
│   │   └── schemas.py            # Pydantic v2 API request/response schemas
│   ├── database/
│   │   ├── __init__.py
│   │   ├── session.py            # DB engine, sessionmaker, get_db dependency
│   │   └── init_db.py            # Table initialization and baseline threat seed data
│   ├── providers/
│   │   ├── __init__.py           # ProviderManager orchestrator
│   │   ├── base.py               # BaseThreatProvider abstract adapter
│   │   ├── virustotal.py         # VirusTotal v3 API adapter
│   │   ├── abuseipdb.py          # AbuseIPDB v2 API adapter
│   │   ├── urlhaus.py            # URLhaus abuse.ch API adapter
│   │   ├── alienvault.py         # AlienVault OTX API adapter
│   │   └── local_intel.py        # Local threat signatures, DNS resolver, WHOIS/RDAP
│   ├── engines/
│   │   ├── __init__.py           # Unified analyze_any_ioc dispatcher
│   │   ├── ip_engine.py          # IP intelligence engine
│   │   ├── domain_engine.py      # Domain intelligence & DNS engine
│   │   ├── url_engine.py         # URL intelligence & SSRF-safe probe engine
│   │   ├── hash_engine.py        # Hash intelligence & file inspection engine
│   │   ├── risk_scorer.py        # Explainable risk & confidence scoring engine
│   │   ├── correlation.py        # NetworkX relationship correlation engine
│   │   └── ai_engine.py          # AI/ML DGA, phishing, anomaly & narrative engines
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── pdf_generator.py      # ReportLab PDF threat report generator
│   │   ├── json_generator.py     # JSON export generator
│   │   └── csv_generator.py      # CSV export generator
│   └── api/
│       ├── __init__.py
│       ├── main.py               # FastAPI application setup & middleware
│       └── routes/
│           ├── analyze.py        # Single IOC & file upload analysis endpoints
│           ├── extract.py        # Text extraction and defanging endpoints
│           ├── batch.py          # Batch analysis endpoints
│           ├── correlation.py    # Correlation graph endpoint
│           ├── history.py        # Investigation history endpoints
│           ├── reports.py        # Threat report generation & download
│           ├── config.py         # Provider status & scoring weights endpoints
│           └── monitor.py        # Threat monitoring & watchlist endpoints
├── frontend/
│   ├── __init__.py
│   ├── app.py                   # Streamlit multi-page dashboard (13 core pages)
│   ├── style.py                 # Cybersecurity dark theme CSS & badge styling
│   └── components/
│       ├── __init__.py
│       ├── cards.py             # Metric cards and risk banner components
│       ├── charts.py            # Plotly risk gauge, donut, and bar charts
│       └── graph_viz.py         # Plotly interactive correlation graph visualizer
├── data/
│   ├── local_threat_db.json     # Curated baseline threat intelligence feeds
│   └── reports/                 # Storage directory for generated PDF/JSON/CSV reports
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Pytest fixtures and in-memory test database
│   ├── test_validators.py       # IOC regex validation & extraction tests
│   ├── test_security.py         # SSRF protection and safe file upload tests
│   ├── test_providers.py        # Mocked provider adapters tests
│   ├── test_engines.py          # IP, Domain, URL, Hash engines tests
│   ├── test_risk_scorer.py      # Risk and confidence scoring tests
│   ├── test_correlation.py      # NetworkX relationship graph tests
│   ├── test_ai_engine.py        # DGA, phishing classifier, anomaly tests
│   ├── test_reports.py          # PDF, JSON, CSV generation tests
│   └── test_api.py              # FastAPI endpoints tests
├── Dockerfile                   # Production container definition
├── docker-compose.yml           # Multi-service compose orchestrator
├── requirements.txt             # Pinned Python package dependencies
├── .env.example                 # Environment variables template
├── .gitignore                   # Git exclusion rules
├── ARCHITECTURE.md              # Detailed architecture & Mermaid diagrams
├── USER_GUIDE.md                # Complete analyst operational manual
└── API_DOCUMENTATION.md         # Full REST API specification
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.11.9)
- Git

### 1. Clone & Set Up Virtual Environment
```bash
# Clone the repository
git clone https://github.com/security/cyber-threat-intelligence-analyzer.git
cd cyber_threat_intelligence_platform

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(Optional)* Add your commercial API keys to `.env`:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
URLHAUS_API_KEY=your_key_here
ALIENVAULT_OTX_API_KEY=your_key_here
```
> **Note:** The application is fully operational out of the box without any commercial keys. It uses built-in threat databases, live DNS infrastructure, WHOIS/RDAP, and heuristic/ML models.

---

## 🏃 Running the Application

### Option A: Launch Both Services (Local Dev)

**Terminal 1 — Start the FastAPI Backend Engine:**
```bash
uvicorn app.api.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Root: `http://localhost:8000`
- Interactive Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

**Terminal 2 — Start the Streamlit Operations Dashboard:**
```bash
streamlit run frontend/app.py --server.port 8501
```
- Web Dashboard: `http://localhost:8501`

### Option B: Docker Container Deployment
```bash
docker compose up --build -d
```

---

## 🧪 Automated Test Suite

Run the full pytest suite with verbose output:
```bash
pytest -v
```

### Test Results
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\Joyunto\Downloads\cyber_threat_intelligence_platform
plugins: anyio-4.16.0, asyncio-1.4.1.post1
collected 41 items

tests/test_ai_engine.py::test_shannon_entropy PASSED                     [  2%]
tests/test_ai_engine.py::test_dga_domain_detection PASSED                [  4%]
tests/test_ai_engine.py::test_phishing_url_lexical_analysis PASSED       [  7%]
tests/test_ai_engine.py::test_brand_typosquatting_detection PASSED       [  9%]
tests/test_ai_engine.py::test_natural_language_summary PASSED            [ 12%]
tests/test_api.py::test_health_check PASSED                              [ 14%]
tests/test_api.py::test_platform_statistics PASSED                       [ 17%]
tests/test_api.py::test_analyze_ip_endpoint PASSED                       [ 19%]
tests/test_api.py::test_extract_iocs_endpoint PASSED                     [ 21%]
tests/test_api.py::test_defang_endpoint PASSED                           [ 24%]
tests/test_api.py::test_batch_analyze_endpoint PASSED                    [ 26%]
tests/test_api.py::test_history_endpoint PASSED                          [ 29%]
tests/test_api.py::test_provider_status_endpoint PASSED                  [ 31%]
tests/test_api.py::test_scoring_weights_endpoint PASSED                  [ 34%]
tests/test_correlation.py::test_correlation_graph_construction PASSED    [ 36%]
tests/test_engines.py::test_ip_engine_local_analysis PASSED              [ 39%]
tests/test_engines.py::test_domain_engine_local_analysis PASSED          [ 41%]
tests/test_engines.py::test_url_engine_ssrf_blocking PASSED              [ 43%]
tests/test_engines.py::test_hash_engine_wannacry_analysis PASSED         [ 46%]
tests/test_providers.py::test_local_threat_intel_provider PASSED         [ 48%]
tests/test_providers.py::test_virustotal_not_configured_graceful_handling PASSED [ 51%]
tests/test_providers.py::test_virustotal_mocked_malicious_response PASSED [ 53%]
tests/test_providers.py::test_abuseipdb_mocked_response PASSED           [ 56%]
tests/test_providers.py::test_urlhaus_mocked_response PASSED             [ 58%]
tests/test_providers.py::test_alienvault_mocked_pulse_response PASSED    [ 60%]
tests/test_reports.py::test_pdf_report_generation PASSED                 [ 63%]
tests/test_reports.py::test_json_report_generation PASSED                [ 65%]
tests/test_reports.py::test_csv_report_generation PASSED                 [ 68%]
tests/test_risk_scorer.py::test_risk_scoring_critical_malware PASSED     [ 70%]
tests/test_risk_scorer.py::test_risk_scoring_benign PASSED               [ 73%]
tests/test_risk_scorer.py::test_confidence_remains_separate_from_risk PASSED [ 75%]
tests/test_security.py::test_private_ip_detection PASSED                 [ 78%]
tests/test_security.py::test_ssrf_hostname_validation_blocks_internal PASSED [ 80%]
tests/test_security.py::test_safe_file_hashing_in_memory PASSED          [ 82%]
tests/test_security.py::test_safe_file_hashing_size_limit PASSED         [ 85%]
tests/test_validators.py::test_ip_validation PASSED                      [ 87%]
tests/test_validators.py::test_domain_validation PASSED                  [ 90%]
tests/test_validators.py::test_url_validation PASSED                     [ 92%]
tests/test_validators.py::test_hash_validation PASSED                    [ 95%]
tests/test_validators.py::test_defang_and_refang PASSED                  [ 97%]
tests/test_validators.py::test_extract_all_iocs_from_text PASSED         [100%]

======================= 41 passed in 28.94s ========================
```

---

## 🔒 Application Security & SSRF Protection

1. **Strict SSRF Boundary:** Prohibits connections to RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (`127.0.0.0/8`), cloud metadata (`169.254.169.254`), and multicast ranges.
2. **DNS Pre-Validation:** Hostnames are resolved before HTTP connections are opened to thwart DNS rebinding attacks.
3. **Safe In-Memory File Hashing:** Uploaded files are streamed in 64KB chunks in memory to compute hashes. Files are never marked executable and never executed.
4. **Parameterized Queries:** Enforced via SQLAlchemy ORM to prevent SQL injection.
5. **No Secret Leaks:** API keys reside in `.env` and are strictly excluded from API responses and frontend code.

---

## ⚠️ Known Limitations
1. **Free Tier Rate Limits:** Commercial APIs (VirusTotal free tier is 4 requests/min; AbuseIPDB is 20/min) will throttle excessive concurrent requests. The platform handles this via a token-bucket rate limiter and TTL caching.
2. **Dynamic DNS / Fast Flux:** Threat actors rotating DNS records frequently may show different A records across lookups.
3. **WHOIS RDAP Availability:** Certain ccTLDs (country code top-level domains) have rate-limited or non-standard RDAP gateways.
4. **AI/ML Heuristics Disclaimer:** Machine learning predictions are probabilistic triage aids and must not be cited as confirmed malicious findings without independent verification.

---

## 🔮 Future Roadmap & Improvements
- [ ] STIX 2.1 / TAXII Feed Export and automated ingest.
- [ ] MISP (Malware Information Sharing Platform) integration adapter.
- [ ] Dynamic sandbox integration (Cuckoo / CAPE Sandbox API) for behavioral detonation.
- [ ] OAuth2 / SAML single sign-on with role-based access control (RBAC) for SOC teams.
- [ ] Automated Slack / Microsoft Teams incident response webhooks.

---

## 📜 License
This project is open-source and intended for cybersecurity research, education, and defensive operations.
