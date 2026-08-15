# REST API Documentation & Specification

**Cyber Threat Intelligence (CTI) Analysis Platform**  
*FastAPI Version 1.0.0 | OpenAPI Specification 3.1.0*

Interactive documentation is available at runtime:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **Health Check:** `GET http://localhost:8000/health`

---

## 1. Authentication & Security
- **API Keys for Providers:** Stored server-side in `.env`. Never exposed in API responses.
- **SSRF Prevention:** Enforced on outbound probe requests (`/api/v1/analyze/url`). Calls targeting private/link-local addresses are rejected with HTTP 403.
- **CORS:** Enabled for cross-origin client integration.

---

## 2. API Endpoints Overview

### A. Core IOC Analysis (`/api/v1/analyze`)

#### `POST /api/v1/analyze`
Auto-detects IOC type (IP, Domain, URL, Hash) and executes multi-source threat intelligence.
- **Request Body:**
  ```json
  {
    "indicator": "194.26.29.112",
    "use_cache": true,
    "ai_analysis": true
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "indicator": "194.26.29.112",
    "normalized": "194.26.29.112",
    "defanged": "194[.]26[.]29[.]112",
    "indicator_type": "IP",
    "timestamp": "2026-11-08T00:00:00Z",
    "risk_assessment": {
      "risk_score": 95.0,
      "risk_category": "CRITICAL",
      "confidence_score": 92.0,
      "threat_classification": "COMMAND_AND_CONTROL",
      "explanations": [
        {
          "factor": "Known Bulletproof C2",
          "points_impact": 50.0,
          "evidence": "Confirmed Cobalt Strike listener infrastructure",
          "source": "Local Threat KnowledgeBase"
        }
      ],
      "recommended_actions": [
        "Block IP immediately at perimeter firewalls and edge WAF.",
        "Search internal SIEM/NetFlow logs for outbound sessions."
      ],
      "weights_used": {
        "reputation": 0.35,
        "heuristics": 0.25,
        "community": 0.25,
        "ai_ml": 0.15
      }
    },
    "ai_insights": {
      "threat_summary": "### Threat Intelligence Assessment...",
      "anomalies_detected": [],
      "disclaimer": "AI/ML predictions are heuristic indicators..."
    },
    "provider_results": [],
    "module_details": {},
    "correlation_graph": { "nodes": [], "edges": [] },
    "investigation_id": 1
  }
  ```

#### `POST /api/v1/analyze/ip`
Explicitly analyzes an IPv4 or IPv6 address.

#### `POST /api/v1/analyze/domain`
Explicitly analyzes a domain, executing DNS resolution (A, AAAA, MX, NS, TXT, CNAME) and DGA evaluation.

#### `POST /api/v1/analyze/url`
Probes a URL using SSRF-safe HTTP HEAD requests and phishing lexical analysis.

#### `POST /api/v1/analyze/hash`
Validates and inspects an MD5, SHA-1, or SHA-256 hash.

#### `POST /api/v1/analyze/upload-file`
Multipart form upload (`file`). Streams bytes in memory, calculates MD5, SHA-1, and SHA-256 hashes, detects magic byte MIME type, and analyzes the artifact without execution.

---

### B. Extraction & Defanging (`/api/v1/extract`)

#### `POST /api/v1/extract`
Extracts and normalizes all indicators from raw unstructured text.
- **Request Body:**
  ```json
  {
    "text": "Threat bulletin: C2 at hxxp://evil-site[.]com/drop[.]exe and IP 185.220.101.5"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "total_found": 2,
    "ips": [{ "raw": "185.220.101.5", "normalized": "185.220.101.5", "defanged": "185[.]220[.]101[.]5", "type": "IP", "version": "IPv4" }],
    "urls": [{ "raw": "http://evil-site.com/drop.exe", "normalized": "http://evil-site.com/drop.exe", "defanged": "hxxp://evil-site[.]com/drop[.]exe", "type": "URL" }],
    "domains": [],
    "hashes": []
  }
  ```

#### `POST /api/v1/extract/defang`
Toggles defanging on a single indicator.

---

### C. Batch Analysis (`/api/v1/batch`)

#### `POST /api/v1/batch`
Bulk analysis for up to 50 indicators.
- **Request Body:**
  ```json
  {
    "indicators": ["194.26.29.112", "malicious-payload-cdn.net"],
    "use_cache": true
  }
  ```

#### `POST /api/v1/batch/upload`
Upload CSV or TXT file for bulk indicator extraction and triage.

---

### D. Correlation Graph (`/api/v1/correlate`)

#### `GET /api/v1/correlate/{ioc_value}`
Retrieves NetworkX directional graph schema (nodes and edges) for an indicator.

---

### E. Investigation History (`/api/v1/history`)

#### `GET /api/v1/history`
Query parameters:
- `query`: Text search in indicator value or notes
- `ioc_type`: `IP`, `DOMAIN`, `URL`, or `HASH`
- `risk_category`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
- `limit`: Default `50`, max `100`
- `offset`: Pagination offset

#### `GET /api/v1/history/{ioc_id}`
Returns all historical provider analysis snapshots and discovered relationships for an indicator.

#### `DELETE /api/v1/history/{ioc_id}`
Deletes an investigation record from the database.

---

### F. Threat Reports (`/api/v1/reports`)

#### `POST /api/v1/reports/generate`
- **Request Body:**
  ```json
  {
    "indicators": ["194.26.29.112", "malicious-payload-cdn.net"],
    "report_type": "PDF",
    "title": "Incident Triage Assessment"
  }
  ```
- **Response `200 OK`:** Returns `report_id` and `download_url`.

#### `GET /api/v1/reports/{report_id}/download`
Streams and downloads the PDF, JSON, or CSV report file.

---

### G. Threat Monitoring (`/api/v1/monitor`)

#### `GET /api/v1/monitor/watchlist`
Lists all active monitored indicators with current and baseline risk scores.

#### `POST /api/v1/monitor/add`
Adds an indicator to the watchlist (`{"indicator": "194.26.29.112"}`).

#### `POST /api/v1/monitor/check-now`
Forces a re-evaluation of all monitored items and returns detected score deltas.

---

### H. Configuration & Settings (`/api/v1/config`)

#### `GET /api/v1/config/providers`
Returns provider statuses, rate limits, and supported indicator types without leaking API keys.

#### `GET /api/v1/config/weights`
Returns current scoring weights and methodology ranges.

#### `POST /api/v1/config/weights`
Updates scoring weights (`weight_reputation`, `weight_heuristics`, `weight_community`, `weight_ai_ml`).
