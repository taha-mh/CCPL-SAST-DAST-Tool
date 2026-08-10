# 🛡️ Phase 2 DAST Pipeline Implementation Plan (Refined Architecture)

## 📌 Executive Summary
Phase 2 extends the CCPL Web Security Assessment Tool with **Dynamic Application Security Testing (DAST)** capabilities. The DAST pipeline automates live HTTP security scanning against target web applications (DVWA) using OWASP ZAP 2.17.0, normalizes live HTTP evidence into a domain-accurate DAST schema, evaluates exploitability via our **Shared Local Dual-Pass AI Engine** (Ollama `qwen3.5:9b`), and presents results via our responsive Web Dashboard UI and HTML/Markdown reports.

---

## 🏗️ Refined Architecture & Key Principles

### 1. The Core Architectural Philosophy
> *"Don't duplicate the LLM engine, but don't force DAST to pretend it's SAST either."*

* **Domain-Specific Normalization (Keep Separate)**:  
  `parsers/semgrep_normalizer.py` and `parsers/dast_normalizer.py` remain separate. DAST preserves HTTP-native fields (`target`, `http_method`, `parameter`, `payload`, `scanner_risk`, `scanner_confidence`) without creating fake source code fields like `file_path` or `start_line`.
* **Common Conceptual Abstraction (Keep Shared)**:  
  Both SAST and DAST normalize into a common conceptual interface consumed by the LLM Engine:
  - `finding_id`
  - Vulnerability metadata (`vulnerability_type` / `title`)
  - Severity metadata (`scanner_severity` / `scanner_risk` / `scanner_confidence`)
  - Evidence Context (`evidence_context` string)
* **Unified Field Aliasing (`evidence_context`)**:  
  The shared LLM Engine (`llm/assessor.py`, `llm/reviewer.py`, `app.js`) accepts `evidence_context` (DAST live HTTP evidence block) with fallback to `code_context` (SAST source code lines) to ensure 100% backward compatibility.

---

## 📐 System Flow Diagram

```text
               ┌── Semgrep Normalizer ──┐
               │                        │
SAST ──────────┤                        ├─► Source Context ──┐
               │                        │                    │
               └── Source Context ──────┘                    │
                                                             ▼
                                                    Common Finding
                                                             │
               ┌── ZAP Normalizer ──────┐                    ▼
               │                        │              LLM Assessor
DAST ──────────┤                        ├─► HTTP Evidence ───┤
               │                        │                    ▼
               └── HTTP Evidence ───────┘              LLM Reviewer
                                                             │
                                                             ▼
                                                     Report Generator
```

---

## 🛠️ Step-by-Step Implementation Breakdown

### Step 1: DAST Scanner Runner (`scanners/dast_runner.py`) [STATUS: COMPLETED ✅]
- **File**: [scanners/dast_runner.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/scanners/dast_runner.py)
- **Features**:
  - OWASP ZAP API daemon client integration via `python-owasp-zap-v2.4`.
  - Background daemon auto-launcher (`ensure_zap_daemon_started`) running `zap.bat -daemon -port 8080`.
  - Automated session login & cookie injection (`get_authenticated_session_cookie`).
  - Spider crawl & Active Scan execution saving raw findings to `data/raw/dast_findings.json`.

---

### Step 2: DAST Normalizer (`parsers/dast_normalizer.py`) [STATUS: COMPLETED ✅]
- **File**: [parsers/dast_normalizer.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/parsers/dast_normalizer.py)
- **Features**:
  - Reads raw ZAP findings from `data/raw/dast_findings.json`.
  - Preserves ZAP native risk & confidence fields (`scanner_risk`, `scanner_confidence`, `scanner_severity`).
  - Formats HTTP Method, Parameter, Attack Payload, and Response Evidence into `evidence_context`.
  - Outputs to `data/normalized/dast_normalized.json`.

---

### Step 3: Shared Dual-Pass LLM Engine Refinement (`llm/assessor.py` & `llm/reviewer.py`) [STATUS: IN PROGRESS ⏳]
- **Files**: [prompts/assessor_prompt.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/prompts/assessor_prompt.py), [llm/assessor.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/llm/assessor.py), [llm/reviewer.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/llm/reviewer.py)
- **Features**:
  - Update `prompts/assessor_prompt.py` & `prompts/reviewer_prompt.py` to instruct Qwen 3.5 9B on how to analyze both SAST source code context and DAST HTTP live evidence.
  - Make `llm/assessor.py` accept `finding.get("evidence_context") or finding.get("code_context")`.
  - Evaluate DAST findings and output to `data/normalized/dast_assessed.json` and `data/normalized/dast_reviewed.json`.

---

### Step 4: Security Report Generator (`reports/report_generator.py`) [STATUS: PENDING ⏹️]
- **File**: [reports/report_generator.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/reports/report_generator.py)
- **Features**:
  - Accepts both SAST and DAST reviewed findings.
  - Generates standalone `dast_report.html` and `dast_report.md`.
  - Displays Executive Summary table and False-Positive Audit Log.

---

### Step 5: Web Dashboard & FastAPI Integration (`main.py` & `frontend/`) [STATUS: PENDING ⏹️]
- **Files**: [main.py](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/main.py), [frontend/index.html](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/frontend/index.html), [frontend/app.js](file:///c:/Users/Administrator/Desktop/CCPL-Project/CCPL-SAST-DAST-Tool/frontend/app.js)
- **Features**:
  - Add request payload option `{"pipeline": "web_dast"}` to `/api/scan`.
  - Stream real-time DAST pipeline log events over SSE (`/api/scan/stream`).
  - Update UI card renderer in `app.js` to check `finding.evidence_context || finding.code_context`.

---

## 🧪 Verification & Acceptance Plan

1. **Normalizer Check**:
   - Verify `dast_normalizer.py` outputs `evidence_context`, `scanner_risk`, and `scanner_confidence`.
2. **Shared LLM Engine Check**:
   - Execute `python llm/assessor.py` on `data/normalized/dast_normalized.json` and verify Qwen 3.5 9B's evaluation of live HTTP evidence.
3. **End-to-End System Check**:
   - Run full DAST scan from Web Dashboard (`http://localhost:8000`), stream real-time logs, view rendered UI cards, and download HTML security reports.
