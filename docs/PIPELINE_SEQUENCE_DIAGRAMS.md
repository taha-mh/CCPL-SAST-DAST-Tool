# 🔄 CCPL SAST & DAST Pipeline Sequence Diagrams

This document contains step-by-step Mermaid sequence diagrams illustrating the end-to-end execution flow for both Phase 1 (Web SAST) and Phase 2 (Web DAST). These diagrams render natively on GitHub.

---

## 🛡️ 1. Phase 1 Sequence Diagram: Web SAST Pipeline

Shows the static code analysis execution flow from user trigger on the frontend dashboard to report generation.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Security Analyst
    participant Frontend as Frontend / Dashboard UI
    participant FastAPI as FastAPI Server (main.py)
    participant Semgrep as Semgrep Scanner (scanners/semgrep_runner.py)
    participant SASTNorm as SAST Normalizer & Context (parsers/)
    participant Assessor as AI Assessor (llm/assessor.py)
    participant Provider as Central LLM Provider (llm/provider.py)
    participant OpenAI as OpenAI API (gpt-5.4-nano)
    participant Reviewer as AI Reviewer (llm/reviewer.py)
    participant Report as Report Generator (reports/report_generator.py)

    User->>Frontend: Selects "Web SAST" & clicks "Start Scan Pipeline"
    Frontend->>FastAPI: POST /api/scan (pipeline="web_sast", target="DVWA")
    FastAPI->>Semgrep: 1. Run Semgrep CLI on target source code (*.php)
    Semgrep-->>FastAPI: Raw findings JSON (data/raw/semgrep_findings.json)
    FastAPI->>SASTNorm: 2. Normalize raw findings & extract source code context (+/- 10 lines)
    SASTNorm-->>FastAPI: Common Finding Format with source evidence
    FastAPI->>Assessor: 3. Evaluate finding plausibility & initial risk
    Assessor->>Provider: query_llm(ASSESSOR_SYSTEM_PROMPT, prompt)
    Provider->>OpenAI: POST /v1/chat/completions (JSON mode)
    OpenAI-->>Provider: Assessment JSON response
    Provider-->>Assessor: Structured assessment payload
    Assessor-->>FastAPI: Assessed findings (data/normalized/assessed_findings.json)
    FastAPI->>Reviewer: 4. Perform second-pass audit on assessment
    Reviewer->>Provider: query_llm(REVIEWER_SYSTEM_PROMPT, prompt)
    Provider->>OpenAI: POST /v1/chat/completions (JSON mode)
    OpenAI-->>Provider: Review JSON response
    Provider-->>Reviewer: Final verdict payload
    Reviewer-->>FastAPI: Reviewed findings (data/normalized/reviewed_findings.json)
    FastAPI->>Report: 5. Generate HTML & Markdown reports
    Report-->>FastAPI: reports/sast_report.html & reports/sast_report.md
    FastAPI-->>Frontend: Returns scan results & log events
    Frontend-->>User: Displays summary metric cards & report download links
```

*Historical Note*: Phase 1 initial prototyping used local Ollama (`qwen3:8b`) before the AI provider communication was decoupled into `llm/provider.py` and connected to OpenAI API (`gpt-5.4-nano`) in Phase 2.

---

## 🌐 2. Phase 2 Sequence Diagram: Web DAST Pipeline

Shows the dynamic HTTP security testing flow, highlighting zero-secondary-network evidence extraction from OWASP ZAP, central LLM provider query, 3-state verdict auditing, and real-time SSE streaming.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Security Analyst
    participant Frontend as Frontend / Dashboard UI
    participant FastAPI as Scan Router (routers/scan.py)
    participant DASTRunner as DAST Runner (scanners/dast_runner.py)
    participant ZAP as OWASP ZAP Daemon (Port 8080)
    participant Target as DVWA Target App (127.0.0.1:8085)
    participant DASTNorm as DAST Normalizer (parsers/dast_normalizer.py)
    participant Assessor as AI Assessor (llm/assessor.py)
    participant Provider as Central LLM Provider (llm/provider.py)
    participant OpenAI as OpenAI API (gpt-5.4-nano)
    participant Reviewer as AI Reviewer (llm/reviewer.py)
    participant Report as Report Generator (reports/report_generator.py)

    User->>Frontend: Selects "Web DAST" & clicks "Start Scan Pipeline"
    Frontend->>FastAPI: GET /api/scan/stream?pipeline=web_dast (SSE Stream)
    FastAPI-->>Frontend: SSE EventSource connection established (real-time logs)

    FastAPI->>DASTRunner: 1. Launch DAST Scan on http://127.0.0.1:8085
    DASTRunner->>ZAP: Ensure ZAP daemon running (port 8080)
    DASTRunner->>Target: Authenticate to /login.php & harvest PHPSESSID cookie
    DASTRunner->>ZAP: Inject PHPSESSID into ZAP replacer rules
    DASTRunner->>Target: Execute active DAST spider & attack scan
    Target-->>ZAP: HTTP response headers & alerts captured in ZAP memory

    FastAPI->>DASTNorm: 2. Normalize raw DAST alerts using captured evidence
    DASTNorm->>ZAP: Fetch captured HTTP message via zap.core.message(message_id)
    ZAP-->>DASTNorm: Raw captured HTTP response headers
    DASTNorm->>DASTNorm: Extract response headers directly from ZAP evidence (0 network calls to DVWA)
    DASTNorm-->>FastAPI: Common Finding Format with HTTP evidence (data/normalized/dast_normalized.json)

    FastAPI->>Assessor: 3. Pass 1: Evaluate risk & plausibility
    Assessor->>Provider: query_llm(ASSESSOR_SYSTEM_PROMPT, prompt)
    Provider->>OpenAI: POST /v1/chat/completions (JSON mode)
    OpenAI-->>Provider: Assessment JSON response
    Provider-->>Assessor: Structured assessment payload
    Assessor-->>FastAPI: Assessed DAST findings (data/normalized/dast_assessed.json)

    FastAPI->>Reviewer: 4. Pass 2: Audit assessment & issue final verdict
    Reviewer->>Provider: query_llm(REVIEWER_SYSTEM_PROMPT, prompt)
    Provider->>OpenAI: POST /v1/chat/completions (JSON mode)
    OpenAI-->>Provider: Review JSON response
    Provider-->>Reviewer: 3-State Verdict (confirmed / rejected / needs_review)
    Reviewer-->>FastAPI: Reviewed DAST findings (data/normalized/dast_reviewed.json)

    FastAPI->>Report: 5. Generate HTML & Markdown reports
    Report-->>FastAPI: reports/sast_report.html & reports/sast_report.md
    FastAPI-->>Frontend: Stream final result JSON & close SSE stream
    Frontend-->>User: Displays 4 clickable metric cards & report download links
```

---

## 📌 Architectural Summary of Key Points

1. **Frontend Layer Integration**: The User interacts exclusively with `Frontend / Dashboard UI` (`frontend/index.html` & `app.js`), which communicates with the backend `FastAPI Server` via REST endpoints (`/api/scan`) and EventSource streams (`/api/scan/stream`).
2. **Zero Secondary Network Requests**: The DAST normalizer retrieves HTTP response headers directly from ZAP's captured evidence (`zap.core.message(id)`). It does NOT issue secondary HTTP requests (`requests.get()` / `requests.head()`) to the target application.
3. **Common Finding Format**: Both SAST and DAST findings are converted into a unified JSON finding structure before entering the AI pipeline:
   - **SAST Evidence**: Source code context snippet (`code_context`).
   - **DAST Evidence**: HTTP request/response header context (`evidence_context`).
4. **Centralized LLM Provider**: Both `llm/assessor.py` (Pass 1) and `llm/reviewer.py` (Pass 2) query `llm/provider.py` (`query_llm()`), which manages communication with OpenAI API (`gpt-5.4-nano`).
5. **Report Artifact Paths**: Generated report files are saved to `reports/sast_report.html` and `reports/sast_report.md`, which are served via `routers/reports.py`.
