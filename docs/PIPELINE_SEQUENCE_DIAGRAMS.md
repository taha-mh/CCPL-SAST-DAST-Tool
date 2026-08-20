# 🔄 CCPL SAST & DAST Phase-Wise Execution Sequence Diagrams

This document contains step-by-step Mermaid sequence diagrams showing the exact execution flow for Phase 1 and Phase 2. These render natively on GitHub.

---

## 🛡️ 1. Phase 1 Execution Sequence Diagram (Web SAST & Local Ollama)

Shows how a Web SAST scan executes step-by-step from trigger to HTML report generation.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Security Engineer
    participant UI as Dashboard UI (frontend/)
    participant App as FastAPI App (main.py)
    participant Scanner as Semgrep Runner (scanners/semgrep_runner.py)
    participant Norm as SAST Normalizer (parsers/semgrep_normalizer.py)
    participant Context as Source Context Extractor (parsers/source_context.py)
    participant Ollama as Local Ollama LLM (Qwen3 Model)
    participant Report as Report Generator (reports/report_generator.py)

    User->>UI: Selects "Web SAST" & clicks "Start Scan Pipeline"
    UI->>App: POST /api/scan (target_name, max_findings, include_pattern)
    App->>Scanner: 1. Run Semgrep CLI on target source code (*.php)
    Scanner-->>App: Raw findings JSON saved (data/raw/semgrep_findings.json)
    App->>Norm: 2. Normalize raw findings into unified schema
    Norm-->>App: Normalized JSON (data/normalized/normalized_findings.json)
    App->>Context: 3. Extract surrounding source code (+/- 10 lines)
    Context-->>App: Enriched findings with code context
    App->>Ollama: 4. Pass 1: Assessor evaluates risk & plausibility
    Ollama-->>App: Assessment result (llm_assessment)
    App->>Ollama: 5. Pass 2: Reviewer performs second logical audit
    Ollama-->>App: Reviewed result (llm_review)
    App->>Report: 6. Build HTML & Markdown security reports
    Report-->>App: sast_report.html & sast_report.md generated
    App-->>UI: Scan result JSON payload
    UI-->>User: Renders summary stats & report download actions
```

---

## 🌐 2. Phase 2 Execution Sequence Diagram (Web DAST + ZAP + OpenAI API + Routers)

Shows how a Web DAST scan executes step-by-step with 0-network-call ZAP evidence parsing, central OpenAI provider, and real-time SSE log streaming.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Security Engineer
    participant UI as Dashboard UI (frontend/)
    participant Router as Scan Router (routers/scan.py)
    participant ZAP as OWASP ZAP Daemon (scanners/dast_runner.py)
    participant Target as DVWA Target Web App (127.0.0.1:8085)
    participant Norm as Zero-Network Normalizer (parsers/dast_normalizer.py)
    participant Provider as Central LLM Provider (llm/provider.py)
    participant Report as Report Generator (reports/report_generator.py)

    User->>UI: Selects "Web DAST" & clicks "Start Scan Pipeline"
    UI->>Router: GET /api/scan/stream (EventSource connection)
    Router-->>UI: EventSource connected (stream log events + keep-alive)
    
    rect rgb(239, 246, 255)
        note over Router,Target: Step 1: Automated ZAP DAST Scanning
        Router->>ZAP: Ensure ZAP daemon running on port 8080
        ZAP->>Target: POST /login.php (Harvest PHPSESSID cookie)
        ZAP->>ZAP: Inject PHPSESSID into ZAP replacer rules
        ZAP->>Target: Execute active DAST spider & attack scan
        Target-->>ZAP: HTTP response headers & alerts captured
    end

    rect rgb(254, 252, 232)
        note over Router,Norm: Step 2 & 3: Zero-Network Evidence Parsing
        Router->>Norm: Retrieve alert message IDs via zap.core.message(id)
        Norm->>Norm: Parse captured HTTP response headers in-memory (18ms)
        Norm-->>Router: Enriched DAST findings with actual HTTP evidence
    end

    rect rgb(236, 253, 245)
        note over Router,Provider: Step 4 & 5: Dual-Pass OpenAI Reasoning
        Router->>Provider: Pass 1: AI Assessor (gpt-5.4-nano in JSON mode)
        Provider-->>Router: Assessment result (plausibility, remediation)
        Router->>Provider: Pass 2: Senior Reviewer Audit (3-state decision)
        Provider-->>Router: Verdict (confirmed / rejected / needs_review)
    end

    Router->>Report: Step 6: Build 3-State HTML & Markdown reports
    Report-->>Router: sast_report.html & sast_report.md generated
    Router-->>UI: Final result JSON & SSE close event
    UI-->>User: Displays 4 interactive stat cards & report download actions
```
