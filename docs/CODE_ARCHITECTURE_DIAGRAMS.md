# 🎨 CCPL Web SAST Code & Data Flow Architecture Diagrams

This document provides visual diagrams and detailed data-flow maps to help developers and reviewers understand the inner workings of the CCPL Web SAST pipeline.

---

## 1. 🔄 Complete End-to-End System Sequence Diagram

This sequence diagram shows how a scan request triggered on the **Frontend Web UI** flows through the **FastAPI Orchestrator**, executes each pipeline step, streams real-time logs via Server-Sent Events (SSE), and renders final results.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Frontend (app.js)
    participant API as FastAPI (main.py)
    participant Semgrep as Scanner (semgrep_runner.py)
    participant Norm as Normalizer (semgrep_normalizer.py)
    participant Ctx as Context (source_context.py)
    participant LLM1 as AI Assessor (assessor.py)
    participant LLM2 as AI Reviewer (reviewer.py)
    participant Rep as Report (report_generator.py)

    User->>UI: Select Target (DVWA) & Click "Start SAST Scan"
    UI->>API: GET /api/scan/stream?target_name=DVWA
    API-->>UI: Establish SSE Stream (EventSource)

    API->>Semgrep: run_semgrep_scan(target_dir, include_pattern="*.php")
    Semgrep-->>API: raw findings (data/raw/semgrep_findings.json)
    API-->>UI: SSE Log: "Step 1 Complete: 68 raw findings"

    API->>Norm: normalize_semgrep_findings()
    Norm-->>API: normalized schema (data/normalized/normalized_findings.json)
    API-->>UI: SSE Log: "Step 2 Complete: Normalized 68 findings"

    API->>Ctx: extract_source_context()
    Ctx-->>API: attached ±10 lines context (findings_with_context.json)
    API-->>UI: SSE Log: "Step 3 Complete: Attached code context"

    loop For each finding
        API->>LLM1: query_ollama(ASSESSOR_PROMPT, finding + code_context)
        LLM1-->>API: returns llm_assessment {is_plausible, reasoning, remediation}
        API-->>UI: Keep-Alive Heartbeat Ping (: keep-alive)
    end
    API-->>UI: SSE Log: "Step 4 Complete: Pass 1 Evaluated findings"

    loop For each assessed finding
        API->>LLM2: query_ollama(REVIEWER_PROMPT, finding + Pass 1 reasoning)
        LLM2-->>API: returns llm_review {decision: "confirmed"|"rejected", review_reason}
        API-->>UI: Keep-Alive Heartbeat Ping (: keep-alive)
    end
    API-->>UI: SSE Log: "Step 5 Complete: Pass 2 Reviewer completed audit"

    API->>Rep: run_report_generator()
    Rep-->>API: sast_report.html & sast_report.md
    API-->>UI: SSE Log: "Step 6 Complete: HTML & MD Reports Generated"

    API-->>UI: SSE Final Result Payload (metrics, reviewed_findings, report_urls)
    UI->>User: Render Metric Cards, Interactive Filter Tabs, & Download Links
```

---

## 2. 🧠 2-Pass Dual-Agent AI Reasoning Architecture

This flowchart illustrates how **Pass 1 AI Assessor** and **Pass 2 AI Senior Reviewer** work together to eliminate false positives.

```mermaid
flowchart TD
    A["📄 Flagged Finding + ±10 Lines Source Context"] --> B{"🤖 Pass 1: AI Assessor (qwen3:8b)"}
    
    B -->|"Prompt: Is this vulnerability plausible in surrounding code?"| C["Pass 1 Verdict: is_plausible & Reasoning"]
    
    C --> D{"🛡️ Pass 2: AI Senior Reviewer (qwen3:8b)"}
    
    D -->|"Audit: Does Pass 1 reasoning hold up to senior security inspection?"| E{"Final Verdict Decision"}
    
    E -->|"decision == 'confirmed'"| F["🚨 CONFIRMED RISK\n(Appears in Confirmed Tab & Report Section 1)"]
    E -->|"decision == 'rejected'"| G["🛡️ DISCARDED FALSE POSITIVE\n(Appears in Discarded Tab & Report Section 2)"]

    style A fill:#eff6ff,stroke:#1d4ed8,stroke-width:2px;
    style B fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px;
    style D fill:#fef3c7,stroke:#d97706,stroke-width:2px;
    style F fill:#fef2f2,stroke:#dc2626,stroke-width:2px;
    style G fill:#ecfdf5,stroke:#059669,stroke-width:2px;
```

---

## 3. 📊 Step-by-Step Data Transformation Pipeline

This diagram shows how data schema transforms at every milestone step in the project.

```mermaid
graph LR
    subgraph Step 1: Scanner
        RAW["Raw Semgrep JSON\n(Semgrep rules format)"]
    end

    subgraph Step 2: Normalizer
        NORM["Normalized JSON\n(finding_id, rule_id, file_path, lines)"]
    end

    subgraph Step 3: Context
        CTX["Context JSON\n(attached code_context ±10 lines)"]
    end

    subgraph Step 4: Pass 1 AI
        ASSESSED["Assessed JSON\n(attached llm_assessment object)"]
    end

    subgraph Step 5: Pass 2 AI
        REVIEWED["Reviewed JSON\n(attached llm_review decision object)"]
    end

    subgraph Step 6: Reports
        OUTPUT["HTML & MD Reports\n(Executive Table + Confirmed + Discarded Log)"]
    end

    RAW --> NORM --> CTX --> ASSESSED --> REVIEWED --> OUTPUT
```

---

## 💡 Quick Reference Summary for Presentations

| Step | Module File | Input | Main Function | Output |
| :--- | :--- | :--- | :--- | :--- |
| **1. Scanner** | `scanners/semgrep_runner.py` | Target Directory (`targets/DVWA`) | Runs Semgrep CLI with `*.php` filter | `data/raw/semgrep_findings.json` |
| **2. Normalizer** | `parsers/semgrep_normalizer.py` | Raw Semgrep JSON | Maps rules to unified schema | `data/normalized/normalized_findings.json` |
| **3. Context** | `parsers/source_context.py` | Normalized JSON | Reads surrounding ±10 lines of source code | `data/normalized/findings_with_context.json` |
| **4. Assessor** | `llm/assessor.py` | Context JSON | Prompts Qwen3 8B for initial plausibility | `data/normalized/assessed_findings.json` |
| **5. Reviewer** | `llm/reviewer.py` | Assessed JSON | Audits Pass 1 verdict for FP elimination | `data/normalized/reviewed_findings.json` |
| **6. Reports** | `reports/report_generator.py` | Reviewed JSON | Generates standalone HTML & MD reports | `reports/sast_report.html` & `.md` |
| **Server** | `main.py` | Web API Request | FastAPI SSE log streaming & orchestrator | Real-Time Log Stream to Browser |
