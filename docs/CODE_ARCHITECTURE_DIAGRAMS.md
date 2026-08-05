# 🎨 CCPL Web SAST Architecture & Data Flow Diagrams

This document provides visual diagrams to help developers and reviewers understand the CCPL Web SAST pipeline.

---

## 1. 🔄 System Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Web UI
    participant API as FastAPI
    participant Scanner
    participant Normalizer
    participant Context
    participant Assessor as AI Assessor
    participant Reviewer as AI Reviewer
    participant Report

    User->>UI: Click "Start SAST Scan"
    UI->>API: GET /api/scan/stream
    API-->>UI: Connect SSE Stream

    API->>Scanner: Run Semgrep (*.php)
    Scanner-->>API: Raw Findings JSON
    API-->>UI: SSE: Step 1 Complete

    API->>Normalizer: Normalize Schema
    Normalizer-->>API: Unified Findings JSON
    API-->>UI: SSE: Step 2 Complete

    API->>Context: Extract ±10 Lines
    Context-->>API: Findings with Code Context
    API-->>UI: SSE: Step 3 Complete

    loop Pass 1 AI Assessment
        API->>Assessor: Query Qwen3 8B
        Assessor-->>API: Returns is_plausible
        API-->>UI: Keep-Alive Beat
    end
    API-->>UI: SSE: Step 4 Complete

    loop Pass 2 Senior Audit
        API->>Reviewer: Query Audit Verdict
        Reviewer-->>API: Returns decision (confirmed/rejected)
        API-->>UI: Keep-Alive Beat
    end
    API-->>UI: SSE: Step 5 Complete

    API->>Report: Generate HTML & MD
    Report-->>API: sast_report.html & .md
    API-->>UI: SSE: Step 6 Complete

    API-->>UI: Final Payload (Metrics & Cards)
    UI->>User: Display Metrics, Tabs & Reports
```

---

## 2. 🧠 2-Pass Dual-Agent AI Reasoning Flowchart

```mermaid
flowchart TD
    A["📄 Flagged Finding<br/>+ Code Context"] --> B["🤖 Pass 1: AI Assessor<br/>(qwen3:8b)"]
    
    B -->|"Is vulnerability plausible?"| C["Pass 1 Verdict & Reasoning"]
    
    C --> D["🛡️ Pass 2: AI Senior Reviewer<br/>(qwen3:8b)"]
    
    D -->|"Audit Pass 1 Reasoning"| E{"Final Verdict"}
    
    E -->|"decision: confirmed"| F["🚨 CONFIRMED RISK<br/>(Section 1 & Confirmed Tab)"]
    E -->|"decision: rejected"| G["🛡️ DISCARDED FALSE POSITIVE<br/>(Section 2 & Discarded Tab)"]

    style A fill:#eff6ff,stroke:#1d4ed8,stroke-width:2px,color:#0f172a;
    style B fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#0f172a;
    style C fill:#f1f5f9,stroke:#64748b,stroke-width:2px,color:#0f172a;
    style D fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#0f172a;
    style E fill:#f3e8ff,stroke:#7c3aed,stroke-width:2px,color:#0f172a;
    style F fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#991b1b;
    style G fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#065f46;
```

---

## 3. 📊 Step-by-Step Data Transformation Pipeline

```mermaid
graph LR
    subgraph Step 1
        RAW["Raw Semgrep JSON"]
    end

    subgraph Step 2
        NORM["Normalized JSON"]
    end

    subgraph Step 3
        CTX["Context JSON"]
    end

    subgraph Step 4
        ASSESSED["Assessed JSON"]
    end

    subgraph Step 5
        REVIEWED["Reviewed JSON"]
    end

    subgraph Step 6
        OUTPUT["HTML & MD Reports"]
    end

    RAW --> NORM --> CTX --> ASSESSED --> REVIEWED --> OUTPUT

    style RAW fill:#f1f5f9,stroke:#64748b,color:#0f172a;
    style NORM fill:#eff6ff,stroke:#1d4ed8,color:#0f172a;
    style CTX fill:#e0e7ff,stroke:#4f46e5,color:#0f172a;
    style ASSESSED fill:#fef3c7,stroke:#d97706,color:#0f172a;
    style REVIEWED fill:#ecfdf5,stroke:#059669,color:#0f172a;
    style OUTPUT fill:#fef2f2,stroke:#dc2626,color:#991b1b;
```

---

## 💡 Quick Reference Summary

| Step | Module File | Main Function | Purpose |
| :--- | :--- | :--- | :--- |
| **1. Scanner** | `scanners/semgrep_runner.py` | `run_semgrep_scan()` | Runs Semgrep CLI on `targets/DVWA` (`*.php`) |
| **2. Normalizer** | `parsers/semgrep_normalizer.py` | `normalize_semgrep_findings()` | Maps raw Semgrep rules to clean JSON schema |
| **3. Context** | `parsers/source_context.py` | `extract_source_context()` | Extracts ±10 lines of surrounding code |
| **4. Assessor** | `llm/assessor.py` | `run_llm_assessor()` | Prompts Qwen3 8B for initial plausibility |
| **5. Reviewer** | `llm/reviewer.py` | `run_llm_reviewer()` | Audits Pass 1 verdict for FP elimination |
| **6. Reports** | `reports/report_generator.py` | `run_report_generator()` | Generates standalone HTML & MD reports |
| **Server** | `main.py` | `stream_sast_scan()` | FastAPI SSE log streaming & orchestrator |
