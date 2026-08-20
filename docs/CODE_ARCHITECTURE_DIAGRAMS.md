# 📊 CCPL SAST & DAST Architecture & Flowchart Diagrams

This document contains visual Mermaid architecture diagrams and pipeline flowcharts for both Phase 1 and Phase 2. These diagrams render automatically on GitHub.

---

## 🛡️ 1. Phase 1 Architecture (Web SAST & Local Ollama Prototype)

```mermaid
flowchart TD
    subgraph Target["Source Code Target"]
        A["DVWA PHP Source Code"]
    end

    subgraph Step1["Step 1: Scanner"]
        B["Semgrep CLI (*.php filter)"]
        A --> B
        B --> C["data/raw/semgrep_findings.json"]
    end

    subgraph Step23["Step 2 & 3: Normalization & Context"]
        C --> D["Semgrep Normalizer"]
        D --> E["Source Code Context Extractor (+/- 10 lines)"]
        E --> F["data/normalized/findings_with_context.json"]
    end

    subgraph Step4["Step 4: Local Ollama Dual-Pass AI"]
        F --> G["Pass 1: AI Assessor (Local Ollama Qwen3)"]
        G --> H["Pass 2: AI Reviewer (Local Ollama Qwen3)"]
        H --> I["reviewed_findings.json"]
    end

    subgraph Step56["Step 5 & 6: Reporting & Web Layer"]
        I --> J["Report Generator"]
        J --> K["sast_report.html & sast_report.md"]
        K --> L["FastAPI Single Main App (main.py)"]
    end

    style B fill:#eff6ff,stroke:#1d4ed8,stroke-width:2px
    style G fill:#fefce8,stroke:#ca8a04,stroke-width:2px
    style H fill:#ecfdf5,stroke:#059669,stroke-width:2px
```

---

## 🌐 2. Phase 2 Architecture (Web DAST + OpenAI Provider + Zero-Network Normalization)

```mermaid
flowchart TD
    subgraph TargetApp["Live Web Target"]
        A["DVWA Target App (http://127.0.0.1:8085)"]
    end

    subgraph ScannerDaemon["DAST Scanner Engine"]
        B["OWASP ZAP API Daemon (port 8080)"]
        C["Automated Session Auth (PHPSESSID Replacer Rule)"]
        A <--> B
        B <--> C
    end

    subgraph ZeroNetworkParser["Zero-Network Normalizer (18ms)"]
        D["ZAP Message ID Retrieval: zap.core.message(id)"]
        E["Pure In-Memory Response Header Parsing"]
        F["Explicit Security Header Status Check"]
        B --> D
        D --> E
        E --> F
    end

    subgraph CentralAIProvider["Centralized OpenAI AI Layer"]
        G["Central Provider: llm/provider.py (OpenAI API gpt-5.4-nano)"]
        H["Pass 1: AI Assessor (Plausibility, Impact, Remediation)"]
        I["Pass 2: AI Senior Reviewer (3-State Audit Decision)"]
        F --> G
        G --> H
        H --> I
    end

    subgraph VerdictBuckets["3-State Verdict Classification"]
        J1["Confirmed Risks"]
        J2["False Positives Discarded"]
        J3["Requires Verification"]
        I --> J1
        I --> J2
        I --> J3
    end

    subgraph FastAPIRouters["FastAPI Modular Routers & Frontend"]
        K1["routers/scan.py (SSE Stream + keep-alive)"]
        K2["routers/targets.py (Target Discovery)"]
        K3["routers/reports.py (HTML/MD Download)"]
        L["Clean Emoji-Free Web UI (frontend/index.html & app.js)"]
        
        J1 & J2 & J3 --> K1
        K1 & K2 & K3 --> L
    end

    style B fill:#eff6ff,stroke:#1d4ed8,stroke-width:2px
    style G fill:#fefce8,stroke:#ca8a04,stroke-width:2px
    style I fill:#ecfdf5,stroke:#059669,stroke-width:2px
    style L fill:#4f46e5,stroke:#ffffff,stroke-width:2px,color:#ffffff
```

---

## 🎨 3. Editable Architecture File
The source editable diagram file **`docs/08_Editable_Architecture.drawio`** and graphics **`architecture diagram.png`** / **`flow chart.png`** are preserved in the `docs/` folder for editing in Draw.io.
