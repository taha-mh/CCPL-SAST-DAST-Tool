# 🔄 CCPL SAST & DAST Execution Flow Diagrams

Compact, ultra-readable execution sequence diagrams for Phase 1 and Phase 2.

---

## 🛡️ Phase 1 Sequence Diagram (Web SAST)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as FastAPI App
    participant Scanner as Semgrep Scanner
    participant AI as Ollama AI Engine
    participant Report as Report Generator

    User->>App: Start SAST Scan (DVWA)
    App->>Scanner: 1. Run Semgrep CLI (*.php)
    Scanner-->>App: Raw findings JSON
    App->>App: 2. Normalize & extract source context (+/- 10 lines)
    App->>AI: 3. Pass 1: Assessor reasoning
    AI-->>App: Assessment JSON
    App->>AI: 4. Pass 2: Reviewer audit
    AI-->>App: Final reviewed JSON
    App->>Report: 5. Generate HTML & Markdown reports
    Report-->>App: sast_report.html & sast_report.md
    App-->>User: Render dashboard summary & report downloads
```

---

## 🌐 Phase 2 Sequence Diagram (Web DAST)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as FastAPI App (Routers)
    participant ZAP as OWASP ZAP (Port 8080)
    participant AI as OpenAI Provider (gpt-5.4-nano)
    participant Report as Report Generator

    User->>App: Start DAST Scan (http://127.0.0.1:8085)
    App->>ZAP: 1. Launch ZAP & auto-authenticate (PHPSESSID)
    ZAP->>ZAP: 2. Run active DAST attack scan
    ZAP-->>App: 3. Return ZAP message IDs
    App->>App: 4. Zero-network response header parsing (18ms)
    App->>AI: 5. Pass 1: Assessor reasoning (JSON mode)
    AI-->>App: Assessment JSON
    App->>AI: 6. Pass 2: Senior Reviewer audit
    AI-->>App: 3-State Verdict (confirmed / rejected / needs_review)
    App->>Report: 7. Generate 3-State HTML & Markdown reports
    Report-->>App: sast_report.html & sast_report.md
    App-->>User: Stream SSE logs & show 4 interactive stat cards
```
