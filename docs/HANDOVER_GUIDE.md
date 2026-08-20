# 🤝 CCPL Web Security Testing Tool - Handover & Execution Guide

---

## 📌 1. Essential Commands Quick Reference

### Server Startup
```powershell
# Start local DVWA Target Web App on Port 8085 (in target terminal)
C:\php\php.exe -S 127.0.0.1:8085 -t C:\Users\Administrator\Desktop\CCPL-Project\CCPL-SAST-DAST-Tool\targets\DVWA

# Start FastAPI Application Server (Port 8000)
python main.py
```

### Access Points
- **Web Dashboard UI**: `http://127.0.0.1:8000/`
- **Interactive Swagger API Docs**: `http://127.0.0.1:8000/docs`

### Automated Regression Testing
```powershell
# Execute full automated unit & integration test suite (0.17s runtime)
python -m unittest discover tests
```

---

## 🏗️ 2. Core Architecture & Directory Map

```text
CCPL-SAST-DAST-Tool/
│
├── main.py                   # 58-line FastAPI application entry point (mounts routers & frontend)
│
├── routers/                  # Modular FastAPI Router Package
│   ├── __init__.py
│   ├── targets.py            # Target project discovery (GET /api/targets)
│   ├── reports.py            # Report delivery endpoints (GET /api/reports/html, GET /api/reports/md)
│   └── scan.py               # Pipeline orchestration & SSE streaming (POST /api/scan, GET /api/scan/stream)
│
├── scanners/                 # Security Scanner Execution Modules
│   ├── semgrep_runner.py     # Semgrep SAST scanner runner
│   └── dast_runner.py        # OWASP ZAP DAST scanner & session cookie replacer runner
│
├── parsers/                  # Evidence Normalizer Modules
│   ├── semgrep_normalizer.py # Semgrep raw finding normalizer
│   ├── source_context.py     # SAST source code context extractor (+/- 10 lines)
│   └── dast_normalizer.py    # Pure in-memory zero-network DAST HTTP response header parser
│
├── llm/                      # Central Dual-Pass AI Reasoning Engine
│   ├── provider.py           # Central OpenAI API provider (gpt-5.4-nano in JSON mode)
│   ├── assessor.py           # Pass 1 AI Assessor (risk plausibility, impact, remediation)
│   └── reviewer.py           # Pass 2 AI Senior Reviewer (3-state decision auditor)
│
├── prompts/                  # AI System Prompts & User Formatters
│   ├── assessor_prompt.py
│   └── reviewer_prompt.py
│
├── reports/                  # Report Generator & HTML Template
│   ├── report_generator.py   # 3-state verdict report builder
│   ├── report_template.html  # Light-theme dashboard HTML template
│   ├── sast_report.html      # Generated HTML report file
│   └── sast_report.md        # Generated Markdown report file
│
├── frontend/                 # Static Web Dashboard UI
│   ├── index.html            # Emoji-free dashboard HTML with 4 clickable stat cards
│   ├── app.js                # EventSource SSE client & category view switching logic
│   └── style.css             # Responsive dashboard styling
│
├── tests/                    # Automated Regression Test Suite
│   ├── test_dast_normalizer.py
│   └── test_routers.py
│
└── docs/                     # Project Documentation & Milestone Reports
    ├── DOCUMENTATION_INDEX.txt
    ├── HANDOVER_GUIDE.md
    ├── PHASE_1_REPORT.md
    └── PHASE_2_REPORT.md
```

---

## 🔒 3. Configuration & Security Rules

1. **Environment Key**: `.env` file contains `OPENAI_API_KEY` and `OPENAI_MODEL=gpt-5.4-nano`. Never commit `.env` to Git.
2. **Zero Network Calls in Normalizer**: DAST normalizer uses HTTP headers harvested from ZAP (`zap.core.message(id=msg_id)`). Never add `requests.get()` inside `parsers/dast_normalizer.py`.
3. **3-State Verdict Decisions**: Reviewer outputs strictly `confirmed`, `rejected`, or `needs_review`. Missing evidence defaults to `needs_review`.
