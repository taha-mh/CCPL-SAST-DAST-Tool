# 🛡️ CCPL Web SAST Security Scanner (Phase 1)

An automated, AI-assisted **Static Application Security Testing (SAST)** tool designed to scan web application codebases, normalize scanner outputs, extract surrounding source code context, and reduce false positives using a **2-Pass AI Reasoning Engine**: local Ollama `qwen3.5:9b` assessment followed by an independent OpenAI `gpt-5.4-nano` review.

---

## 🏗️ Architecture & 6-Step SAST Pipeline

```text
 🔍 Semgrep Scan ➔ 📊 Normalizing ➔ 📄 Source Context ➔ 🤖 AI Assessor (Pass 1) ➔ 🛡️ AI Reviewer (Pass 2) ➔ 📝 Report Generator
```

1. **Step 1: Scanner Wrapper (`scanners/semgrep_runner.py`)**: Runs Semgrep rules restricted to target web files (`*.php`).
2. **Step 2: Findings Normalizer (`parsers/semgrep_normalizer.py`)**: Converts raw Semgrep output into a standardized JSON schema.
3. **Step 3: Source Context Extractor (`parsers/source_context.py`)**: Extracts ±10 lines of surrounding code context around flagged vulnerabilities.
4. **Step 4: Pass 1 AI Assessor (`llm/assessor.py`)**: Prompts local Ollama (`qwen3.5:9b`) for an initial plausibility verdict (`is_plausible: true/false`).
5. **Step 5: Pass 2 AI Senior Reviewer (`llm/reviewer.py`)**: Sends the finding evidence and Pass 1 assessment to OpenAI `gpt-5.4-nano` for an independent structured verdict (`confirmed`, `rejected`, or `needs_review`).
6. **Step 6: Security Report Generator (`reports/report_generator.py`)**: Generates executive HTML and Markdown reports featuring a Summary Matrix Table and a Discarded False-Positives Audit Log.

---

## 🌐 FastAPI Backend & Web Dashboard UI

* **Backend Server (`main.py`)**: Built using FastAPI with Server-Sent Events (SSE) log streaming (`GET /api/scan/stream`) and Pydantic body validation (`POST /api/scan`).
* **Minimalist Web GUI (`frontend/`)**: Modern light-mode interface with live log streaming, 6-step pathway tracking, interactive filter tabs (*Confirmed Risks*, *Discarded False Positives*, *All Evaluated*), and official CCPL logo integration.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* Python 3.10+
* Semgrep CLI (`pip install semgrep`)
* Ollama running locally with `qwen3.5:9b` pulled
* An OpenAI API key provided through the `OPENAI_API_KEY` environment variable

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/taha-mh/CCPL-SAST-DAST-Tool.git
cd CCPL-SAST-DAST-Tool

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### 3. Run the Server
```powershell
python main.py
```

### 4. Open Web Dashboard
Open your web browser to:
👉 **`http://localhost:8000`**

Click **`⚡ Start SAST Scan`** to run the scan pipeline and view interactive results!

---

## 📁 Repository Structure

```text
CCPL-SAST-DAST-Tool/
├── main.py                     # FastAPI server orchestrator & SSE streaming endpoint
├── requirements.txt            # Python dependencies (fastapi, uvicorn, semgrep, httpx, pydantic)
├── scanners/
│   └── semgrep_runner.py       # Milestone 2: Semgrep scanner wrapper
├── parsers/
│   ├── semgrep_normalizer.py   # Milestone 3: JSON schema normalizer
│   └── source_context.py       # Milestone 4: Source code context extractor
├── prompts/
│   ├── assessor_prompt.py      # Pass 1 LLM system & user prompt templates
│   └── reviewer_prompt.py      # Pass 2 LLM system & user prompt templates
├── llm/
│   ├── assessor.py             # Milestone 5: Pass 1 AI Assessor module
│   └── reviewer.py             # Milestone 6: Pass 2 AI Senior Reviewer module
├── reports/
│   └── report_generator.py     # Milestone 7: HTML & Markdown report generator
├── frontend/
│   ├── index.html              # Dashboard HTML structure & filter tabs
│   ├── style.css               # Minimalist responsive theme & animations
│   ├── app.js                  # SSE EventSource streaming & tab logic
│   └── logo.webp               # Official CCPL Logo asset
├── targets/
│   └── DVWA/                   # Vulnerable web application target codebase
└── data/                       # Pipeline JSON artifacts (git-ignored)
    ├── raw/
    └── normalized/
```

---

## 📄 License & Handoff
Maintained for CCPL Security Assessment Project. All code is modular, fully typed, and ready for Phase 2 (DAST Integration).
