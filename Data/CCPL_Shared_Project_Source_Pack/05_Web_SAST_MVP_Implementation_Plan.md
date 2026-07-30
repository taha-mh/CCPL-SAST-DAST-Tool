# Web SAST MVP Implementation Plan

## Purpose

The first implementation milestone is intentionally limited to **Web SAST on DVWA source code**.  
The goal is to prove one complete pipeline before adding Web DAST or mobile testing.

## Current Environment

- **Operating system:** Windows Server 2025 virtual machine
- **Memory:** 16 GB RAM
- **CPU allocation:** 8 vCPUs
- **Internet/accounts:** Fresh VM; no development accounts are required for the initial setup
- **Execution policy:** One resource-intensive scan at a time

## First Working Pipeline

```text
DVWA source code
    -> Semgrep scan
    -> Raw Semgrep JSON
    -> Normalize findings
    -> Add relevant source-code context
    -> Qwen3 8B assessor
    -> Qwen3 8B reviewer
    -> Confirmed and discarded findings
    -> Markdown/HTML report
```

## Selected Technologies

| Area | Decision | Reason |
|---|---|---|
| Source target | DVWA | Fixed vulnerable web target from the requirements |
| SAST scanner | Semgrep | Produces structured source-code findings and supports local rules |
| Backend language | Python | Fits FastAPI, scanner orchestration, JSON processing, and Ollama integration |
| Backend framework | FastAPI | Suitable for REST APIs and later background scan-status handling |
| Local LLM runtime | Ollama | Provides a simple local API for automated inference |
| Model | Qwen3 8B | Balanced code understanding and reasoning |
| Quantization | Q4_K_M | Fits the 16 GB VM while keeping useful output quality |
| Initial storage | Local files | No database is needed for the proof-of-concept |
| Report format | Markdown and HTML | Easy to generate, review, and later convert to PDF |

## Implementation Order

### Milestone 1 - Environment Validation

Complete these checks before writing the application:

- Git works.
- Python and `pip` work.
- VS Code opens the project.
- Ollama runs locally.
- `qwen3:8b` answers a test prompt.
- Semgrep runs locally.
- DVWA source code is available.
- A Semgrep JSON result file is generated.

### Milestone 2 - Scanner Wrapper

Create `scanners/semgrep_runner.py`.

Its only responsibility is:

1. Receive the DVWA source path.
2. Run Semgrep with local rules.
3. Save the raw JSON output.
4. Return success/failure and the output path.

### Milestone 3 - Normalizer

Create `parsers/semgrep_normalizer.py`.

Convert Semgrep output into a common finding structure containing:

- Finding ID
- Tool
- Rule ID
- Title/message
- Scanner severity
- File path
- Start and end line
- Matched code/evidence
- CWE/OWASP metadata when available

The normalizer must **not** decide whether the finding is real.

### Milestone 4 - Source Context Extractor

Read the affected source file and attach a small line window around each finding.  
This context is necessary because the LLM should not judge a vulnerability from the scanner title alone.

### Milestone 5 - LLM Assessor

Send one normalized finding at a time to Qwen3 8B through Ollama.

The assessor should return structured JSON containing:

- `is_plausible`
- `vulnerability_type`
- `severity`
- `reasoning`
- `evidence`
- `impact`
- `remediation`
- `confidence`

### Milestone 6 - LLM Reviewer

The second pass reviews the raw evidence and the assessor result.

It must return:

- `decision`: confirmed, rejected, or needs_review
- `review_reason`
- `final_severity`
- `confidence`

Only **confirmed** findings enter the main report.

### Milestone 7 - Report Generator

Generate:

- Executive summary
- Confirmed findings
- Severity totals
- Evidence and affected locations
- Recommended remediation
- Optional discarded-findings appendix
- Tool/model/hardware metadata

### Milestone 8 - FastAPI and Frontend

Only after the terminal pipeline works:

- `POST /api/scans`
- `GET /api/scans/{scan_id}/status`
- `GET /api/scans/{scan_id}/results`

The frontend will later use HTML, CSS, and Vanilla JavaScript to start a scan, show status, and display the final report.

## Definition of Done for the First Demo

The first demo is complete when a user can:

1. Start a local DVWA source scan.
2. See Semgrep complete successfully.
3. See Qwen3 assess and review the findings.
4. Open a report containing confirmed findings.
5. Review discarded findings separately.
6. Verify that no cloud LLM or cloud scanner was used.
