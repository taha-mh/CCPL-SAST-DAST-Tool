# CCPL Web SAST MVP

This repository is being prepared for the first implementation milestone
of the CCPL local, AI-assisted security-testing proof of concept.

## Current Scope

The current implementation scope is limited to Web SAST against the local
DVWA source code.

The planned first pipeline is:

```text
DVWA source
-> Semgrep
-> raw JSON
-> normalized findings with source context
-> Qwen3 8B assessor through Ollama
-> independent reviewer pass
-> confirmed and discarded findings
-> local Markdown/HTML report
```

Semgrep will collect candidate findings and supporting code evidence.
The local language model will later assess that evidence in context.
A second logical review pass will classify findings as confirmed,
rejected, or requiring manual review.

## Planned Technology Stack

- Windows Server 2025 VM
- Python
- Semgrep
- FastAPI
- Pydantic
- HTTPX
- Ollama
- Qwen3 8B with Q4_K_M quantization
- Local JSON, Markdown, and HTML files

## Repository Layout

- `scanners/` - scanner wrappers
- `llm/` - future local-model integration
- `prompts/` - future assessor and reviewer prompts
- `scripts/` - setup and pipeline utilities
- `tests/` - automated tests
- `targets/` - local approved targets; DVWA is not committed
- `data/raw/` - generated scanner output
- `data/normalized/` - generated normalized findings
- `reports/` - generated reports
- `docs/` - requirements, design, architecture, and team documentation

## Current Status

The repository structure and dependencies are being prepared.

No scanner wrapper, normalizer, LLM integration, FastAPI route,
frontend, or report generator is currently claimed as implemented or
tested.

## Explicitly Deferred

The following are outside the current MVP boundary:

- Web DAST
- OWASP ZAP automation
- Mobile SAST or DAST
- DIVA, JADX, MobSF, Frida, or Android emulator work
- Database integration
- Authentication or user accounts
- Complex frontend development
- Concurrent heavy scans

These areas will remain deferred until the Web SAST pipeline works
end to end.
