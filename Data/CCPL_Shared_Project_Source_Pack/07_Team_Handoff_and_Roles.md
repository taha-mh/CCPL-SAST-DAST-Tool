# Team Handoff and Working Agreement

## Shared Understanding

We are building one project together. The goal is not to compete over who writes more code; the goal is to deliver a working, explainable, and testable security pipeline.

Both team members should understand the complete flow, even when each person owns different modules.

## Current Scope

The current sprint covers **Web SAST only**:

```text
DVWA source -> Semgrep -> normalization -> Qwen3 assessor
-> Qwen3 reviewer -> report
```

Web DAST and both mobile pipelines remain part of the overall design, but they are not part of the first implementation sprint.

## Suggested Ownership

| Module | Primary Owner | Secondary Reviewer |
|---|---|---|
| VM setup and dependency verification | Joint | Joint |
| Semgrep runner and raw JSON output | Security/pipeline owner | Web owner |
| Normalizer and source context | Security/pipeline owner | Web owner |
| Ollama and LLM integration | Security/pipeline owner | Web owner |
| FastAPI endpoints | Web/backend owner | Security owner |
| HTML/CSS/JavaScript interface | Web owner | Security owner |
| Report content and vulnerability quality | Joint | Joint |
| Testing and final demo | Joint | Joint |

Names can be assigned by the team. Ownership means responsibility, not exclusive control.

## Daily Communication

Use a short daily update:

- What I completed
- What I will do next
- What is blocking me
- Which file or branch I changed

## Git Rules

- Use one shared repository.
- Do not both edit the same large file without coordination.
- Use small commits with clear messages.
- Pull before starting work.
- Create separate branches for larger modules.
- Review each other's work before merging.
- Never commit passwords, tokens, VM credentials, or private company information.

## Decision Rule

A decision becomes final only when:

1. It is written in the project documentation.
2. Both members know about it.
3. It does not contradict the supervisor's requirements.

When a new decision replaces an old one, update the source document rather than leaving both versions active.

## Demo Rule

Both members should be able to explain:

- What SAST is
- Why DVWA source code is used
- What Semgrep contributes
- Why scanner output is normalized
- Why the LLM needs source context
- Why two LLM passes are used
- Why Qwen3 8B Q4_K_M was selected
- Why the first version has no database
- Why scans are sequential and limited to one heavy job at a time
