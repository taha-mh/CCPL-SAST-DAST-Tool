# Phase 4 — Android Mobile DAST Scope and Learning Guide

## Current status

Phase 4 is **deferred**. No Mobile DAST code, emulator automation, ADB control, runtime hooks, or dynamic attack logic has been implemented.

## Why this document exists now

Mobile SAST and Mobile DAST use the same DIVA application but answer different questions. Maintaining a separate phase record prevents static APK analysis from being mixed with runtime testing and prevents unverified future work from being presented as complete.

## Conceptual distinction

```text
Mobile SAST
  APK at rest → manifest/resources/decompiled code → static findings

Mobile DAST
  installed running app → emulator/device interaction → runtime evidence
```

Mobile SAST asks, “What risky implementation patterns exist inside the package?” Mobile DAST asks, “What security behavior can be observed while the installed application runs?”

## Expected future prerequisites

- An isolated Android emulator or approved test device
- ADB connectivity restricted to the lab environment
- Installation of the exact hashed DIVA APK
- A repeatable reset procedure
- Runtime evidence capture
- Explicit authorization boundaries
- A mobile dynamic-analysis tool selected after evaluation

## Evidence discipline

Future dynamic findings must preserve observed runtime evidence separately from scanner descriptions. Cached, simulated, or manually constructed examples must never be labelled as genuine runtime findings.

## AI boundary

The currently approved Mobile design uses OpenAI `gpt-5.4-nano` for both logical passes. Before Phase 4 begins, the team must review whether runtime evidence may be sent to an external API and define redaction, retention, budget, and failure policies.

## Supervisor explanation

> Phase 3 examines the APK without executing it. Phase 4 will later install the same identified APK in an isolated Android lab and analyze runtime behaviour. We document them separately so every conclusion remains tied to the type of evidence that produced it.

## Gate before implementation

Phase 4 must not start until Phase 3 produces a genuine static scan, normalized mobile evidence, tested assessor and reviewer outputs, and an auditable result.
