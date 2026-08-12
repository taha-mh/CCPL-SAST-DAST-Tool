# Phase 3 — Android Mobile SAST Implementation and Learning Guide

## Document purpose

This is the living engineering, learning, and presentation record for Phase 3 of the CCPL Security Assessment Tool. It will be updated after each completed and verified Mobile SAST step. Claims are recorded as complete only after their output has been checked.

## Phase boundary

Phase 3 implements **Mobile SAST only** against the intentionally vulnerable DIVA Android application. It does not implement Mobile DAST, emulator-driven attacks, runtime instrumentation, or Web DAST.

The planned evidence path is:

```text
DIVA APK
  → APK identity and integrity check
  → manifest/resource extraction and code decompilation
  → mobile static scanner output
  → mobile finding normalization and evidence context
  → OpenAI GPT-5.4 Nano assessor
  → independent OpenAI GPT-5.4 Nano reviewer
  → auditable Mobile SAST output
```

Both AI passes use the same selected OpenAI model, but they remain separate logical roles with separate prompts. This provides a second evaluation pass; it does not provide full model independence.

## Step 1 — Work isolation and target discovery

Status: **Complete and verified on 2026-08-12**

### Branch strategy

Mobile work is isolated on the `refactoring` Git branch so it does not interfere with the teammate's Web DAST work on `main`. Existing uncommitted OpenAI Reviewer integration changes were preserved when the branch was created.

### Target repository

The approved target is:

```text
https://github.com/0xArab/diva-apk-file.git
```

The repository distributes `DivaApplication.apk`. It is an APK artifact rather than an Android Studio source project.

Verified target record:

```text
Local path: targets/DIVA
Origin: https://github.com/0xArab/diva-apk-file.git
Branch: main
Commit: b43a4d33fb1703e8a0d30312cde92b5f8b70556c
Commit date: 2020-12-17T13:55:31+03:00
Working tree: clean
APK: DivaApplication.apk
APK size: 1,502,294 bytes
APK SHA-256: 5cefc51fce9bd760b92ab2340477f4dda84b4ae0c5d04a8c9493e4fe34fab7c5
```

The SHA-256 value is the APK's identity card. If the APK changes, the hash changes, allowing reports and test results to be tied to the exact artifact that was analyzed.

### Why this distinction matters

An APK is the packaged application installed on Android. It contains compiled Dalvik bytecode, the Android manifest, resources, and signatures. A source scanner cannot treat it like ordinary Java source immediately. We must first extract or decompile it into analyzable evidence.

Supervisor explanation:

> In Web SAST, Semgrep can read the DVWA source tree directly. In Mobile SAST, our input is a compiled APK, so we first recover the manifest, resources, and readable code representation. Static findings must remain traceable to the original APK and its cryptographic hash.

### Target isolation

`targets/DIVA/` is ignored by the parent repository because it is an external test target with its own Git history and a binary APK. The CCPL repository should store pipeline code and documentation, not duplicate third-party binaries.

This boundary was verified with `git check-ignore`; the APK is excluded by the parent `.gitignore` rule.

## Step 1 evidence checklist

- [x] Exact DIVA repository origin
- [x] Branch and commit
- [x] APK filename and byte size
- [x] APK SHA-256 hash
- [x] Target repository cleanliness
- [x] Local Android static-analysis tool audit
- [x] External target excluded from the parent repository

### Toolchain audit result

The following commands were not available on PATH:

```text
java
javac
adb
apktool
jadx
aapt
aapt2
apkanalyzer
```

This is not a scan failure because scanning has not started. It establishes the prerequisite gap for Step 2.

### Provenance limitation

The selected repository is a public mirror containing the compiled DIVA APK and only four commits. Its latest recorded commit is from 2020. We therefore preserve the origin, commit, size, and hash rather than claiming that it is the official upstream Android source repository.

## Security and privacy decisions

- Never commit an OpenAI API key.
- Read the key only from `OPENAI_API_KEY`.
- Send one normalized finding at a time.
- Send only the evidence required for assessment.
- Store reviewer decisions and usage metadata, not secrets.
- Treat scanner and LLM outputs as assessments, not guaranteed proof.
- Keep Mobile SAST separate from Web DAST and Mobile DAST.

## Presentation vocabulary

- **APK:** The installable Android application package.
- **Decompilation:** Recovering a readable representation from compiled application code.
- **Static analysis:** Inspecting application contents without executing the application.
- **Evidence context:** The manifest entry, resource, or decompiled code associated with a finding.
- **Assessor:** First AI pass that evaluates plausibility from evidence.
- **Reviewer:** Second logical AI pass that audits the first verdict.

## Step 2 — Toolchain and scanner selection

Status: **Pending**

The next decision must distinguish two responsibilities:

1. **APK extraction/decompilation** recovers the manifest, resources, and readable code representation.
2. **Static scanning** applies Android security checks and produces machine-readable findings.

Candidate tools must be evaluated for Windows compatibility, JSON output, auditability, resource requirements, licensing, and whether they analyze compiled APK evidence rather than requiring the unavailable original source project.

## Next controlled step

Select and establish the minimum Mobile SAST toolchain, then produce one genuine machine-readable finding before building normalization or either OpenAI pass.
