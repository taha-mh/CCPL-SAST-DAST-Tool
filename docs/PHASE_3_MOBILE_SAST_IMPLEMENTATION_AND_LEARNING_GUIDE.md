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

Status: **Complete and verified with a native Windows MobSF runtime on 2026-08-17**

The next decision must distinguish two responsibilities:

1. **APK extraction/decompilation** recovers the manifest, resources, and readable code representation.
2. **Static scanning** applies Android security checks and produces machine-readable findings.

Candidate tools must be evaluated for Windows compatibility, JSON output, auditability, resource requirements, licensing, and whether they analyze compiled APK evidence rather than requiring the unavailable original source project.

### Decision: MobSF

MobSF (Mobile Security Framework) is the selected primary scanner. It is an open-source, GPL-3.0 mobile security framework that accepts compiled Android APK files, performs static analysis, and exposes REST endpoints for automation and JSON report retrieval.

The Web and Mobile responsibilities now map as follows:

| Responsibility | Web pipeline | Mobile SAST pipeline |
|---|---|---|
| Primary static scanner | Semgrep | MobSF Static Analyzer |
| Human-readable code inspection | Original source | JADX decompilation |
| Package/manifest extraction | Not normally required | Apktool or MobSF extraction |
| Dynamic testing | ZAP | Deferred; not part of Phase 3 |
| Evidence assessor | Qwen/OpenAI according to web design | OpenAI GPT-5.4 Nano |
| Independent reviewer | OpenAI | Separate OpenAI GPT-5.4 Nano pass |

MobSF was selected because it understands Android-specific evidence that a general source scanner does not fully model: the manifest, permissions, exported components, signing certificates, network-security configuration, WebView behavior, insecure storage patterns, weak cryptography, hardcoded values, native libraries, and application metadata.

### Why LongCat was not selected as the scanner

LongCat is a general-purpose large language model for reasoning, coding, and agentic work. It is not an APK parser or a deterministic Android security scanner. An LLM may assess evidence after scanning, but it should not replace the evidence-producing scanner. This project therefore uses MobSF to produce findings and structured evidence, followed by explicitly separated AI assessment and review passes.

Supervisor explanation:

> MobSF is the mobile equivalent of the scanner layer, while GPT is the reasoning layer. MobSF opens and understands the APK using Android-specific checks. The AI receives those traceable findings afterward and helps distinguish plausible vulnerabilities from noise. This separation makes the process more reproducible and auditable than asking an LLM to inspect an APK by itself.

### Tool responsibilities and limitations

- **MobSF:** primary automated APK static scanner and machine-readable evidence producer.
- **JADX:** supporting tool for readable decompiled Java/Kotlin evidence and manual verification.
- **Apktool:** supporting tool for decoded resources, manifest content, and Smali bytecode.
- **OWASP MASVS/MASTG:** security requirements and testing guidance, not an executable scanner.
- **LongCat or another LLM:** optional reasoning technology, not a replacement for MobSF.

Automated findings remain candidates. MobSF may report configuration weaknesses, suspicious patterns, or informational observations that are not exploitable in DIVA's actual data flow. Conversely, decompilation can lose source-level names and exact original line mappings. Those limitations are why the raw report is preserved and later findings must retain their evidence and provenance.

### Approved static-only API workflow

```text
POST /api/v1/upload
  → POST /api/v1/scan
  → POST /api/v1/report_json
  → data/raw/mobsf.json (unchanged response bytes)
  → data/raw/mobsf_scan.log (timestamps, hashes, statuses; never the API key)
```

The runner is deliberately limited to this workflow. It does not call MobSF dynamic-analysis endpoints, start an emulator, normalize findings, classify vulnerabilities, call OpenAI, or generate reports.

### Local deployment decision

The scanner runs locally. MobSF's hosted demonstration service is not the project pipeline because uploading a company or client APK to a third-party service would change the privacy boundary.

Docker Desktop was initially installed because containers are MobSF's simplest documented deployment method. This Windows system is itself a virtual machine, however, and the host does not expose nested hardware virtualization. WSL 2 installed successfully, but Docker reported `Virtualization support not detected` and could not start its Linux engine. A Docker account, Docker reinstall, or guest-administrator command cannot add a CPU capability withheld by the VM host.

Because host-level permission was unavailable, the verified solution was MobSF's officially supported native Windows installation. This keeps the static scanner inside the same VM without requiring a second Linux VM:

```text
Physical host
  → Windows project VM
      → CCPL FastAPI
      → native MobSF on 127.0.0.1:8001
```

This workaround is suitable for Mobile SAST. MobSF correctly warns that dynamic analysis is unavailable without an emulator; that warning is expected because Mobile DAST is outside Phase 3.

Configuration values are environment variables:

```text
MOBSF_URL=http://127.0.0.1:8000
MOBSF_API_KEY=<local MobSF REST API key>
```

The API key is a local scanner credential. It must be placed in the process environment or an ignored `.env` file and must never be committed, printed in logs, or written into the learning guide.

### Reproducible runner command

After local MobSF is running:

```powershell
$env:MOBSF_URL = "http://127.0.0.1:8000"
$env:MOBSF_API_KEY = "<key shown by the local MobSF instance>"
.\.venv\Scripts\python.exe -m scanners.mobsf_runner `
  targets\DIVA\DivaApplication.apk `
  --output data\raw\mobsf.json `
  --log data\raw\mobsf_scan.log
```

Success requires all of the following evidence:

- the upload, static scan, and JSON-report requests return successful HTTP statuses;
- `data/raw/mobsf.json` parses as a JSON object;
- the raw response bytes are saved without normalization or rewriting;
- the log records the DIVA APK SHA-256 and raw-report SHA-256;
- the API key is absent from output and logs;
- no dynamic-analysis endpoint is called.

## Next controlled step

Run a controlled live OpenAI assessment on a small number of normalized findings after `OPENAI_API_KEY` is supplied through the local environment. The implementation and schema tests are complete, but no live Phase 3 AI verdict is claimed in this document yet.

## Step 3 — Dual APK input workflow

Status: **Implemented; genuine MobSF runtime verification pending**

The Mobile SAST interface supports two input modes:

1. **Existing target:** select an APK already stored below `targets/`, such as `DIVA/DivaApplication.apk`.
2. **Browser upload:** choose an APK from the user's computer and upload it once to CCPL temporary storage.

Both modes converge on the same scanner function:

```text
Existing target APK ───────────────┐
                                  ├─→ CCPL backend → MobSF REST API → raw JSON
Browser → temporary APK + token ──┘
```

The user never uploads the APK manually in MobSF. For browser mode, FastAPI receives the file, returns an opaque UUID token, and the scan stream uses that token to locate the temporary file. The backend then forwards the APK to MobSF automatically and removes the temporary upload after the scan attempt, including when MobSF returns an error.

### Security controls

- Only `.apk` filenames are accepted.
- The uploaded content must begin as an APK/ZIP container.
- Upload size is limited to 200 MB.
- Uploaded filenames are never used as server paths; storage uses a random UUID.
- Target references are resolved below `targets/` and directory traversal is rejected.
- Absolute server paths and the MobSF API key are never sent to the browser.
- Mobile scans use a lock so only one resource-intensive MobSF scan runs at a time.

This step wires only the MobSF scanner stage. Until a genuine raw MobSF report has been inspected, the interface clearly states that normalization and AI review remain deferred rather than displaying invented vulnerability counts.

## Step 4 — Native MobSF installation and first genuine scan

Status: **Complete and verified on 2026-08-17**

### Verified environment

```text
Operating system: Windows Server 2025 VM
CPU allocation: 12 virtual processors
Memory: 16 GB
Python: 3.12.10
MobSF: 4.5.2
Java: Microsoft OpenJDK 17.0.20
MobSF bind address: 127.0.0.1:8001
MobSF source location: C:\MobSF
MobSF source commit: 3f48c5deb57e5df4c6a507d111da956fcdd535d1
```

Native prerequisites established:

- Full Win64 OpenSSL 4.0.1 at MobSF's expected location.
- Visual Studio 2022 Build Tools with the C++ x64/x86 workload.
- Microsoft OpenJDK 17 with `JAVA_HOME` registered.
- Poetry 1.8.4 and MobSF's locked runtime dependencies.
- MobSF SQLite migrations, local user, and authorization roles.

The MobSF API credential was generated locally. Its value is intentionally excluded from this guide, Git, CCPL logs, and frontend responses.

### Installation troubleshooting record

1. Docker could not start because nested virtualization was not exposed to the Windows VM. The architecture changed to native MobSF rather than repeatedly reinstalling Docker.
2. WinGet could not download the Visual Studio bootstrapper and returned `0x80072efd`. The same official Microsoft URL was downloaded with resumable `curl` retries, then the required C++ workload was verified using `vswhere`.
3. Slow package downloads exceeded command execution windows. Poetry installation was safely resumed because it is idempotent and uses cached packages; persistent stdout/stderr logs were used for observation.
4. MobSF initially reported that JDK 8+ was unavailable. Java 17 was already installed, but `JAVA_HOME` was missing from the child process. Registering and explicitly passing `JAVA_HOME` resolved the check.
5. Database migration succeeded, but the first superuser command lost an empty email argument in PowerShell. Re-running only that unfinished command with a local placeholder email completed user and role creation.

These were installation/integration conditions, not vulnerability-scan findings.

### Genuine DIVA scan evidence

The approved DIVA APK was submitted automatically through the local MobSF REST API. All three scanner requests succeeded:

```text
Upload HTTP status: 200
Static scan HTTP status: 200
JSON report HTTP status: 200
APK SHA-256: 5cefc51fce9bd760b92ab2340477f4dda84b4ae0c5d04a8c9493e4fe34fab7c5
Raw JSON size: 114,216 bytes
Raw JSON SHA-256: 8addfa97267ce9c83c2571db6d13030bb8eed1813f5b29728c314d4a447bcc10
Raw report: data/raw/mobsf.json
Audit log: data/raw/mobsf_scan.log
```

JSON validation identified the application as `Diva` with package `jakhar.aseem.diva`. After verified JADX decompilation, MobSF produced a security score of 42 and the following high-level scanner observations:

- five manifest findings: one high and four warnings;
- five code findings: one high, three warnings, and one informational;
- two certificate findings: one high and one informational;
- three declared permissions, including two critical/dangerous permission observations;
- two exported activities and one exported content provider;
- fourteen binary-analysis records.

Examples include a debug certificate, an enabled debug flag, backup permission, exported Android components, and external-storage permissions. These are **candidate observations**, not confirmed vulnerabilities. The assessor and reviewer have not evaluated them yet.

### Decompiler failure discovered and corrected

The first otherwise-successful API scan produced an empty `code_analysis` section. Server-log inspection proved that this was not an expected DIVA result: the first-time setup had been interrupted while downloading JADX, so `jadx.bat` did not exist.

After the official JADX 1.5.0 archive was downloaded and extracted, MobSF initially rejected the new executable with `Executable/Library Tampering Detected`. This was MobSF's intended integrity protection: its executable hash map had been created before JADX existed. The protection was not disabled. MobSF was restarted so it could hash the completed official toolset, then the identical APK was submitted with `re_scan=1` to bypass the cached incomplete report.

The final server log confirms this sequence without an error:

```text
Decompiling APK to Java with JADX
Code Analysis Started on - java_source
Android SAST Completed
```

The final raw report contains five code findings. This illustrates why HTTP 200 and valid JSON alone are insufficient scan-quality checks: key scanner stages and expected evidence sections must also be validated.

### Supervisor explanation

> Docker could not operate because our Windows development system is already a VM and the host does not permit virtualization inside it. We used MobSF's supported native Windows deployment instead. The scanner now runs locally, the DIVA APK was scanned through the automated API, and the unchanged JSON plus cryptographic hashes were preserved. The scanner produced genuine candidate findings. Normalization and both OpenAI stages are implemented and tested with controlled fixtures; a live AI verdict still requires the API key to be supplied at runtime.

## Step 5 - Main-branch integration and Mobile SAST normalization

Status: **Implemented and regression-tested on 2026-08-18**

The latest tagged Phase 1/2 implementation from `main` was merged into `refactoring`. The mentor-maintained modular FastAPI routers, DAST evidence improvements, three-verdict reporting, and frontend cleanup were retained as the shared baseline. Phase 3 additions were then reapplied to that architecture instead of restoring the older monolithic `main.py`.

The Mobile SAST normalizer is `parsers/mobsf_normalizer.py`. It performs transformation only and never confirms a vulnerability. It reads the unchanged `data/raw/mobsf.json`, optionally reads separately preserved MobSF decompiled-source responses, and produces `data/normalized/mobile_findings.json`.

The genuine DIVA report produced 24 normalized candidate findings:

| Category | Count |
|---|---:|
| Manifest | 5 |
| Decompiled code rules | 5 |
| Certificate | 2 |
| Permissions | 3 |
| Grouped native-binary checks | 9 |
| **Total** | **24** |

Severity mapping produced five `HIGH`, ten `MEDIUM`, and nine `INFO` scanner severities. These are scanner severities, not final AI verdicts. Each normalized record keeps a stable finding ID, MobSF rule/category, APK identity, location, evidence context, metadata, and the original raw evidence.

For code findings, the runner can call MobSF's static `view_source` API and save source responses separately in `data/raw/mobsf_sources.json`. The normalizer extracts a five-line window before and after reported lines when that evidence exists. This does not rewrite the original MobSF report.

## Step 6 - Dual OpenAI assessment design

Status: **Implemented and contract-tested; live API run pending local key configuration**

Both Mobile SAST passes use OpenAI `gpt-5.4-nano` by explicit project decision:

```text
Normalized MobSF finding
  -> Pass 1 OpenAI assessor
  -> Pass 2 independent-role OpenAI reviewer
  -> confirmed / rejected / needs_review
```

The two passes use separate prompts and schemas, but the same model family. This is logical review independence, not vendor or model independence. The API provider uses the OpenAI Responses API, strict JSON Schema output, `store: false`, a bounded output-token limit, and fail-safe error objects. A missing key, timeout, authentication failure, quota/rate-limit response, empty response, or schema mismatch cannot be converted into a confirmed finding.

Configuration uses environment variables only:

```text
OPENAI_API_KEY=<never commit this value>
OPENAI_MODEL=gpt-5.4-nano
MOBILE_OPENAI_MODEL=gpt-5.4-nano
OPENAI_REASONING_EFFORT=low
OPENAI_MAX_OUTPUT_TOKENS=900
```

This is an approved Phase 3 exception to the original local-only LLM requirement. MobSF and APK processing remain local, but the evidence supplied to the assessor and reviewer is sent to OpenAI. This privacy boundary must be disclosed before scanning any private or client APK.

## Step 7 - Unified three-phase interface

Status: **Implemented and route-tested on 2026-08-18**

The frontend now presents three explicit choices:

1. Phase 1 - Web SAST with Semgrep.
2. Phase 2 - Web DAST with OWASP ZAP.
3. Phase 3 - Mobile SAST with MobSF.

Mobile SAST supports both an APK already below `targets/` and a browser upload. Both paths converge on the same backend pipeline. The phase-specific six-step labels, evidence location, live status stream, three verdict categories, and Mobile SAST report links are selected automatically.

Figma integration was not used because the requested Figma workspace belongs to a different account and was not connected to this development session. The frontend was implemented directly in the repository without blocking the functional integration.

## Verification record

The repository-owned suite completed with `23 passed` and one existing Starlette deprecation warning. Python compilation passed for the entry point, routers, MobSF runner/normalizer, and OpenAI modules. The generated genuine normalized JSON parsed successfully and contained 24 findings. The tests use simulated MobSF/OpenAI responses for deterministic integration contracts; they are not presented as a live OpenAI security assessment.
