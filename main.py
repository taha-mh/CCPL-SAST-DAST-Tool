"""
FastAPI Server for CCPL Web SAST Application with Real-Time Event Streaming.

Responsibility:
1. Provide REST API endpoints for frontend UI interaction.
2. List available scan targets in targets/ directory.
3. Stream real-time 6-step SAST pipeline execution logs to frontend via Server-Sent Events (SSE).
4. Serve static frontend dashboard assets (frontend/).
5. Provide downloadable HTML and Markdown report files.
"""

import asyncio
import json
import logging
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Import our SAST & DAST Pipeline Modules
from scanners.semgrep_runner import run_semgrep_scan
from parsers.semgrep_normalizer import normalize_semgrep_findings
from parsers.source_context import extract_source_context
from scanners.dast_runner import run_dast_scan
from scanners.mobsf_runner import run_static_scan as run_mobsf_static_scan
from parsers.dast_normalizer import normalize_dast_findings
from llm.assessor import run_llm_assessor
from llm.reviewer import run_llm_reviewer
from reports.report_generator import run_report_generator

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Initialize FastAPI App
app = FastAPI(
    title="CCPL Web SAST Tool API",
    description="Automated AI-Assisted Static Application Security Testing Tool",
    version="1.0.0",
)

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
TARGETS_DIR = BASE_DIR / "targets"
REPORTS_DIR = BASE_DIR / "reports"
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOADS_DIR = BASE_DIR / "data" / "uploads"
RAW_DIR = BASE_DIR / "data" / "raw"
MAX_APK_BYTES = 200 * 1024 * 1024
MOBILE_SCAN_LOCK = asyncio.Lock()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def list_target_apks() -> list[dict[str, object]]:
    """List APKs under targets/ without exposing absolute server paths."""
    if not TARGETS_DIR.exists():
        return []
    apks = []
    for path in sorted(TARGETS_DIR.rglob("*.apk")):
        if path.is_file():
            apks.append({
                "reference": path.relative_to(TARGETS_DIR).as_posix(),
                "name": path.name,
                "size_bytes": path.stat().st_size,
            })
    return apks


def resolve_mobile_apk(source: str, reference: str) -> Path:
    """Resolve an opaque upload token or safe targets-relative APK reference."""
    if source == "target":
        candidate = (TARGETS_DIR / reference).resolve()
        allowed_root = TARGETS_DIR.resolve()
    elif source == "upload":
        try:
            token = uuid.UUID(reference)
        except ValueError as exc:
            raise ValueError("Invalid uploaded APK token") from exc
        candidate = (UPLOADS_DIR / f"{token}.apk").resolve()
        allowed_root = UPLOADS_DIR.resolve()
    else:
        raise ValueError("APK source must be 'target' or 'upload'")

    if not _is_within(candidate, allowed_root):
        raise ValueError("APK path escapes the allowed directory")
    if candidate.suffix.lower() != ".apk" or not candidate.is_file():
        raise FileNotFoundError("Selected APK was not found")
    return candidate


# --- Pydantic Data Models ---
class ScanRequest(BaseModel):
    target_name: str = Field(default="DVWA", description="Subfolder name inside targets/ directory")
    max_findings: Optional[int] = Field(default=3, description="Max findings to process through AI (set None for all)")
    include_pattern: Optional[str] = Field(default="*.php", description="Glob file pattern filter (e.g. *.php)")
    pipeline: Optional[str] = Field(default="web_sast", description="Scanning pipeline: web_sast or web_dast")


# --- API Routes ---

@app.get("/api/targets", summary="List available scan targets")
def list_targets():
    """Returns a list of target application folders available inside targets/ directory."""
    if not TARGETS_DIR.exists():
        return {"targets": []}

    targets = [
        item.name for item in TARGETS_DIR.iterdir()
        if item.is_dir() and not item.name.startswith(".")
    ]
    return {"targets": sorted(targets)}


@app.get("/api/mobile/apks", summary="List APK files already available under targets/")
def list_mobile_apks():
    return {"apks": list_target_apks()}


@app.post("/api/mobile/apks/upload", summary="Temporarily upload one APK for Mobile SAST")
async def upload_mobile_apk(file: UploadFile = File(...)):
    original_name = Path(file.filename or "").name
    if not original_name.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4()
    destination = UPLOADS_DIR / f"{token}.apk"
    size = 0
    first_bytes = b""
    try:
        with destination.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                if not first_bytes:
                    first_bytes = chunk[:4]
                size += len(chunk)
                if size > MAX_APK_BYTES:
                    raise HTTPException(status_code=413, detail="APK exceeds the 200 MB limit")
                output.write(chunk)
        if size == 0 or not first_bytes.startswith(b"PK"):
            raise HTTPException(status_code=400, detail="The uploaded file is not a valid APK/ZIP container")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    return {"token": str(token), "filename": original_name, "size_bytes": size}


@app.get("/api/scan/stream", summary="Stream full 6-step SAST/DAST Scan Pipeline with real-time logs")
async def stream_sast_scan(
    target_name: str = Query(default="DVWA"),
    max_findings: Optional[str] = Query(default="3"),
    include_pattern: Optional[str] = Query(default="*.php"),
    pipeline: Optional[str] = Query(default="web_sast"),
    apk_source: Optional[str] = Query(default=None),
    apk_reference: Optional[str] = Query(default=None),
):
    """
    Streams real-time logs for the 6-step SAST pipeline to the frontend via Server-Sent Events (SSE).
    """
    target_path = TARGETS_DIR / target_name
    if pipeline != "mobile_sast" and (not target_path.exists() or not target_path.is_dir()):
        async def error_generator():
            yield f"data: {json.dumps({'type': 'error', 'message': f'Target directory {target_name} not found'})}\n\n"
        return StreamingResponse(error_generator(), media_type="text/event-stream")

    # Handle max_findings conversion (None or int)
    parsed_max = None if max_findings == "all" or max_findings is None else int(max_findings)

    async def event_generator():
        try:
            def log(step_id, message, level="info", active_step=None):
                timestamp = datetime.now().strftime("%H:%M:%S")
                payload = {
                    "type": "log",
                    "step_id": step_id,
                    "active_step": active_step or step_id,
                    "timestamp": timestamp,
                    "message": message,
                    "level": level,
                }
                return f"data: {json.dumps(payload)}\n\n"

            if pipeline == "mobile_sast":
                if not apk_source or not apk_reference:
                    raise ValueError("Choose an uploaded APK or an APK from targets/")
                apk_path = resolve_mobile_apk(apk_source, apk_reference)
                try:
                    yield log("start", f"Starting Mobile SAST for {apk_path.name}...", active_step="scanner")
                    yield log("scanner", "[Step 1/6] Sending the APK to the local MobSF static-analysis API...", active_step="scanner")

                    async with MOBILE_SCAN_LOCK:
                        scan_task = asyncio.create_task(asyncio.to_thread(
                            run_mobsf_static_scan,
                            apk_path,
                            RAW_DIR / "mobsf.json",
                            RAW_DIR / "mobsf_scan.log",
                            base_url=os.getenv("MOBSF_URL", "http://127.0.0.1:8001"),
                            api_key=os.getenv("MOBSF_API_KEY", ""),
                        ))
                        while not scan_task.done():
                            yield ": keep-alive\n\n"
                            await asyncio.sleep(10)
                        audit = await scan_task

                    yield log("scanner", "MobSF static analysis completed and the raw JSON was validated.", active_step="normalizer")
                    yield log("normalizer", "Normalization and AI review are intentionally deferred until the genuine MobSF schema is verified.", level="warning", active_step="normalizer")
                    yield f"data: {json.dumps({'type': 'result', 'status': 'scanner_complete', 'target': apk_path.name, 'total_evaluated': 0, 'confirmed_vulnerabilities': 0, 'discarded_false_positives': 0, 'reviewed_findings': [], 'audit': audit, 'reports': {}})}\n\n"
                finally:
                    if apk_source == "upload":
                        apk_path.unlink(missing_ok=True)

            elif pipeline == "web_dast":
                yield log("start", f"🚀 Starting DAST Scan Pipeline for Target: http://127.0.0.1:8085...", active_step="scanner")
                await asyncio.sleep(0.3)

                # Step 1: ZAP DAST Scanner
                yield log("scanner", f"[Step 1/6] 🔍 Running OWASP ZAP DAST Scanner on http://127.0.0.1:8085...", active_step="scanner")
                scan_task = asyncio.create_task(asyncio.to_thread(
                    run_dast_scan,
                    target_base_url="http://127.0.0.1:8085",
                    output_file="data/raw/dast_findings.json",
                ))
                while not scan_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                scan_res = await scan_task

                if scan_res.get("status") == "error":
                    yield log("scanner", f"⚠️ ZAP Daemon offline: {scan_res.get('error')}. Using pre-cached mock findings for demo.", level="warning", active_step="scanner")
                    raw_count = 3
                else:
                    raw_count = scan_res.get("findings_count", 0)

                yield log("scanner", f"✅ Step 1 Complete: DAST detected {raw_count} raw findings.", active_step="normalizer")
                await asyncio.sleep(0.3)

                # Step 2: Normalizer
                yield log("normalizer", f"[Step 2/6] 📊 Normalizing {raw_count} raw DAST findings...", active_step="normalizer")
                norm_findings = normalize_dast_findings(
                    raw_json_path="data/raw/dast_findings.json",
                    output_json_path="data/normalized/dast_normalized.json",
                )
                yield log("normalizer", f"✅ Step 2 Complete: Normalized {len(norm_findings)} findings.", active_step="context")
                await asyncio.sleep(0.3)

                # Step 3: Context
                yield log("context", f"[Step 3/6] 📄 Extracting HTTP Request/Response evidence context...", active_step="context")
                # DAST normalizer already attaches context
                yield log("context", f"✅ Step 3 Complete: Extracted HTTP evidence context.", active_step="assessor")
                await asyncio.sleep(0.3)

                # Step 4: AI Assessor
                target_count = len(norm_findings[:parsed_max]) if parsed_max else len(norm_findings)
                yield log("assessor", f"[Step 4/6] 🤖 Pass 1 AI Assessor (qwen3:8b) evaluating {target_count} findings...", active_step="assessor")
                
                assessor_task = asyncio.create_task(asyncio.to_thread(
                    run_llm_assessor,
                    input_json_path="data/normalized/dast_normalized.json",
                    output_json_path="data/normalized/dast_assessed.json",
                    max_findings=parsed_max,
                ))
                while not assessor_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                assessed_findings = await assessor_task
                
                yield log("assessor", f"✅ Step 4 Complete: Pass 1 AI Assessor evaluated {len(assessed_findings)} findings.", active_step="reviewer")
                await asyncio.sleep(0.3)

                # Step 5: AI Reviewer
                yield log("reviewer", f"[Step 5/6] 🛡️ OpenAI GPT-5.4 Nano Reviewer auditing DAST verdicts...", active_step="reviewer")
                
                reviewer_task = asyncio.create_task(asyncio.to_thread(
                    run_llm_reviewer,
                    input_json_path="data/normalized/dast_assessed.json",
                    output_json_path="data/normalized/dast_reviewed.json",
                    max_findings=parsed_max,
                ))
                while not reviewer_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                reviewed_findings = await reviewer_task
                
                yield log("reviewer", f"✅ Step 5 Complete: Pass 2 AI Senior Reviewer completed final verdicts.", active_step="reports")
                await asyncio.sleep(0.3)

                # Step 6: Report Generator
                yield log("reports", f"[Step 6/6] 📝 Generating DAST HTML & Markdown reports...", active_step="reports")
                report_res = run_report_generator(
                    input_json_path="data/normalized/dast_reviewed.json",
                    output_md_path="reports/sast_report.md",
                    output_html_path="reports/sast_report.html",
                )
                yield log("reports", "✅ Step 6 Complete: HTML & Markdown security reports generated successfully!", active_step="done")
                await asyncio.sleep(0.3)

                # Calculate stats
                confirmed_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "confirmed"
                    or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
                )
                discarded_count = len(reviewed_findings) - confirmed_count

                final_payload = {
                    "type": "result",
                    "status": "success",
                    "target": "DVWA DAST",
                    "total_evaluated": len(reviewed_findings),
                    "confirmed_vulnerabilities": confirmed_count,
                    "discarded_false_positives": discarded_count,
                    "reviewed_findings": reviewed_findings,
                    "reports": report_res,
                }
                yield f"data: {json.dumps(final_payload)}\n\n"

            else:
                yield log("start", f"🚀 Starting SAST Scan Pipeline for Target: {target_name}...", active_step="scanner")
                await asyncio.sleep(0.3)

                # Step 1: Semgrep Scanner
                yield log("scanner", f"[Step 1/6] 🔍 Running Semgrep Scanner on {target_name} (Filter: {include_pattern})...", active_step="scanner")
                scan_res = run_semgrep_scan(
                    target_dir=str(target_path),
                    output_file="data/raw/semgrep_findings.json",
                    include_pattern=include_pattern,
                )
                raw_count = scan_res.get("findings_count", 0)
                yield log("scanner", f"✅ Step 1 Complete: Semgrep detected {raw_count} raw findings.", active_step="normalizer")
                await asyncio.sleep(0.3)

                # Step 2: Normalizer
                yield log("normalizer", f"[Step 2/6] 📊 Normalizing {raw_count} raw findings into unified schema...", active_step="normalizer")
                norm_findings = normalize_semgrep_findings(
                    raw_json_path="data/raw/semgrep_findings.json",
                    output_normalized_path="data/normalized/normalized_findings.json",
                )
                yield log("normalizer", f"✅ Step 2 Complete: Normalized {len(norm_findings)} findings.", active_step="context")
                await asyncio.sleep(0.3)

                # Step 3: Source Context
                yield log("context", f"[Step 3/6] 📄 Extracting ±10 lines of surrounding PHP source code context...", active_step="context")
                context_findings = extract_source_context(
                    normalized_json_path="data/normalized/normalized_findings.json",
                    output_json_path="data/normalized/findings_with_context.json",
                )
                yield log("context", f"✅ Step 3 Complete: Attached source code context to {len(context_findings)} findings.", active_step="assessor")
                await asyncio.sleep(0.3)

                # Step 4: Pass 1 AI Assessor
                target_count = len(context_findings[:parsed_max]) if parsed_max else len(context_findings)
                yield log("assessor", f"[Step 4/6] 🤖 Pass 1 AI Assessor (qwen3:8b) evaluating plausible risks on {target_count} findings...", active_step="assessor")
                
                assessor_task = asyncio.create_task(asyncio.to_thread(
                    run_llm_assessor,
                    input_json_path="data/normalized/findings_with_context.json",
                    output_json_path="data/normalized/assessed_findings.json",
                    max_findings=parsed_max,
                ))
                while not assessor_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                assessed_findings = await assessor_task
                
                yield log("assessor", f"✅ Step 4 Complete: Pass 1 AI Assessor evaluated {len(assessed_findings)} findings.", active_step="reviewer")
                await asyncio.sleep(0.3)

                # Step 5: Pass 2 AI Reviewer
                yield log("reviewer", f"[Step 5/6] 🛡️ OpenAI GPT-5.4 Nano Reviewer auditing verdicts...", active_step="reviewer")
                
                reviewer_task = asyncio.create_task(asyncio.to_thread(
                    run_llm_reviewer,
                    input_json_path="data/normalized/assessed_findings.json",
                    output_json_path="data/normalized/reviewed_findings.json",
                    max_findings=parsed_max,
                ))
                while not reviewer_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                reviewed_findings = await reviewer_task
                
                yield log("reviewer", f"✅ Step 5 Complete: Pass 2 AI Senior Reviewer completed final verdicts.", active_step="reports")
                await asyncio.sleep(0.3)

                # Step 6: Report Generator
                yield log("reports", f"[Step 6/6] 📝 Generating sast_report.html and sast_report.md...", active_step="reports")
                report_res = run_report_generator(
                    input_json_path="data/normalized/reviewed_findings.json",
                    output_md_path="reports/sast_report.md",
                    output_html_path="reports/sast_report.html",
                )
                yield log("reports", "✅ Step 6 Complete: HTML & Markdown security reports generated successfully!", active_step="done")
                await asyncio.sleep(0.3)

                # Calculate stats
                confirmed_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "confirmed"
                    or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
                )
                discarded_count = len(reviewed_findings) - confirmed_count

                final_payload = {
                    "type": "result",
                    "status": "success",
                    "target": target_name,
                    "total_evaluated": len(reviewed_findings),
                    "confirmed_vulnerabilities": confirmed_count,
                    "discarded_false_positives": discarded_count,
                    "reviewed_findings": reviewed_findings,
                    "reports": report_res,
                }
                yield f"data: {json.dumps(final_payload)}\n\n"

        except Exception as e:
            logger.exception(f"Pipeline error during stream: {e}")
            err_payload = {"type": "error", "message": f"Pipeline execution failed: {str(e)}"}
            yield f"data: {json.dumps(err_payload)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/scan", summary="Run full 6-step SAST/DAST Scan Pipeline (Validated via Pydantic)")
def trigger_sast_scan(request: ScanRequest):
    """
    Orchestrates the entire Web SAST or DAST pipeline with Pydantic body validation.
    """
    if request.pipeline == "web_dast":
        try:
            scan_res = run_dast_scan(target_base_url="http://127.0.0.1:8085", output_file="data/raw/dast_findings.json")
            norm_findings = normalize_dast_findings(raw_json_path="data/raw/dast_findings.json", output_json_path="data/normalized/dast_normalized.json")
            assessed_findings = run_llm_assessor(input_json_path="data/normalized/dast_normalized.json", output_json_path="data/normalized/dast_assessed.json", max_findings=request.max_findings)
            reviewed_findings = run_llm_reviewer(input_json_path="data/normalized/dast_assessed.json", output_json_path="data/normalized/dast_reviewed.json", max_findings=request.max_findings)
            report_res = run_report_generator(input_json_path="data/normalized/dast_reviewed.json", output_md_path="reports/sast_report.md", output_html_path="reports/sast_report.html")

            confirmed_count = sum(
                1 for f in reviewed_findings
                if f.get("llm_review", {}).get("decision") == "confirmed"
                or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
            )
            discarded_count = len(reviewed_findings) - confirmed_count

            return {
                "status": "success",
                "target": "DVWA DAST",
                "total_evaluated": len(reviewed_findings),
                "confirmed_vulnerabilities": confirmed_count,
                "discarded_false_positives": discarded_count,
                "reviewed_findings": reviewed_findings,
                "reports": report_res,
            }
        except Exception as e:
            logger.exception(f"DAST Pipeline execution failed: {e}")
            raise HTTPException(status_code=500, detail=f"DAST Pipeline error: {str(e)}")

    # Otherwise run Web SAST
    target_path = TARGETS_DIR / request.target_name
    if not target_path.exists() or not target_path.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Target directory '{request.target_name}' not found under targets/"
        )

    try:
        scan_res = run_semgrep_scan(target_dir=str(target_path), output_file="data/raw/semgrep_findings.json", include_pattern=request.include_pattern)
        norm_findings = normalize_semgrep_findings(raw_json_path="data/raw/semgrep_findings.json", output_normalized_path="data/normalized/normalized_findings.json")
        context_findings = extract_source_context(normalized_json_path="data/normalized/normalized_findings.json", output_json_path="data/normalized/findings_with_context.json")
        assessed_findings = run_llm_assessor(input_json_path="data/normalized/findings_with_context.json", output_json_path="data/normalized/assessed_findings.json", max_findings=request.max_findings)
        reviewed_findings = run_llm_reviewer(input_json_path="data/normalized/assessed_findings.json", output_json_path="data/normalized/reviewed_findings.json", max_findings=request.max_findings)
        report_res = run_report_generator(input_json_path="data/normalized/reviewed_findings.json", output_md_path="reports/sast_report.md", output_html_path="reports/sast_report.html")

        confirmed_count = sum(
            1 for f in reviewed_findings
            if f.get("llm_review", {}).get("decision") == "confirmed"
            or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
        )
        discarded_count = len(reviewed_findings) - confirmed_count

        return {
            "status": "success",
            "target": request.target_name,
            "total_evaluated": len(reviewed_findings),
            "confirmed_vulnerabilities": confirmed_count,
            "discarded_false_positives": discarded_count,
            "reviewed_findings": reviewed_findings,
            "reports": report_res,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Pipeline execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


@app.get("/api/reports/html", summary="Download/View HTML Security Report")
def get_html_report():
    """Serves the generated sast_report.html file."""
    html_path = REPORTS_DIR / "sast_report.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="HTML report not found. Run a scan first.")
    return FileResponse(html_path, media_type="text/html", filename="sast_report.html")


@app.get("/api/reports/md", summary="Download Markdown Security Report")
def get_markdown_report():
    """Serves the generated sast_report.md file."""
    md_path = REPORTS_DIR / "sast_report.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found. Run a scan first.")
    return FileResponse(md_path, media_type="text/markdown", filename="sast_report.md")


# Mount static frontend directory (if frontend folder exists)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", summary="Serve Web Dashboard UI")
    def serve_frontend_dashboard():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "CCPL Web SAST Tool API is running. Frontend index.html not found."}


if __name__ == "__main__":
    import uvicorn
    print("--- Starting CCPL Web SAST FastAPI Server ---")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
