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
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Import our SAST Pipeline Modules
from scanners.semgrep_runner import run_semgrep_scan
from parsers.semgrep_normalizer import normalize_semgrep_findings
from parsers.source_context import extract_source_context
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


@app.get("/api/scan/stream", summary="Stream full 6-step SAST Scan Pipeline with real-time logs")
async def stream_sast_scan(
    target_name: str = Query(default="DVWA"),
    max_findings: Optional[str] = Query(default="3"),
    include_pattern: Optional[str] = Query(default="*.php"),
):
    """
    Streams real-time logs for the 6-step SAST pipeline to the frontend via Server-Sent Events (SSE).
    """
    target_path = TARGETS_DIR / target_name
    if not target_path.exists() or not target_path.is_dir():
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
            yield log("reviewer", f"[Step 5/6] 🛡️ Pass 2 AI Senior Reviewer auditing verdicts for false-positive elimination...", active_step="reviewer")
            
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
