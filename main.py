"""
FastAPI Server for CCPL Web SAST Application.

Responsibility:
1. Provide REST API endpoints for frontend UI interaction.
2. List available scan targets in targets/ directory.
3. Orchestrate full 6-step SAST pipeline upon scan request.
4. Serve static frontend dashboard assets (frontend/).
5. Provide downloadable HTML and Markdown report files.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
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


# --- Pydantic Data Models ---
class ScanRequest(BaseModel):
    target_name: str = Field(default="DVWA", description="Subfolder name inside targets/ directory")
    max_findings: Optional[int] = Field(default=3, description="Max findings to process through AI (set None for all)")
    include_pattern: Optional[str] = Field(default="*.php", description="Glob file pattern filter (e.g. *.php)")


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


@app.post("/api/scan", summary="Run full 6-step SAST Scan Pipeline")
def trigger_sast_scan(request: ScanRequest):
    """
    Orchestrates the entire Web SAST pipeline:
    1. Semgrep Scanner Wrapper
    2. Semgrep Normalizer
    3. Source Context Extractor
    4. Pass 1 LLM Assessor
    5. Pass 2 LLM Reviewer
    6. Report Generator
    """
    target_path = TARGETS_DIR / request.target_name
    if not target_path.exists() or not target_path.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Target directory '{request.target_name}' not found under targets/"
        )

    logger.info(f"--- Starting Full SAST Scan Pipeline for Target: {request.target_name} ---")

    try:
        # Step 1: Semgrep Scanner
        logger.info("[Step 1/6] Running Semgrep Scanner...")
        scan_res = run_semgrep_scan(
            target_dir=str(target_path),
            output_file="data/raw/semgrep_findings.json",   
            include_pattern=request.include_pattern,
        )
        if scan_res.get("status") == "error":
            raise HTTPException(status_code=500, detail=f"Semgrep scanner failed: {scan_res.get('error')}")

        # Step 2: Findings Normalizer
        logger.info("[Step 2/6] Normalizing Semgrep Findings...")
        norm_findings = normalize_semgrep_findings(
            raw_json_path="data/raw/semgrep_findings.json",
            output_normalized_path="data/normalized/normalized_findings.json",
        )

        # Step 3: Source Context Extractor
        logger.info("[Step 3/6] Extracting Source Code Context...")
        context_findings = extract_source_context(
            normalized_json_path="data/normalized/normalized_findings.json",
            output_json_path="data/normalized/findings_with_context.json",
        )

        # Step 4: Pass 1 LLM Assessor
        logger.info(f"[Step 4/6] Running Pass 1 LLM Assessor (max_findings={request.max_findings})...")
        assessed_findings = run_llm_assessor(
            input_json_path="data/normalized/findings_with_context.json",
            output_json_path="data/normalized/assessed_findings.json",
            max_findings=request.max_findings,
        )

        # Step 5: Pass 2 LLM Reviewer
        logger.info(f"[Step 5/6] Running Pass 2 LLM Reviewer (max_findings={request.max_findings})...")
        reviewed_findings = run_llm_reviewer(
            input_json_path="data/normalized/assessed_findings.json",
            output_json_path="data/normalized/reviewed_findings.json",
            max_findings=request.max_findings,
        )

        # Step 6: Report Generator
        logger.info("[Step 6/6] Generating Security Reports (HTML & Markdown)...")
        report_res = run_report_generator(
            input_json_path="data/normalized/reviewed_findings.json",
            output_md_path="reports/sast_report.md",
            output_html_path="reports/sast_report.html",
        )

        # Calculate summary stats for response
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
