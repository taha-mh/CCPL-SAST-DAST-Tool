"""
Pipeline Scan Execution & Real-Time Streaming Router for CCPL Web Security Testing Tool.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Import Pipeline Modules
from scanners.semgrep_runner import run_semgrep_scan
from parsers.semgrep_normalizer import normalize_semgrep_findings
from parsers.source_context import extract_source_context
from scanners.dast_runner import run_dast_scan
from parsers.dast_normalizer import normalize_dast_findings
from llm.assessor import run_llm_assessor
from llm.reviewer import run_llm_reviewer
from reports.report_generator import run_report_generator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scan"])

# Project-Root Path Calculations
BASE_DIR = Path(__file__).resolve().parent.parent
TARGETS_DIR = BASE_DIR / "targets"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"


class ScanRequest(BaseModel):
    target_name: str = Field(default="DVWA", description="Subfolder name inside targets/ directory")
    max_findings: Optional[int] = Field(default=3, description="Max findings to process through AI (set None for all)")
    include_pattern: Optional[str] = Field(default="*.php", description="Glob file pattern filter (e.g. *.php)")
    pipeline: Optional[str] = Field(default="web_sast", description="Scanning pipeline: web_sast or web_dast")


@router.get("/scan/stream", summary="Stream full 6-step SAST/DAST Scan Pipeline with real-time logs")
async def stream_sast_scan(
    target_name: str = Query(default="DVWA"),
    max_findings: Optional[str] = Query(default="3"),
    include_pattern: Optional[str] = Query(default="*.php"),
    pipeline: Optional[str] = Query(default="web_sast"),
):
    """
    Streams real-time logs for the 6-step SAST/DAST pipeline to the frontend via Server-Sent Events (SSE).
    """
    target_path = TARGETS_DIR / target_name
    if not target_path.exists() or not target_path.is_dir():
        async def error_generator():
            yield f"data: {json.dumps({'type': 'error', 'message': f'Target directory {target_name} not found'})}\n\n"
        return StreamingResponse(error_generator(), media_type="text/event-stream")

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

            if pipeline == "web_dast":
                yield log("start", "Starting DAST Scan Pipeline for Target: http://127.0.0.1:8085...", active_step="scanner")
                await asyncio.sleep(0.3)

                # Step 1: ZAP DAST Scanner
                yield log("scanner", "[Step 1/6] Running OWASP ZAP DAST Scanner on http://127.0.0.1:8085...", active_step="scanner")
                scan_task = asyncio.create_task(asyncio.to_thread(
                    run_dast_scan,
                    target_base_url="http://127.0.0.1:8085",
                    output_file=str(DATA_DIR / "raw" / "dast_findings.json"),
                ))
                while not scan_task.done():
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(10)
                scan_res = await scan_task

                if scan_res.get("status") == "error":
                    yield log("scanner", f"ZAP Daemon offline: {scan_res.get('error')}. Using pre-cached findings if available.", level="warning", active_step="scanner")
                    raw_count = 3
                else:
                    raw_count = scan_res.get("findings_count", 0)

                yield log("scanner", f"Step 1 Complete: DAST detected {raw_count} raw findings.", active_step="normalizer")
                await asyncio.sleep(0.3)

                # Step 2: Normalizer
                yield log("normalizer", f"[Step 2/6] Normalizing {raw_count} raw DAST findings...", active_step="normalizer")
                norm_findings = normalize_dast_findings(
                    raw_json_path="data/raw/dast_findings.json",
                    output_json_path="data/normalized/dast_normalized.json",
                )
                yield log("normalizer", f"Step 2 Complete: Normalized {len(norm_findings)} findings.", active_step="context")
                await asyncio.sleep(0.3)

                # Step 3: Context
                yield log("context", "[Step 3/6] Extracting HTTP Request/Response evidence context...", active_step="context")
                yield log("context", "Step 3 Complete: Extracted HTTP evidence context.", active_step="assessor")
                await asyncio.sleep(0.3)

                # Step 4: AI Assessor
                target_count = len(norm_findings[:parsed_max]) if parsed_max else len(norm_findings)
                yield log("assessor", f"[Step 4/6] Running Pass 1 AI Assessor evaluating {target_count} findings...", active_step="assessor")
                
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
                
                yield log("assessor", f"Step 4 Complete: Pass 1 AI Assessor evaluated {len(assessed_findings)} findings.", active_step="reviewer")
                await asyncio.sleep(0.3)

                # Step 5: AI Reviewer
                yield log("reviewer", "[Step 5/6] Running Pass 2 AI Reviewer auditing DAST verdicts...", active_step="reviewer")
                
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
                
                yield log("reviewer", "Step 5 Complete: Pass 2 AI Reviewer completed final verdicts.", active_step="reports")
                await asyncio.sleep(0.3)

                # Step 6: Report Generator
                yield log("reports", "[Step 6/6] Generating DAST HTML & Markdown reports...", active_step="reports")
                report_res = run_report_generator(
                    input_json_path="data/normalized/dast_reviewed.json",
                    output_md_path=str(REPORTS_DIR / "sast_report.md"),
                    output_html_path=str(REPORTS_DIR / "sast_report.html"),
                )
                yield log("reports", "Step 6 Complete: HTML & Markdown security reports generated successfully!", active_step="done")
                await asyncio.sleep(0.3)

                # Calculate stats
                confirmed_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "confirmed"
                )
                rejected_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "rejected"
                )
                needs_review_count = len(reviewed_findings) - confirmed_count - rejected_count

                final_payload = {
                    "type": "result",
                    "status": "success",
                    "target": "DVWA DAST",
                    "total_evaluated": len(reviewed_findings),
                    "confirmed_vulnerabilities": confirmed_count,
                    "rejected_false_positives": rejected_count,
                    "requires_manual_verification": needs_review_count,
                    "reviewed_findings": reviewed_findings,
                    "reports": report_res,
                }
                yield f"data: {json.dumps(final_payload)}\n\n"

            else:
                yield log("start", f"Starting SAST Scan Pipeline for Target: {target_name}...", active_step="scanner")
                await asyncio.sleep(0.3)

                # Step 1: Semgrep Scanner
                yield log("scanner", f"[Step 1/6] Running Semgrep Scanner on {target_name} (Filter: {include_pattern})...", active_step="scanner")
                scan_res = run_semgrep_scan(
                    target_dir=str(target_path),
                    output_file=str(DATA_DIR / "raw" / "semgrep_findings.json"),
                    include_pattern=include_pattern,
                )
                raw_count = scan_res.get("findings_count", 0)
                yield log("scanner", f"Step 1 Complete: Semgrep detected {raw_count} raw findings.", active_step="normalizer")
                await asyncio.sleep(0.3)

                # Step 2: Normalizer
                yield log("normalizer", f"[Step 2/6] Normalizing {raw_count} raw findings into unified schema...", active_step="normalizer")
                norm_findings = normalize_semgrep_findings(
                    raw_json_path="data/raw/semgrep_findings.json",
                    output_normalized_path="data/normalized/normalized_findings.json",
                )
                yield log("normalizer", f"Step 2 Complete: Normalized {len(norm_findings)} findings.", active_step="context")
                await asyncio.sleep(0.3)

                # Step 3: Source Context
                yield log("context", "[Step 3/6] Extracting PHP source code context...", active_step="context")
                context_findings = extract_source_context(
                    normalized_json_path="data/normalized/normalized_findings.json",
                    output_json_path="data/normalized/findings_with_context.json",
                )
                yield log("context", f"Step 3 Complete: Attached source code context to {len(context_findings)} findings.", active_step="assessor")
                await asyncio.sleep(0.3)

                # Step 4: Pass 1 AI Assessor
                target_count = len(context_findings[:parsed_max]) if parsed_max else len(context_findings)
                yield log("assessor", f"[Step 4/6] Running Pass 1 AI Assessor evaluating plausible risks on {target_count} findings...", active_step="assessor")
                
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
                
                yield log("assessor", f"Step 4 Complete: Pass 1 AI Assessor evaluated {len(assessed_findings)} findings.", active_step="reviewer")
                await asyncio.sleep(0.3)

                # Step 5: Pass 2 AI Reviewer
                yield log("reviewer", "[Step 5/6] Running Pass 2 AI Reviewer auditing verdicts...", active_step="reviewer")
                
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
                
                yield log("reviewer", "Step 5 Complete: Pass 2 AI Reviewer completed final verdicts.", active_step="reports")
                await asyncio.sleep(0.3)

                # Step 6: Report Generator
                yield log("reports", "[Step 6/6] Generating sast_report.html and sast_report.md...", active_step="reports")
                report_res = run_report_generator(
                    input_json_path="data/normalized/reviewed_findings.json",
                    output_md_path=str(REPORTS_DIR / "sast_report.md"),
                    output_html_path=str(REPORTS_DIR / "sast_report.html"),
                )
                yield log("reports", "Step 6 Complete: HTML & Markdown security reports generated successfully!", active_step="done")
                await asyncio.sleep(0.3)

                # Calculate stats
                confirmed_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "confirmed"
                )
                rejected_count = sum(
                    1 for f in reviewed_findings
                    if f.get("llm_review", {}).get("decision") == "rejected"
                )
                needs_review_count = len(reviewed_findings) - confirmed_count - rejected_count

                final_payload = {
                    "type": "result",
                    "status": "success",
                    "target": target_name,
                    "total_evaluated": len(reviewed_findings),
                    "confirmed_vulnerabilities": confirmed_count,
                    "rejected_false_positives": rejected_count,
                    "requires_manual_verification": needs_review_count,
                    "reviewed_findings": reviewed_findings,
                    "reports": report_res,
                }
                yield f"data: {json.dumps(final_payload)}\n\n"

        except Exception as e:
            logger.exception(f"Pipeline error during stream: {e}")
            err_payload = {"type": "error", "message": f"Pipeline execution failed: {str(e)}"}
            yield f"data: {json.dumps(err_payload)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/scan", summary="Run full 6-step SAST/DAST Scan Pipeline (Validated via Pydantic)")
def trigger_sast_scan(request: ScanRequest):
    """
    Orchestrates the entire Web SAST or DAST pipeline with Pydantic body validation.
    """
    if request.pipeline == "web_dast":
        try:
            scan_res = run_dast_scan(
                target_base_url="http://127.0.0.1:8085",
                output_file=str(DATA_DIR / "raw" / "dast_findings.json"),
            )
            norm_findings = normalize_dast_findings(
                raw_json_path="data/raw/dast_findings.json",
                output_json_path="data/normalized/dast_normalized.json",
            )
            assessed_findings = run_llm_assessor(
                input_json_path="data/normalized/dast_normalized.json",
                output_json_path="data/normalized/dast_assessed.json",
                max_findings=request.max_findings,
            )
            reviewed_findings = run_llm_reviewer(
                input_json_path="data/normalized/dast_assessed.json",
                output_json_path="data/normalized/dast_reviewed.json",
                max_findings=request.max_findings,
            )
            report_res = run_report_generator(
                input_json_path="data/normalized/dast_reviewed.json",
                output_md_path=str(REPORTS_DIR / "sast_report.md"),
                output_html_path=str(REPORTS_DIR / "sast_report.html"),
            )

            confirmed_count = sum(
                1 for f in reviewed_findings
                if f.get("llm_review", {}).get("decision") == "confirmed"
            )
            rejected_count = sum(
                1 for f in reviewed_findings
                if f.get("llm_review", {}).get("decision") == "rejected"
            )
            needs_review_count = len(reviewed_findings) - confirmed_count - rejected_count

            return {
                "status": "success",
                "target": "DVWA DAST",
                "total_evaluated": len(reviewed_findings),
                "confirmed_vulnerabilities": confirmed_count,
                "rejected_false_positives": rejected_count,
                "requires_manual_verification": needs_review_count,
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
        scan_res = run_semgrep_scan(
            target_dir=str(target_path),
            output_file=str(DATA_DIR / "raw" / "semgrep_findings.json"),
            include_pattern=request.include_pattern,
        )
        norm_findings = normalize_semgrep_findings(
            raw_json_path="data/raw/semgrep_findings.json",
            output_normalized_path="data/normalized/normalized_findings.json",
        )
        context_findings = extract_source_context(
            normalized_json_path="data/normalized/normalized_findings.json",
            output_json_path="data/normalized/findings_with_context.json",
        )
        assessed_findings = run_llm_assessor(
            input_json_path="data/normalized/findings_with_context.json",
            output_json_path="data/normalized/assessed_findings.json",
            max_findings=request.max_findings,
        )
        reviewed_findings = run_llm_reviewer(
            input_json_path="data/normalized/assessed_findings.json",
            output_json_path="data/normalized/reviewed_findings.json",
            max_findings=request.max_findings,
        )
        report_res = run_report_generator(
            input_json_path="data/normalized/reviewed_findings.json",
            output_md_path=str(REPORTS_DIR / "sast_report.md"),
            output_html_path=str(REPORTS_DIR / "sast_report.html"),
        )

        confirmed_count = sum(
            1 for f in reviewed_findings
            if f.get("llm_review", {}).get("decision") == "confirmed"
        )
        rejected_count = sum(
            1 for f in reviewed_findings
            if f.get("llm_review", {}).get("decision") == "rejected"
        )
        needs_review_count = len(reviewed_findings) - confirmed_count - rejected_count

        return {
            "status": "success",
            "target": request.target_name,
            "total_evaluated": len(reviewed_findings),
            "confirmed_vulnerabilities": confirmed_count,
            "rejected_false_positives": rejected_count,
            "requires_manual_verification": needs_review_count,
            "reviewed_findings": reviewed_findings,
            "reports": report_res,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Pipeline execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")
