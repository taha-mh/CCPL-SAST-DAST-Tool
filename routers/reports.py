"""
Reports Delivery Router for CCPL Web Security Testing Tool.
"""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(tags=["Reports"])

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


@router.get("/reports/html", summary="Download/View HTML Security Report")
def get_html_report():
    """Serves the generated sast_report.html file."""
    html_path = REPORTS_DIR / "sast_report.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="HTML report not found. Run a scan first.")
    return FileResponse(html_path, media_type="text/html", filename="sast_report.html")


@router.get("/reports/md", summary="Download Markdown Security Report")
def get_markdown_report():
    """Serves the generated sast_report.md file."""
    md_path = REPORTS_DIR / "sast_report.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found. Run a scan first.")
    return FileResponse(md_path, media_type="text/markdown", filename="sast_report.md")


@router.get("/reports/mobile/html", summary="View the Mobile SAST HTML report")
def get_mobile_html_report():
    html_path = REPORTS_DIR / "mobile_sast_report.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Mobile SAST HTML report not found. Run a mobile scan first.")
    return FileResponse(html_path, media_type="text/html", filename="mobile_sast_report.html")


@router.get("/reports/mobile/md", summary="Download the Mobile SAST Markdown report")
def get_mobile_markdown_report():
    md_path = REPORTS_DIR / "mobile_sast_report.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="Mobile SAST Markdown report not found. Run a mobile scan first.")
    return FileResponse(md_path, media_type="text/markdown", filename="mobile_sast_report.md")
