"""
FastAPI Application Entry Point for CCPL Web Security Testing Tool.

Responsibility:
1. Initialize FastAPI application.
2. Mount modular routers from routers/ package.
3. Serve static frontend dashboard assets (frontend/).
4. Provide local uvicorn server startup entry point.
"""

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from routers.targets import router as targets_router
from routers.reports import router as reports_router
from routers.scan import router as scan_router
from routers.mobile import router as mobile_router

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Initialize FastAPI App
app = FastAPI(
    title="CCPL Web Security Testing Tool API",
    description="Automated AI-Assisted Web SAST, Web DAST, and Mobile SAST Security Testing Tool",
    version="1.0.0",
)

# Register Modular Routers with /api prefix
app.include_router(targets_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(mobile_router, prefix="/api")

# Base Paths for main.py (located at project root)
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

# Mount static frontend directory if present
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", summary="Serve Web Dashboard UI")
    def serve_frontend_dashboard():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "CCPL Web Security Testing Tool API is running. Frontend index.html not found."}


if __name__ == "__main__":
    import uvicorn
    print("--- Starting CCPL Web Security Testing Tool FastAPI Server ---")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
