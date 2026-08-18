"""
Targets Discovery Router for CCPL Web Security Testing Tool.
"""

from pathlib import Path
from fastapi import APIRouter

router = APIRouter(tags=["Targets"])

BASE_DIR = Path(__file__).resolve().parent.parent
TARGETS_DIR = BASE_DIR / "targets"


@router.get("/targets", summary="List available scan targets")
def list_targets():
    """Returns a list of target application folders available inside targets/ directory."""
    if not TARGETS_DIR.exists():
        return {"targets": []}

    targets = [
        item.name for item in TARGETS_DIR.iterdir()
        if item.is_dir() and not item.name.startswith(".")
    ]
    return {"targets": sorted(targets)}
