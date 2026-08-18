"""Safe Mobile SAST APK discovery, temporary upload, and path resolution."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile


router = APIRouter(tags=["Mobile SAST"])

BASE_DIR = Path(__file__).resolve().parent.parent
TARGETS_DIR = BASE_DIR / "targets"
UPLOADS_DIR = BASE_DIR / "data" / "uploads"
MAX_APK_BYTES = 200 * 1024 * 1024


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def list_target_apks() -> list[dict[str, object]]:
    if not TARGETS_DIR.exists():
        return []
    return [
        {
            "reference": path.relative_to(TARGETS_DIR).as_posix(),
            "name": path.name,
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(TARGETS_DIR.rglob("*.apk"))
        if path.is_file()
    ]


def resolve_mobile_apk(source: str, reference: str) -> Path:
    if source == "target":
        allowed_root = TARGETS_DIR.resolve()
        candidate = (TARGETS_DIR / reference).resolve()
    elif source == "upload":
        try:
            token = uuid.UUID(reference)
        except ValueError as exc:
            raise ValueError("Invalid uploaded APK token") from exc
        allowed_root = UPLOADS_DIR.resolve()
        candidate = (UPLOADS_DIR / f"{token}.apk").resolve()
    else:
        raise ValueError("APK source must be 'target' or 'upload'")

    if not _is_within(candidate, allowed_root):
        raise ValueError("APK path escapes the allowed directory")
    if candidate.suffix.lower() != ".apk" or not candidate.is_file():
        raise FileNotFoundError("Selected APK was not found")
    return candidate


@router.get("/mobile/apks", summary="List APK files already available under targets/")
def list_mobile_apks():
    return {"apks": list_target_apks()}


@router.post("/mobile/apks/upload", summary="Temporarily upload one APK for Mobile SAST")
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
