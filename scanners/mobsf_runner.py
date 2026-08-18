"""Run a MobSF static APK scan and preserve its raw JSON report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


DEFAULT_URL = "http://127.0.0.1:8000"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(client: httpx.Client, path: str, **kwargs: Any) -> httpx.Response:
    response = client.post(path, **kwargs)
    response.raise_for_status()
    return response


def run_static_scan(
    apk_path: Path,
    output_path: Path,
    log_path: Path,
    *,
    base_url: str,
    api_key: str,
    timeout_seconds: float = 900.0,
    force_rescan: bool = False,
    source_output_path: Path | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Upload and statically scan one APK through the MobSF REST API."""
    apk_path = apk_path.resolve()
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK does not exist: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        raise ValueError(f"Expected an .apk file: {apk_path}")
    if not api_key.strip():
        raise ValueError("MOBSF_API_KEY is required")

    started_at = _utc_now()
    apk_sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    headers = {"Authorization": api_key}

    with httpx.Client(
        base_url=base_url.rstrip("/"),
        headers=headers,
        timeout=timeout_seconds,
        follow_redirects=True,
        transport=transport,
    ) as client:
        with apk_path.open("rb") as apk_file:
            upload_response = _post(
                client,
                "/api/v1/upload",
                files={"file": (apk_path.name, apk_file, "application/octet-stream")},
            )
            upload = upload_response.json()

        required = ("hash", "scan_type", "file_name")
        missing = [field for field in required if not upload.get(field)]
        if missing:
            raise ValueError(f"MobSF upload response missing: {', '.join(missing)}")

        scan_data = {field: upload[field] for field in required}
        if force_rescan:
            scan_data["re_scan"] = "1"
        scan_response = _post(client, "/api/v1/scan", data=scan_data)
        report_response = _post(
            client,
            "/api/v1/report_json",
            data={"hash": upload["hash"]},
        )

    # Parse before writing so an HTML/error body can never masquerade as raw JSON.
    report = report_response.json()
    if not isinstance(report, dict):
        raise ValueError("MobSF report JSON must be an object")

    source_records: dict[str, Any] = {}
    if source_output_path is not None:
        code_findings = (report.get("code_analysis") or {}).get("findings") or {}
        source_files = sorted({
            str(file_path)
            for finding in code_findings.values()
            if isinstance(finding, dict)
            for file_path in (finding.get("files") or {})
        })
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout_seconds,
            follow_redirects=True,
            transport=transport,
        ) as client:
            for file_path in source_files:
                source_response = _post(
                    client,
                    "/api/v1/view_source",
                    data={"file": file_path, "type": "apk", "hash": upload["hash"]},
                )
                source_payload = source_response.json()
                if not isinstance(source_payload, dict) or not isinstance(source_payload.get("data"), str):
                    raise ValueError(f"MobSF source response was invalid for {file_path}")
                source_records[file_path] = source_payload

    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(report_response.content)
    if source_output_path is not None:
        source_output_path.parent.mkdir(parents=True, exist_ok=True)
        source_output_path.write_text(
            json.dumps(source_records, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    audit = {
        "scanner": "MobSF",
        "mode": "static",
        "started_at_utc": started_at,
        "completed_at_utc": _utc_now(),
        "base_url": base_url.rstrip("/"),
        "apk_path": str(apk_path),
        "apk_sha256": apk_sha256,
        "mobsf_scan_hash": upload["hash"],
        "scan_type": upload["scan_type"],
        "force_rescan": force_rescan,
        "upload_http_status": upload_response.status_code,
        "scan_http_status": scan_response.status_code,
        "report_http_status": report_response.status_code,
        "raw_report_path": str(output_path.resolve()),
        "raw_report_sha256": hashlib.sha256(report_response.content).hexdigest(),
        "raw_json_valid": True,
        "source_evidence_files": len(source_records),
        "source_evidence_path": str(source_output_path.resolve()) if source_output_path else None,
        "api_key_recorded": False,
    }
    log_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    return audit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/raw/mobsf.json"))
    parser.add_argument("--log", type=Path, default=Path("data/raw/mobsf_scan.log"))
    parser.add_argument("--url", default=os.getenv("MOBSF_URL", DEFAULT_URL))
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--force-rescan", action="store_true")
    parser.add_argument("--sources", type=Path, default=Path("data/raw/mobsf_sources.json"))
    args = parser.parse_args()

    try:
        audit = run_static_scan(
            args.apk,
            args.output,
            args.log,
            base_url=args.url,
            api_key=os.getenv("MOBSF_API_KEY", ""),
            timeout_seconds=args.timeout,
            force_rescan=args.force_rescan,
            source_output_path=args.sources,
        )
    except (OSError, ValueError, httpx.HTTPError) as exc:
        print(f"MobSF static scan failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(audit, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
