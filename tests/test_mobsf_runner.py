import hashlib
import json
from pathlib import Path

import httpx
import pytest

from scanners.mobsf_runner import run_static_scan


def test_static_scan_preserves_raw_json_and_writes_safe_audit_log(tmp_path: Path) -> None:
    apk = tmp_path / "DivaApplication.apk"
    apk.write_bytes(b"fake-apk-for-contract-test")
    raw_report = b'{"app_name":"DIVA","manifest_analysis":[{"severity":"high"}]}'
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers["Authorization"] == "test-secret"
        if request.url.path == "/api/v1/upload":
            return httpx.Response(
                200,
                json={"hash": "abc123", "scan_type": "apk", "file_name": apk.name},
            )
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(200, content=raw_report)
        return httpx.Response(404)

    output = tmp_path / "raw" / "mobsf.json"
    log = tmp_path / "raw" / "mobsf_scan.log"
    audit = run_static_scan(
        apk,
        output,
        log,
        base_url="http://mobsf.local:8000",
        api_key="test-secret",
        transport=httpx.MockTransport(handler),
    )

    assert calls == ["/api/v1/upload", "/api/v1/scan", "/api/v1/report_json"]
    assert output.read_bytes() == raw_report
    assert json.loads(output.read_text(encoding="utf-8"))["app_name"] == "DIVA"
    assert audit["apk_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert audit["raw_report_sha256"] == hashlib.sha256(raw_report).hexdigest()
    assert "test-secret" not in log.read_text(encoding="utf-8")


def test_static_scan_can_force_mobsf_rescan(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK-test")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "abc", "scan_type": "apk", "file_name": apk.name})
        if request.url.path == "/api/v1/scan":
            assert b"re_scan=1" in request.content
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"app_name": "sample"})

    audit = run_static_scan(
        apk,
        tmp_path / "out.json",
        tmp_path / "scan.log",
        base_url="http://mobsf.local:8000",
        api_key="key",
        force_rescan=True,
        transport=httpx.MockTransport(handler),
    )
    assert audit["force_rescan"] is True


def test_static_scan_rejects_missing_apk(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="APK does not exist"):
        run_static_scan(
            tmp_path / "missing.apk",
            tmp_path / "out.json",
            tmp_path / "scan.log",
            base_url="http://127.0.0.1:8000",
            api_key="key",
        )


def test_static_scan_requires_api_key(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    with pytest.raises(ValueError, match="MOBSF_API_KEY is required"):
        run_static_scan(
            apk,
            tmp_path / "out.json",
            tmp_path / "scan.log",
            base_url="http://127.0.0.1:8000",
            api_key="",
        )
