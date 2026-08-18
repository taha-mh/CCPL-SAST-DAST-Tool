from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main


client = TestClient(main.app)


def test_target_apk_resolution_stays_inside_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    targets = tmp_path / "targets"
    apk = targets / "DIVA" / "DivaApplication.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"PK-test")
    monkeypatch.setattr(main, "TARGETS_DIR", targets)

    assert main.resolve_mobile_apk("target", "DIVA/DivaApplication.apk") == apk.resolve()
    assert main.list_target_apks() == [{
        "reference": "DIVA/DivaApplication.apk",
        "name": "DivaApplication.apk",
        "size_bytes": 7,
    }]


def test_target_apk_resolution_rejects_directory_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    targets = tmp_path / "targets"
    targets.mkdir()
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"PK-test")
    monkeypatch.setattr(main, "TARGETS_DIR", targets)

    with pytest.raises(ValueError, match="escapes"):
        main.resolve_mobile_apk("target", "../outside.apk")


def test_upload_reference_must_be_uuid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "UPLOADS_DIR", tmp_path / "uploads")
    with pytest.raises(ValueError, match="Invalid uploaded APK token"):
        main.resolve_mobile_apk("upload", "../../secret.apk")


def test_upload_endpoint_stores_apk_under_opaque_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    uploads = tmp_path / "uploads"
    monkeypatch.setattr(main, "UPLOADS_DIR", uploads)

    response = client.post(
        "/api/mobile/apks/upload",
        files={"file": ("customer-app.apk", b"PK-valid-test-apk", "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["filename"] == "customer-app.apk"
    stored = main.resolve_mobile_apk("upload", payload["token"])
    assert stored.parent == uploads.resolve()
    assert stored.name != "customer-app.apk"


def test_upload_endpoint_rejects_non_apk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "UPLOADS_DIR", tmp_path / "uploads")
    response = client.post(
        "/api/mobile/apks/upload",
        files={"file": ("notes.txt", b"not an apk", "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Only .apk files are accepted"
