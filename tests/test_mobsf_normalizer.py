import json
from pathlib import Path

from parsers.mobsf_normalizer import normalize_mobsf_findings


def test_normalizer_preserves_sections_and_attaches_source_context(tmp_path: Path) -> None:
    report = {
        "file_name": "Diva.apk",
        "package_name": "example.diva",
        "sha256": "abc",
        "manifest_analysis": {
            "manifest_findings": [{
                "rule": "app_is_debuggable",
                "title": "Debug enabled",
                "severity": "high",
                "description": "Debugging is enabled.",
                "component": [],
            }]
        },
        "code_analysis": {
            "findings": {
                "android_sql_raw_query": {
                    "files": {"example/Sql.java": "7"},
                    "metadata": {
                        "severity": "warning",
                        "cwe": "CWE-89",
                        "description": "Raw SQL query used.",
                    },
                }
            }
        },
        "certificate_analysis": {
            "certificate_info": "debug certificate",
            "certificate_findings": [["high", "Debug certificate used.", "Debug certificate"]],
        },
        "permissions": {
            "android.permission.INTERNET": {
                "status": "normal",
                "description": "Network access.",
            }
        },
        "binary_analysis": [{
            "name": "lib/test.so",
            "nx": {"severity": "high", "description": "NX is disabled."},
        }],
    }
    source = "\n".join(f"line {number}" for number in range(1, 14))
    raw_path = tmp_path / "mobsf.json"
    source_path = tmp_path / "sources.json"
    output_path = tmp_path / "findings.json"
    raw_path.write_text(json.dumps(report), encoding="utf-8")
    source_path.write_text(json.dumps({"example/Sql.java": {"data": source}}), encoding="utf-8")

    findings = normalize_mobsf_findings(raw_path, output_path, source_path)

    assert len(findings) == 5
    assert {item["category"] for item in findings} == {
        "manifest", "code", "certificate", "permission", "binary",
    }
    code = next(item for item in findings if item["category"] == "code")
    assert code["scanner_severity"] == "MEDIUM"
    assert "    7: line 7" in code["evidence_context"]
    assert code["raw_evidence"]["files"] == {"example/Sql.java": "7"}
    assert json.loads(output_path.read_text(encoding="utf-8")) == findings


def test_finding_ids_are_stable(tmp_path: Path) -> None:
    report = {
        "manifest_analysis": {"manifest_findings": [{
            "rule": "backup", "title": "Backup", "severity": "warning", "description": "Enabled",
        }]}
    }
    raw_path = tmp_path / "mobsf.json"
    raw_path.write_text(json.dumps(report), encoding="utf-8")

    first = normalize_mobsf_findings(raw_path, tmp_path / "one.json", None)
    second = normalize_mobsf_findings(raw_path, tmp_path / "two.json", None)

    assert first[0]["finding_id"] == second[0]["finding_id"]
