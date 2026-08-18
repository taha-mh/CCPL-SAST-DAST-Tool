"""Normalize MobSF Android static-analysis JSON into auditable findings."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "warning": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "normal": "INFO",
    "dangerous": "MEDIUM",
}


def _severity(value: Any) -> str:
    return SEVERITY_MAP.get(str(value).strip().lower(), "INFO")


def _finding_id(section: str, rule_id: str, location: str, raw: Any) -> str:
    identity = json.dumps([section, rule_id, location, raw], sort_keys=True, default=str)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    return f"MOBSF-{digest}"


def _line_numbers(value: Any) -> list[int]:
    numbers = []
    for part in str(value or "").replace("-", ",").split(","):
        try:
            number = int(part.strip())
        except ValueError:
            continue
        if number > 0 and number not in numbers:
            numbers.append(number)
    return numbers


def _source_context(source: str, lines: Iterable[int], radius: int = 5) -> str:
    source_lines = source.splitlines()
    selected: set[int] = set()
    for line in lines:
        selected.update(range(max(1, line - radius), min(len(source_lines), line + radius) + 1))
    return "\n".join(f"{line:>5}: {source_lines[line - 1]}" for line in sorted(selected))


def _base(
    report: dict[str, Any],
    *,
    category: str,
    rule_id: str,
    title: str,
    severity: Any,
    location: str,
    message: str,
    evidence_context: str,
    metadata: dict[str, Any],
    raw_evidence: Any,
) -> dict[str, Any]:
    return {
        "finding_id": _finding_id(category, rule_id, location, raw_evidence),
        "tool": "MobSF",
        "scan_type": "mobile_sast",
        "category": category,
        "rule_id": rule_id,
        "title": title,
        "message": message,
        "scanner_severity": _severity(severity),
        "scanner_severity_original": str(severity),
        "target": report.get("file_name") or report.get("app_name") or "Android APK",
        "package_name": report.get("package_name"),
        "apk_sha256": report.get("sha256"),
        "location": location,
        "evidence_context": evidence_context,
        "metadata": metadata,
        "raw_evidence": raw_evidence,
    }


def normalize_mobsf_findings(
    raw_json_path: str | Path = "data/raw/mobsf.json",
    output_json_path: str | Path = "data/normalized/mobile_findings.json",
    source_json_path: str | Path | None = "data/raw/mobsf_sources.json",
) -> list[dict[str, Any]]:
    """Transform MobSF output only; no vulnerability confirmation occurs here."""
    raw_path = Path(raw_json_path)
    report = json.loads(raw_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("MobSF raw JSON must contain an object")

    sources: dict[str, str] = {}
    if source_json_path:
        source_path = Path(source_json_path)
        if source_path.exists():
            source_payload = json.loads(source_path.read_text(encoding="utf-8"))
            if isinstance(source_payload, dict):
                sources = {
                    str(path): str(value.get("data", "") if isinstance(value, dict) else value)
                    for path, value in source_payload.items()
                }

    findings: list[dict[str, Any]] = []
    manifest = report.get("manifest_analysis") or {}
    for raw in manifest.get("manifest_findings", []):
        if not isinstance(raw, dict):
            continue
        component = raw.get("component") or []
        component_text = ": ".join(str(item) for item in component) if component else "application"
        evidence = f"AndroidManifest.xml\nComponent: {component_text}\nObserved configuration: {raw.get('name') or raw.get('title')}"
        findings.append(_base(
            report,
            category="manifest",
            rule_id=str(raw.get("rule") or "manifest_finding"),
            title=str(raw.get("title") or raw.get("name") or "Manifest finding"),
            severity=raw.get("severity"),
            location="AndroidManifest.xml",
            message=str(raw.get("description") or ""),
            evidence_context=evidence,
            metadata={"component": component},
            raw_evidence=raw,
        ))

    code = report.get("code_analysis") or {}
    code_findings = code.get("findings") or {}
    for rule_id, raw in code_findings.items():
        if not isinstance(raw, dict):
            continue
        metadata = raw.get("metadata") or {}
        files = raw.get("files") or {}
        context_blocks = []
        for file_path, line_spec in files.items():
            lines = _line_numbers(line_spec)
            header = f"File: {file_path}; reported lines: {', '.join(map(str, lines)) or line_spec}"
            snippet = _source_context(sources[file_path], lines) if file_path in sources else ""
            context_blocks.append(f"{header}\n{snippet}".rstrip())
        evidence = "\n\n".join(context_blocks) or str(metadata.get("description") or "No code location supplied")
        findings.append(_base(
            report,
            category="code",
            rule_id=str(rule_id),
            title=str(metadata.get("cwe") or rule_id).replace("_", " "),
            severity=metadata.get("severity"),
            location=", ".join(files) or "decompiled source",
            message=str(metadata.get("description") or ""),
            evidence_context=evidence,
            metadata={**metadata, "affected_files": files},
            raw_evidence=raw,
        ))

    certificate = report.get("certificate_analysis") or {}
    for index, raw in enumerate(certificate.get("certificate_findings", []), start=1):
        if not isinstance(raw, list) or len(raw) < 3:
            continue
        severity, message, title = raw[:3]
        evidence = f"{message}\n\nCertificate details:\n{certificate.get('certificate_info', '')}"
        findings.append(_base(
            report,
            category="certificate",
            rule_id=f"certificate_{index}",
            title=str(title),
            severity=severity,
            location="APK signing certificate",
            message=str(message),
            evidence_context=evidence,
            metadata={},
            raw_evidence=raw,
        ))

    for permission, raw in (report.get("permissions") or {}).items():
        if not isinstance(raw, dict):
            continue
        evidence = f"Declared permission: {permission}\nClassification: {raw.get('status')}\nPurpose: {raw.get('description') or raw.get('info')}"
        findings.append(_base(
            report,
            category="permission",
            rule_id=str(permission),
            title=f"Declared Android permission: {permission}",
            severity=raw.get("status"),
            location="AndroidManifest.xml",
            message=str(raw.get("description") or raw.get("info") or ""),
            evidence_context=evidence,
            metadata=raw,
            raw_evidence=raw,
        ))

    binary_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for binary in report.get("binary_analysis") or []:
        if not isinstance(binary, dict):
            continue
        binary_name = str(binary.get("name") or "native binary")
        for check, raw in binary.items():
            if check == "name" or not isinstance(raw, dict):
                continue
            key = (str(check), str(raw.get("severity") or "info"), str(raw.get("description") or ""))
            binary_groups[key].append({"binary": binary_name, "evidence": raw})
    for (check, severity, description), evidence_rows in binary_groups.items():
        binaries = [row["binary"] for row in evidence_rows]
        findings.append(_base(
            report,
            category="binary",
            rule_id=f"binary_{check}",
            title=f"Native binary check: {check.replace('_', ' ')}",
            severity=severity,
            location=", ".join(binaries),
            message=description,
            evidence_context=f"Affected native binaries:\n- " + "\n- ".join(binaries) + f"\n\nMobSF evidence: {description}",
            metadata={"check": check, "affected_binaries": binaries},
            raw_evidence=evidence_rows,
        ))

    output_path = Path(output_json_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/raw/mobsf.json")
    parser.add_argument("--output", default="data/normalized/mobile_findings.json")
    parser.add_argument("--sources", default="data/raw/mobsf_sources.json")
    args = parser.parse_args()
    findings = normalize_mobsf_findings(args.input, args.output, args.sources)
    print(f"Normalized {len(findings)} MobSF findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
