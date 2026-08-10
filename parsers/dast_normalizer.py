"""
DAST Normalizer & HTTP Context Module for CCPL Web Security Tool.

Responsibility:
1. Load raw ZAP findings from data/raw/dast_findings.json.
2. Standardize fields into unified JSON schema.
3. Format DAST finding evidence summary into code_context string.
4. Save normalized findings to data/normalized/dast_normalized.json.
"""

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
MAX_EVIDENCE_LENGTH = 500
SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFO",
}


def normalize_dast_findings(
    raw_json_path: str = "data/raw/dast_findings.json",
    output_json_path: str = "data/normalized/dast_normalized.json",
) -> list[dict]:
    """
    Normalizes raw ZAP DAST findings and formats HTTP Request/Response evidence context.
    Strictly separates observed HTTP evidence from scanner description text and missing evidence.
    """
    raw_path = (BASE_DIR / raw_json_path).resolve()
    output_path = (BASE_DIR / output_json_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not raw_path.exists():
        logger.error(f"Raw DAST findings file not found at {raw_path}")
        return []

    with open(raw_path, "r", encoding="utf-8") as f:
        raw_payload = json.load(f)

    raw_results = raw_payload.get("dast_raw_results", [])
    logger.info(f"Normalizing {len(raw_results)} raw DAST findings...")

    normalized_list: list[dict] = []
    for idx, item in enumerate(raw_results, start=1):
        risk = str(item.get("risk", "Low")).upper()
        severity = SEVERITY_MAP.get(risk, "LOW")

        affected_url = item.get("affected_url", "")
        http_method = item.get("http_method", "GET")
        raw_param = item.get("parameter_tested", "")
        raw_attack = item.get("payload_used", "").strip()
        raw_evidence = item.get("evidence_snippet", "").strip()
        raw_description = item.get("test_description", "").strip()
        plugin_id_str = str(item.get("category", ""))

        # 1. Reliable scan_type classification (do not guess blindly)
        source_id = str(item.get("sourceid", ""))
        if source_id in ["1", "2"]:
            scan_type = "passive"
        elif source_id == "3":
            scan_type = "active"
        elif raw_attack:
            scan_type = "active"
        elif plugin_id_str.isdigit() and int(plugin_id_str) >= 10000 and int(plugin_id_str) < 40000:
            scan_type = "passive"
        else:
            scan_type = "unknown"

        # 2. Distinguish tested parameter vs tested response header
        vulnerability_type = item.get("vulnerability_type", "Security Finding")
        is_header_issue = "header" in vulnerability_type.lower() or "policy" in vulnerability_type.lower()
        if is_header_issue and raw_param:
            tested_header = raw_param
            parameter_tested = "N/A"
        else:
            tested_header = "N/A"
            parameter_tested = raw_param if raw_param else "N/A"

        # 3. Format Observed Evidence vs Scanner Description vs Missing Evidence
        evidence_blocks = []
        evidence_blocks.append("=== DAST LIVE HTTP EVIDENCE ===")
        evidence_blocks.append(f"Scan Type: {scan_type}")
        evidence_blocks.append(f"Target URL: {affected_url}")
        evidence_blocks.append(f"HTTP Method: {http_method}")
        if tested_header != "N/A":
            evidence_blocks.append(f"Tested Response Header: {tested_header}")
        if parameter_tested != "N/A":
            evidence_blocks.append(f"Tested Parameter: {parameter_tested}")

        # OBSERVED EVIDENCE SECTION
        observed_items = []
        if raw_attack:
            observed_items.append(f"Attack Payload: {raw_attack}")
        if raw_evidence and raw_evidence != "ZAP Alert Evidence":
            observed_items.append(f"Response Evidence Match: {raw_evidence[:MAX_EVIDENCE_LENGTH]}")

        evidence_blocks.append("\n[OBSERVED HTTP EVIDENCE]")
        if observed_items:
            for obs in observed_items:
                evidence_blocks.append(f"- {obs}")
        else:
            evidence_blocks.append("- Information not available in captured response evidence.")

        # SCANNER DESCRIPTION SECTION
        evidence_blocks.append("\n[SCANNER ALERT DESCRIPTION]")
        if raw_description:
            evidence_blocks.append(raw_description[:MAX_EVIDENCE_LENGTH])
        else:
            evidence_blocks.append("No scanner description provided.")

        context_str = "\n".join(evidence_blocks)

        normalized_finding = {
            "finding_id": f"DAST-{idx:03d}",
            "vulnerability_type": vulnerability_type,
            "rule_id": f"zap_{plugin_id_str}" if plugin_id_str else "zap_alert",
            "scanner_severity": severity,
            "scanner_risk": item.get("risk", "Low"),
            "scanner_confidence": item.get("confidence", "Medium"),
            "scan_type": scan_type,
            "target": affected_url,
            "http_method": http_method,
            "tested_header": tested_header,
            "parameter": parameter_tested,
            "attack_payload": raw_attack if raw_attack else "N/A",
            "evidence_context": context_str,
            "test_description": raw_description,
        }
        normalized_list.append(normalized_finding)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(normalized_list, f, indent=2)

    logger.info(f"Successfully normalized {len(normalized_list)} DAST findings -> {output_path}")
    return normalized_list


if __name__ == "__main__":
    print("--- Running Step 2: DAST Normalizer Test ---")
    res = normalize_dast_findings()
    print(f"Normalized {len(res)} findings cleanly.")
