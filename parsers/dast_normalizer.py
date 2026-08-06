"""
DAST Normalizer & HTTP Context Module for CCPL Web Security Tool.

Responsibility:
1. Load raw ZAP findings from data/raw/dast_findings.json.
2. Standardize fields into unified JSON schema.
3. Package HTTP Request & Server Response evidence into code_context string.
4. Save normalized findings to data/normalized/dast_normalized.json.
"""

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent


def normalize_dast_findings(
    raw_json_path: str = "data/raw/dast_findings.json",
    output_json_path: str = "data/normalized/dast_normalized.json",
) -> list[dict]:
    """
    Normalizes raw ZAP DAST findings and formats HTTP Request/Response context.
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
        severity_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"}
        severity = severity_map.get(risk, "LOW")

        affected_url = item.get("affected_url", "")
        http_method = item.get("http_method", "GET")
        parameter = item.get("parameter_tested", "N/A")
        payload = item.get("payload_used", "N/A")
        evidence = item.get("evidence_snippet", "N/A")

        # Format clean HTTP Evidence string into code_context
        context_str = (
            f"=== DAST LIVE HTTP EVIDENCE ===\n"
            f"Target URL: {affected_url}\n"
            f"HTTP Method: {http_method} | Parameter: {parameter}\n"
            f"Attack Payload: {payload}\n"
            f"Response Evidence Snippet:\n{evidence[:500]}"
        )

        normalized_finding = {
            "finding_id": f"DAST-{idx:03d}",
            "vulnerability_type": item.get("vulnerability_type", "Security Finding"),
            "rule_id": f"zap_{item.get('category', 'alert')}",
            "scanner_severity": severity,
            "target": affected_url,
            "code_context": context_str,
            "test_description": item.get("test_description", ""),
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
