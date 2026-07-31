"""
Semgrep Normalizer Module for CCPL Web SAST Tool.

Responsibility:
1. Load raw Semgrep JSON findings from data/raw/semgrep_findings.json.
2. Standardize each finding into a common dictionary schema.
3. Save normalized findings to data/normalized/normalized_findings.json.
4. Return normalized data list.
"""

import json
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def normalize_semgrep_findings(
    raw_json_path: str = "data/raw/semgrep_findings.json",
    output_normalized_path: str = "data/normalized/normalized_findings.json",
) -> list:
    """
    Parses raw Semgrep JSON findings and normalizes them into a unified schema.

    :param raw_json_path: Path to raw Semgrep findings JSON file.
    :param output_normalized_path: Path to save normalized findings JSON file.
    :return: List of normalized finding dictionaries.
    """
    raw_file = Path(raw_json_path).resolve()
    output_file = Path(output_normalized_path).resolve()

    if not raw_file.exists():
        logger.error(f"Raw Semgrep findings file not found at: {raw_file}")
        return []

    logger.info(f"Loading raw Semgrep findings from: {raw_file}")
    with open(raw_file, "r", encoding="utf-8", errors="replace") as f:
        raw_data = json.load(f)

    raw_results = raw_data.get("results", [])
    logger.info(f"Normalizing {len(raw_results)} raw findings...")

    normalized_findings = []

    for index, item in enumerate(raw_results, start=1):
        # Extract location info
        path_str = item.get("path", "")
        start_line = item.get("start", {}).get("line", 0)
        end_line = item.get("end", {}).get("line", 0)

        # Extract extra metadata
        extra = item.get("extra", {})
        message = extra.get("message", "").strip()
        severity = extra.get("severity", "WARNING").upper()
        metadata = extra.get("metadata", {})

        cwe_list = metadata.get("cwe", [])
        owasp_list = metadata.get("owasp", [])

        # Build standardized schema
        finding = {
            "finding_id": f"FINDING-{index:03d}",
            "tool": "semgrep",
            "rule_id": item.get("check_id", "unknown_rule"),
            "title": message.split(".")[0] if message else "Security Issue Detected",
            "message": message,
            "scanner_severity": severity,
            "file_path": path_str,
            "start_line": start_line,
            "end_line": end_line,
            "matched_snippet": extra.get("lines", ""),
            "cwe": cwe_list,
            "owasp": owasp_list,
            "category": metadata.get("category", "security"),
            "vulnerability_class": metadata.get("vulnerability_class", []),
        }

        normalized_findings.append(finding)

    # Ensure data/normalized directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Save normalized JSON file (pretty printed with indent=2)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(normalized_findings, f, indent=2, ensure_ascii=False)

    logger.info(f"Successfully normalized {len(normalized_findings)} findings!")
    logger.info(f"Saved normalized data to: {output_file}")

    return normalized_findings


if __name__ == "__main__":
    print("--- Running Milestone 3: Semgrep Normalizer Test ---")
    results = normalize_semgrep_findings()
    print(f"\nTotal Normalized Findings: {len(results)}")
    if results:
        print("\nSample Normalized Finding (First Item):")
        print(json.dumps(results[0], indent=2))
