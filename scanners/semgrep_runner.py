"""
Semgrep Scanner Wrapper Module for CCPL Web SAST Tool.

Responsibility:
1. Accept a target directory path (e.g., targets/DVWA).
2. Execute Semgrep scan with specified security rulesets.
3. Save the raw scanner output in JSON format to data/raw/semgrep_findings.json.
4. Return execution status and metadata.
"""

import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def get_semgrep_executable() -> str:
    """Locates the semgrep executable across system PATH and active virtualenv."""
    # Check if 'semgrep' is directly in PATH
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        return semgrep_path

    # Check active virtualenv Scripts folder (Windows) or bin folder (Linux)
    venv_dir = Path(sys.executable).parent
    possible_paths = [
        venv_dir / "semgrep.exe",
        venv_dir / "semgrep",
        Path(sys.prefix) / "Scripts" / "semgrep.exe",
        Path(sys.prefix) / "bin" / "semgrep",
    ]

    for p in possible_paths:
        if p.exists():
            return str(p)

    return "semgrep"


def run_semgrep_scan(
    target_dir: str = "targets/DVWA",
    output_file: str = "data/raw/semgrep_findings.json",
    config_rule: str = "auto",
) -> dict:
    """
    Executes a Semgrep SAST scan against the target directory and outputs raw JSON results.

    :param target_dir: Relative or absolute path to target source code.
    :param output_file: Filepath where raw JSON output will be saved.
    :param config_rule: Semgrep ruleset configuration (default: 'auto' or 'p/default').
    :return: Dictionary containing scan status, result path, and total findings count.
    """
    target_path = Path(target_dir).resolve()
    output_path = Path(output_file).resolve()

    # Validate target directory existence
    if not target_path.exists() or not target_path.is_dir():
        error_msg = f"Target directory '{target_path}' does not exist or is not a directory."
        logger.error(error_msg)
        return {"status": "error", "error": error_msg, "findings_count": 0}

    # Ensure output parent directory exists (e.g. data/raw/)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    semgrep_bin = get_semgrep_executable()
    logger.info(f"Using Semgrep binary: {semgrep_bin}")
    logger.info(f"Starting Semgrep scan on target: {target_path}")
    logger.info(f"Using ruleset: {config_rule}")

    # Build Semgrep command
    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        config_rule,
        "--json",
        "--output",
        str(output_path),
        str(target_path),
    ]

    try:
        # Run Semgrep command
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode not in (0, 1):  # 0 = clean, 1 = findings found
            logger.warning(f"Semgrep exited with code {result.returncode}. Stderr: {result.stderr.strip()}")

        # Verify output JSON file creation
        if not output_path.exists():
            error_msg = f"Semgrep completed but output file '{output_path}' was not generated. Stderr: {result.stderr.strip()}"
            logger.error(error_msg)
            return {"status": "error", "error": error_msg, "findings_count": 0}

        # Load raw JSON to verify structure and count findings
        with open(output_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        findings_count = len(raw_data.get("results", []))
        logger.info(f"Scan completed successfully! Total raw findings detected: {findings_count}")
        logger.info(f"Raw findings saved to: {output_path}")

        return {
            "status": "success",
            "output_path": str(output_path),
            "findings_count": findings_count,
            "target": str(target_path),
            "error": None,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during Semgrep execution: {e}")
        return {"status": "error", "error": str(e), "findings_count": 0}


if __name__ == "__main__":
    print("--- Running Milestone 2: Semgrep Scanner Wrapper Test ---")
    scan_result = run_semgrep_scan(target_dir="targets/DVWA", output_file="data/raw/semgrep_findings.json")
    print("\nScan Summary:")
    print(json.dumps(scan_result, indent=2))
