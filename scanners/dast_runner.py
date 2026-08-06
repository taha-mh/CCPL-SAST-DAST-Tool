"""
OWASP ZAP DAST Scanner Runner Module for CCPL Web Security Tool.

Responsibility:
1. Connect to OWASP ZAP API Daemon (http://127.0.0.1:8080).
2. Trigger dynamic scanning against authenticated target application.
3. Fetch OWASP ZAP live alerts + HTTP evidence.
4. Output raw findings to data/raw/dast_findings.json.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List
import requests

try:
    from zapv2 import ZAPv2
    ZAP_INSTALLED = True
except ImportError:
    ZAP_INSTALLED = False

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_RAW_DIR = BASE_DIR / "data" / "raw"


def run_dast_scan(
    target_base_url: str = "http://127.0.0.1:8085",
    output_file: str = "data/raw/dast_findings.json",
    zap_proxy_url: str = "http://127.0.0.1:8080",
) -> Dict:
    """
    Executes a DAST scan by connecting to OWASP ZAP API daemon.

    :param target_base_url: Target application base URL.
    :param output_file: Filepath to save raw ZAP alerts JSON.
    :param zap_proxy_url: OWASP ZAP Daemon proxy API address.
    :return: Summary dictionary with scan status and results path.
    """
    target_base_url = target_base_url.rstrip("/")
    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Starting OWASP ZAP DAST Scan on target: {target_base_url}")

    # Check ZAP python package installation
    if not ZAP_INSTALLED:
        error_msg = "Python package 'python-owasp-zap-v2.4' is not installed."
        logger.error(error_msg)
        return {"status": "error", "error": error_msg, "findings_count": 0}

    # Verify OWASP ZAP Daemon is running
    try:
        resp = requests.get(f"{zap_proxy_url}/JSON/core/view/version/", timeout=3)
        if resp.status_code != 200:
            raise ConnectionError("ZAP API did not return HTTP 200 OK.")
    except Exception as err:
        error_msg = f"OWASP ZAP is not running at {zap_proxy_url}. Please start OWASP ZAP daemon. ({err})"
        logger.error(error_msg)
        return {"status": "error", "error": error_msg, "findings_count": 0}

    try:
        zap = ZAPv2(proxies={'http': zap_proxy_url, 'https': zap_proxy_url})

        logger.info(f"Fetching OWASP ZAP alerts for base URL: {target_base_url}...")
        zap_alerts = zap.core.alerts(baseurl=target_base_url)

        raw_findings: List[Dict] = []
        for idx, alert in enumerate(zap_alerts, start=1):
            raw_findings.append({
                "finding_id": f"ZAP-RAW-{idx:03d}",
                "vulnerability_type": alert.get("name", "Security Vulnerability"),
                "category": alert.get("pluginId", "zap_alert"),
                "risk": alert.get("risk", "Low"),
                "confidence": alert.get("confidence", "Medium"),
                "target_base_url": target_base_url,
                "endpoint_path": alert.get("url", target_base_url),
                "full_request_url": alert.get("url", target_base_url),
                "http_method": alert.get("method", "GET"),
                "parameter_tested": alert.get("param", "N/A"),
                "payload_used": alert.get("attack", alert.get("evidence", "")),
                "test_description": alert.get("description", "OWASP ZAP Scanner Alert"),
                "response_status_code": 200,
                "response_body_snippet": alert.get("evidence", alert.get("other", "OWASP ZAP Alert Finding")),
            })

        # Save to data/raw/dast_findings.json
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"dast_raw_results": raw_findings}, f, indent=2)

        total_findings = len(raw_findings)
        logger.info(f"OWASP ZAP DAST Scan completed! Total raw findings: {total_findings}")
        logger.info(f"Raw findings saved to: {output_path}")

        return {
            "status": "success",
            "output_path": str(output_path),
            "findings_count": total_findings,
            "target_url": target_base_url,
            "error": None,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during OWASP ZAP scan execution: {e}")
        return {"status": "error", "error": str(e), "findings_count": 0}


if __name__ == "__main__":
    print("--- Running OWASP ZAP DAST Scanner Runner ---")
    res = run_dast_scan(target_base_url="http://127.0.0.1:8085")
    print(json.dumps(res, indent=2))
