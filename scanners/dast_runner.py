"""
OWASP ZAP DAST Scanner Runner Module for CCPL Web Security Tool.
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

try:
    from zapv2 import ZAPv2
    ZAP_INSTALLED = True
except ImportError:
    ZAP_INSTALLED = False

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

ZAP_BAT_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"


def ensure_zap_daemon_started(zap_proxy_url: str = "http://127.0.0.1:8080"):
    """Auto-launches OWASP ZAP Daemon in background if not running."""
    if not ZAP_INSTALLED:
        return

    try:
        zap = ZAPv2(proxies={'http': zap_proxy_url, 'https': zap_proxy_url})
        _ = zap.core.version
        return
    except Exception:
        logger.info("OWASP ZAP Daemon is offline. Auto-starting ZAP in background...")

    if os.path.exists(ZAP_BAT_PATH):
        try:
            cmd = [ZAP_BAT_PATH, "-daemon", "-port", "8080", "-config", "api.disablekey=true"]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(10)
        except Exception as e:
            logger.warning(f"Failed to auto-start OWASP ZAP Daemon: {e}")


def run_dast_scan(
    target_base_url: str = "http://127.0.0.1:8085",
    output_file: str = "data/raw/dast_findings.json",
    zap_proxy_url: str = "http://127.0.0.1:8080",
) -> dict:
    """Executes DAST scan via OWASP ZAP API daemon."""
    target_base_url = target_base_url.rstrip("/")
    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Starting OWASP ZAP DAST Scan on target: {target_base_url}")

    if not ZAP_INSTALLED:
        error_msg = "Python package 'python-owasp-zap-v2.4' is not installed."
        logger.error(error_msg)
        return {"status": "error", "error": error_msg, "findings_count": 0}

    ensure_zap_daemon_started(zap_proxy_url)

    try:
        zap = ZAPv2(proxies={'http': zap_proxy_url, 'https': zap_proxy_url})
        logger.info(f"Connected to OWASP ZAP Daemon v{zap.core.version} at {zap_proxy_url}")
    except Exception as err:
        error_msg = f"OWASP ZAP daemon is not running at {zap_proxy_url}. Please start OWASP ZAP. ({err})"
        logger.error(error_msg)
        return {"status": "error", "error": error_msg, "findings_count": 0}

    try:
        # Step 1: Spider Crawl
        logger.info(f"Triggering ZAP Spider crawl for {target_base_url}...")
        spider_id = zap.spider.scan(target_base_url)
        time.sleep(2)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(2)

        # Step 2: Active Scan
        logger.info(f"Triggering ZAP Active Scan for {target_base_url}...")
        scan_id = zap.ascan.scan(target_base_url)
        time.sleep(2)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(3)

        # Step 3: Fetch Alerts & Format Findings
        zap_alerts = zap.core.alerts(baseurl=target_base_url)
        raw_findings: list[dict] = [
            {
                "finding_id": f"ZAP-RAW-{idx:03d}",
                "vulnerability_type": alert.get("name", "Security Vulnerability"),
                "category": alert.get("pluginId", "zap_alert"),
                "risk": alert.get("risk", "Low"),
                "confidence": alert.get("confidence", "Medium"),
                "affected_url": alert.get("url", target_base_url),
                "http_method": alert.get("method", "GET"),
                "parameter_tested": alert.get("param", "N/A"),
                "payload_used": alert.get("attack", alert.get("evidence", "")),
                "test_description": alert.get("description", "OWASP ZAP Alert"),
                "evidence_snippet": alert.get("evidence", alert.get("other", "ZAP Alert Evidence")),
            }
            for idx, alert in enumerate(zap_alerts, start=1)
        ]

        output_payload = {
            "scanner": "OWASP ZAP API Daemon",
            "target_url": target_base_url,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(raw_findings),
            "dast_raw_results": raw_findings,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2)

        logger.info(f"DAST Scan finished cleanly! Saved {len(raw_findings)} raw findings to {output_path}")

        return {
            "status": "success",
            "output_path": str(output_path),
            "findings_count": len(raw_findings),
            "target_url": target_base_url,
            "error": None,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during OWASP ZAP execution: {e}")
        return {"status": "error", "error": str(e), "findings_count": 0}


if __name__ == "__main__":
    print("--- Running OWASP ZAP DAST Scanner Runner ---")
    res = run_dast_scan(target_base_url="http://127.0.0.1:8085")
    print(json.dumps(res, indent=2))
