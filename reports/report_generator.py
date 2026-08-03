"""
Report Generator Module for CCPL Web SAST Tool.

Responsibility:
1. Load reviewed findings from data/normalized/reviewed_findings.json.
2. Separate confirmed findings from discarded/rejected false positives.
3. Calculate summary statistics (severity counts, plausible totals).
4. Generate professional Markdown report (reports/sast_report.md).
5. Generate modern HTML report dashboard (reports/sast_report.html).
"""

import json
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def generate_markdown_report(reviewed_findings: list, output_md_path: str = "reports/sast_report.md") -> str:
    """
    Generates a structured Markdown security report from reviewed findings.

    :param reviewed_findings: List of finding dictionaries with llm_assessment & llm_review.
    :param output_md_path: Path to save the Markdown report file.
    :return: Generated Markdown string.
    """
    confirmed = [
        f for f in reviewed_findings
        if f.get("llm_review", {}).get("decision") == "confirmed"
        or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
    ]
    discarded = [f for f in reviewed_findings if f not in confirmed]

    # Calculate severity counts for confirmed findings
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in confirmed:
        sev = f.get("llm_review", {}).get("final_severity") or f.get("llm_assessment", {}).get("severity") or f.get("scanner_severity", "LOW")
        sev = sev.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["LOW"] += 1

    md_lines = []
    md_lines.append("# 🛡️ CCPL Web SAST Security Assessment Report")
    md_lines.append("")
    md_lines.append(f"**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md_lines.append(f"**Target System:** DVWA Source Code (`targets/DVWA`)")
    md_lines.append(f"**Scanner Engine:** Semgrep + Ollama (`qwen3:8b`)")
    md_lines.append("")
    md_lines.append("---")
    md_lines.append("")
    md_lines.append("## 📊 Executive Summary")
    md_lines.append("")
    md_lines.append(f"- **Total Candidate Findings Evaluated:** {len(reviewed_findings)}")
    md_lines.append(f"- **Confirmed Vulnerabilities:** {len(confirmed)}")
    md_lines.append(f"- **Discarded False Positives:** {len(discarded)}")
    md_lines.append("")
    md_lines.append("| Severity | Count |")
    md_lines.append("|---|---|")
    for sev, count in severity_counts.items():
        md_lines.append(f"| **{sev}** | {count} |")
    md_lines.append("")
    md_lines.append("---")
    md_lines.append("")
    md_lines.append("## 🚨 Confirmed Security Vulnerabilities")
    md_lines.append("")

    if not confirmed:
        md_lines.append("*No confirmed vulnerabilities detected in the evaluated sample.*")
    else:
        for f in confirmed:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title", "Security Issue")
            file_path = f.get("file_path", "")
            lines_str = f"{f.get('start_line')}-{f.get('end_line')}"
            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})

            sev = review.get("final_severity") or assessment.get("severity") or f.get("scanner_severity")
            rule_id = f.get("rule_id", "unknown_rule")
            reasoning = review.get("review_reason") or assessment.get("reasoning", "No explanation available.")
            remediation = assessment.get("remediation", "No remediation snippet available.")

            md_lines.append(f"### [{sev}] {f_id}: {title}")
            md_lines.append(f"- **Rule ID:** `{rule_id}`")
            md_lines.append(f"- **Affected Location:** `{file_path}` (Lines {lines_str})")
            md_lines.append(f"- **AI Review Verdict:** `{review.get('decision', 'confirmed').upper()}` (Confidence: `{review.get('confidence', 'HIGH')}`)")
            md_lines.append("")
            md_lines.append(f"**Analysis & Evidence:**")
            md_lines.append(f"> {reasoning}")
            md_lines.append("")
            md_lines.append(f"**Recommended Developer Remediation:**")
            md_lines.append(f"```text\n{remediation}\n```")
            md_lines.append("")
            md_lines.append("#### Code Context")
            md_lines.append("```text")
            md_lines.append(f.get("code_context", "No context snippet available."))
            md_lines.append("```")
            md_lines.append("")
            md_lines.append("---")
            md_lines.append("")

    md_lines.append("## 📁 Appendix: Discarded False Positives")
    md_lines.append("")
    if not discarded:
        md_lines.append("*No findings were discarded during this evaluation.*")
    else:
        md_lines.append("| Finding ID | Rule ID | File | Discard Reason |")
        md_lines.append("|---|---|---|---|")
        for f in discarded:
            f_id = f.get("finding_id", "UNKNOWN")
            rule_id = f.get("rule_id", "UNKNOWN")
            file_path = Path(f.get("file_path", "")).name
            reason = f.get("llm_review", {}).get("review_reason") or f.get("llm_assessment", {}).get("reasoning") or "Discarded by 2nd pass review"
            md_lines.append(f"| `{f_id}` | `{rule_id}` | `{file_path}` | {reason} |")

    report_content = "\n".join(md_lines)

    output_file = Path(output_md_path).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info(f"Generated Markdown report at: {output_file}")
    return report_content


def generate_html_report(reviewed_findings: list, output_html_path: str = "reports/sast_report.html") -> str:
    """
    Generates a modern HTML security dashboard report from reviewed findings.

    :param reviewed_findings: List of finding dictionaries with llm_assessment & llm_review.
    :param output_html_path: Path to save the HTML report file.
    :return: Generated HTML string.
    """
    confirmed = [
        f for f in reviewed_findings
        if f.get("llm_review", {}).get("decision") == "confirmed"
        or (not f.get("llm_review", {}).get("decision") and f.get("llm_assessment", {}).get("is_plausible") is True)
    ]
    discarded = [f for f in reviewed_findings if f not in confirmed]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CCPL Web SAST Security Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-high: #ef4444;
            --accent-medium: #f59e0b;
            --accent-low: #3b82f6;
            --accent-success: #10b981;
            --border-color: #475569;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }}
        h1 {{ margin: 0 0 0.5rem 0; color: #38bdf8; font-size: 2rem; }}
        .meta-info {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }}
        .stat-number {{ font-size: 2.2rem; font-weight: bold; margin-top: 0.5rem; }}
        .stat-number.high {{ color: var(--accent-high); }}
        .stat-number.success {{ color: var(--accent-success); }}
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.8rem;
            text-transform: uppercase;
        }}
        .badge-high {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-high); border: 1px solid var(--accent-high); }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-medium); border: 1px solid var(--accent-medium); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-low); border: 1px solid var(--accent-low); }}
        pre {{
            background: #090d16;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            font-family: "Fira Code", Consolas, monospace;
            font-size: 0.88rem;
        }}
        .reasoning-box {{
            background: rgba(56, 189, 248, 0.1);
            border-left: 4px solid #38bdf8;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 6px 6px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CCPL Web SAST Security Assessment Dashboard</h1>
            <div class="meta-info">
                <p><strong>Target:</strong> DVWA Source Code (<code>targets/DVWA</code>) | <strong>Engine:</strong> Semgrep + Ollama (<code>qwen3:8b</code>)</p>
                <p><strong>Report Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div>Evaluated Findings</div>
                <div class="stat-number">{len(reviewed_findings)}</div>
            </div>
            <div class="stat-card">
                <div>Confirmed Vulnerabilities</div>
                <div class="stat-number high">{len(confirmed)}</div>
            </div>
            <div class="stat-card">
                <div>Discarded False Positives</div>
                <div class="stat-number success">{len(discarded)}</div>
            </div>
        </div>

        <h2>🚨 Confirmed Security Findings</h2>
"""

    if not confirmed:
        html_content += "<p>No confirmed vulnerabilities detected in the evaluated sample.</p>"
    else:
        for f in confirmed:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title", "Security Issue")
            file_path = f.get("file_path", "")
            lines_str = f"{f.get('start_line')}-{f.get('end_line')}"
            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            sev = (review.get("final_severity") or assessment.get("severity") or f.get("scanner_severity", "HIGH")).upper()
            badge_class = "badge-high" if sev in ("CRITICAL", "HIGH") else ("badge-medium" if sev == "MEDIUM" else "badge-low")
            reasoning = review.get("review_reason") or assessment.get("reasoning", "No explanation available.")
            remediation = assessment.get("remediation", "No remediation snippet available.")

            html_content += f"""
        <div class="finding-card">
            <div>
                <span class="badge {badge_class}">{sev}</span>
                <strong style="margin-left: 0.5rem; font-size: 1.1rem;">{f_id}: {title}</strong>
            </div>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">
                <strong>Location:</strong> <code>{file_path}</code> (Lines {lines_str}) | <strong>Rule:</strong> <code>{f.get('rule_id')}</code>
            </p>

            <div class="reasoning-box">
                <strong>AI Assessment & Evidence:</strong>
                <p style="margin: 0.5rem 0 0 0;">{reasoning}</p>
            </div>

            <strong>Remediation Recommendation:</strong>
            <pre><code>{remediation}</code></pre>

            <strong>Code Context:</strong>
            <pre><code>{f.get('code_context', '')}</code></pre>
        </div>
"""

    html_content += """
    </div>
</body>
</html>
"""

    output_file = Path(output_html_path).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info(f"Generated HTML report at: {output_file}")
    return html_content


def run_report_generator(
    input_json_path: str = "data/normalized/reviewed_findings.json",
    output_md_path: str = "reports/sast_report.md",
    output_html_path: str = "reports/sast_report.html",
) -> dict:
    """Loads reviewed findings and generates both Markdown and HTML reports."""
    input_file = Path(input_json_path).resolve()
    if not input_file.exists():
        logger.error(f"Input reviewed findings file not found at: {input_file}")
        return {}

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        reviewed_findings = json.load(f)

    logger.info(f"Generating reports for {len(reviewed_findings)} reviewed findings...")
    md_content = generate_markdown_report(reviewed_findings, output_md_path)
    html_content = generate_html_report(reviewed_findings, output_html_path)

    return {
        "md_path": output_md_path,
        "html_path": output_html_path,
        "findings_count": len(reviewed_findings),
    }


if __name__ == "__main__":
    print("--- Running Milestone 7: Report Generator Test ---")
    res = run_report_generator()
    print(f"\nReport Generation Result: {res}")
