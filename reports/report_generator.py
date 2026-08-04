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
    <title>CCPL Web SAST Security Assessment Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #f8fafc;
            --card-bg: #ffffff;
            --card-border: #e2e8f0;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --brand-indigo: #4f46e5;
            --accent-blue-bg: #eff6ff;
            --accent-blue-border: #bfdbfe;
            --accent-blue-text: #1d4ed8;
            --accent-red-bg: #fef2f2;
            --accent-red-border: #fecaca;
            --accent-red-text: #dc2626;
            --accent-green-bg: #ecfdf5;
            --accent-green-border: #a7f3d0;
            --accent-green-text: #059669;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            background: #ffffff;
            padding: 2rem;
            border-radius: 14px;
            border: 1px solid var(--card-border);
            border-top: 5px solid var(--brand-indigo);
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(15, 23, 42, 0.04);
        }}
        h1 {{ margin: 0 0 0.5rem 0; color: var(--brand-indigo); font-size: 1.8rem; font-weight: 700; }}
        .meta-info {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-card.evaluated {{ background: var(--accent-blue-bg); border: 1px solid var(--accent-blue-border); }}
        .stat-card.confirmed {{ background: var(--accent-red-bg); border: 1px solid var(--accent-red-border); }}
        .stat-card.discarded {{ background: var(--accent-green-bg); border: 1px solid var(--accent-green-border); }}
        .stat-label {{ font-size: 0.88rem; font-weight: 600; color: var(--text-secondary); }}
        .stat-number {{ font-size: 2.5rem; font-weight: 700; margin-top: 0.25rem; }}
        .stat-number.blue {{ color: var(--accent-blue-text); }}
        .stat-number.red {{ color: var(--accent-red-text); }}
        .stat-number.green {{ color: var(--accent-green-text); }}
        .section-title {{
            font-size: 1.35rem;
            margin: 2rem 0 1rem 0;
            color: var(--text-primary);
            font-weight: 700;
        }}
        .finding-card {{
            background: #ffffff;
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.6rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.03);
        }}
        .badge {{
            display: inline-block;
            padding: 0.3rem 0.85rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.78rem;
            text-transform: uppercase;
        }}
        .badge-high {{ background: var(--accent-red-bg); color: var(--accent-red-text); border: 1px solid var(--accent-red-border); }}
        .badge-medium {{ background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }}
        .badge-low {{ background: var(--accent-green-bg); color: var(--accent-green-text); border: 1px solid var(--accent-green-border); }}
        pre {{
            background: #0f172a;
            padding: 1.1rem;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid #1e293b;
            font-family: 'Fira Code', monospace;
            font-size: 0.88rem;
            color: #f1f5f9;
            margin-top: 0.5rem;
        }}
        .reasoning-box {{
            background: var(--accent-blue-bg);
            border-left: 4px solid var(--brand-indigo);
            padding: 1.1rem;
            margin: 1.1rem 0;
            border-radius: 0 8px 8px 0;
            font-size: 0.92rem;
            color: #1e3a8a;
        }}
        @media print {{
            body {{ background-color: #ffffff; padding: 0; }}
            .container {{ max-width: 100%; }}
            .header, .finding-card, .stat-card {{ box-shadow: none; page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CCPL Web SAST Security Assessment Report</h1>
            <div class="meta-info">
                <p><strong>Target Codebase:</strong> DVWA (<code>targets/DVWA</code>) | <strong>Engine:</strong> Semgrep + Ollama (<code>qwen3:8b</code>)</p>
                <p><strong>Report Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card evaluated">
                <div class="stat-label">Evaluated Findings</div>
                <div class="stat-number blue">{len(reviewed_findings)}</div>
            </div>
            <div class="stat-card confirmed">
                <div class="stat-label">Confirmed Risks</div>
                <div class="stat-number red">{len(confirmed)}</div>
            </div>
            <div class="stat-card discarded">
                <div class="stat-label">False Positives Discarded</div>
                <div class="stat-number green">{len(discarded)}</div>
            </div>
        </div>

        <h2 class="section-title">📊 Security Findings Summary Matrix</h2>
        <div class="finding-card" style="padding: 1rem; overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem;">
                <thead>
                    <tr style="background: #f1f5f9; border-bottom: 2px solid var(--card-border);">
                        <th style="padding: 0.75rem;">Finding ID</th>
                        <th style="padding: 0.75rem;">Vulnerability / Rule</th>
                        <th style="padding: 0.75rem;">File Location</th>
                        <th style="padding: 0.75rem;">Severity</th>
                        <th style="padding: 0.75rem;">AI Final Verdict</th>
                    </tr>
                </thead>
                <tbody>
"""

    for f in reviewed_findings:
        f_id = f.get("finding_id", "UNKNOWN")
        title = f.get("title", "Security Issue")
        file_path = Path(f.get("file_path", "")).name
        lines_str = f"L{f.get('start_line')}-{f.get('end_line')}"
        review = f.get("llm_review", {})
        assessment = f.get("llm_assessment", {})
        decision = review.get("decision") or ("confirmed" if assessment.get("is_plausible") else "rejected")
        is_conf = decision == "confirmed"
        sev = (review.get("final_severity") or assessment.get("severity") or f.get("scanner_severity", "LOW")).upper()
        
        verdict_badge = "<span class='badge badge-high'>CONFIRMED</span>" if is_conf else "<span class='badge badge-low'>DISCARDED (FP)</span>"
        sev_badge = f"<span class='badge badge-high'>{sev}</span>" if is_conf else f"<span class='badge badge-low'>{sev}</span>"

        html_content += f"""
                    <tr style="border-bottom: 1px solid var(--card-border);">
                        <td style="padding: 0.75rem;"><strong>{f_id}</strong></td>
                        <td style="padding: 0.75rem;">{title}<br><code style="font-size: 0.75rem; color: var(--text-muted);">{f.get('rule_id')}</code></td>
                        <td style="padding: 0.75rem;"><code>{file_path}:{lines_str}</code></td>
                        <td style="padding: 0.75rem;">{sev_badge}</td>
                        <td style="padding: 0.75rem;">{verdict_badge}</td>
                    </tr>
"""

    html_content += """
                </tbody>
            </table>
        </div>

        <h2 class="section-title">🚨 Section 1: Confirmed Security Findings</h2>
"""

    if not confirmed:
        html_content += "<div class='finding-card'><p>No confirmed vulnerabilities detected in the evaluated sample.</p></div>"
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
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.5rem;">
                <strong>Location:</strong> <code>{file_path}</code> (Lines {lines_str}) | <strong>Rule:</strong> <code>{f.get('rule_id')}</code>
            </p>

            <div class="reasoning-box">
                <strong>🤖 AI Security Reasoning & Evidence:</strong>
                <p style="margin-top: 0.4rem;">{reasoning}</p>
            </div>

            <strong>🛠️ Remediation Recommendation:</strong>
            <pre><code>{remediation}</code></pre>

            <strong style="display: block; margin-top: 0.75rem;">📄 Source Code Context:</strong>
            <pre><code>{f.get('code_context', '')}</code></pre>
        </div>
"""

    html_content += """
        <h2 class="section-title">🛡️ Section 2: Discarded False Positives Audit Log</h2>
"""

    if not discarded:
        html_content += "<div class='finding-card'><p>No false positives were discarded in this evaluation.</p></div>"
    else:
        for f in discarded:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title", "Security Issue")
            file_path = f.get("file_path", "")
            lines_str = f"{f.get('start_line')}-{f.get('end_line')}"
            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            reasoning = review.get("review_reason") or assessment.get("reasoning", "Evaluated as non-exploitable context.")

            html_content += f"""
        <div class="finding-card" style="border-left: 4px solid var(--accent-green-text);">
            <div>
                <span class="badge badge-low">FALSE POSITIVE DISCARDED</span>
                <strong style="margin-left: 0.5rem; font-size: 1.1rem;">{f_id}: {title}</strong>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.5rem;">
                <strong>Location:</strong> <code>{file_path}</code> (Lines {lines_str}) | <strong>Rule:</strong> <code>{f.get('rule_id')}</code>
            </p>

            <div class="reasoning-box" style="background: var(--accent-green-bg); border-left-color: var(--accent-green-text); color: var(--accent-green-text);">
                <strong>🤖 AI Reason for Discarding:</strong>
                <p style="margin-top: 0.4rem;">{reasoning}</p>
            </div>

            <strong style="display: block; margin-top: 0.75rem;">📄 Source Code Context:</strong>
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
