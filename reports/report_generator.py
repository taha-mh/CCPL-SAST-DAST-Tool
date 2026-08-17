"""
Refactored Report Generator Module for CCPL Web SAST & DAST Security Tool.

Responsibility:
1. Load reviewed findings from JSON.
2. Filter confirmed vulnerabilities using strict Reviewer verdict rules.
3. Dynamically detect LLM Provider/Model and finding type (SAST vs DAST).
4. Separate HTML presentation into reports/report_template.html.
5. Generate both Markdown and HTML security assessment reports.
"""

import base64
import json
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def get_finding_type(finding: dict) -> str:
    """Detects whether a finding is DAST or SAST based on present fields."""
    if finding.get("target") or finding.get("scan_type") or finding.get("tested_header"):
        return "DAST"
    return "SAST"


def get_review_verdict(finding: dict) -> str:
    """
    Returns the strict Reviewer decision.
    Only returns 'confirmed' if the Reviewer explicitly confirmed the finding.
    """
    review = finding.get("llm_review", {})
    decision = review.get("decision")
    if decision == "confirmed":
        return "confirmed"
    elif decision in ("rejected", "discarded"):
        return "rejected"
    elif decision == "needs_review":
        return "needs_review"
    return "not_reviewed"


def get_final_severity(finding: dict) -> str:
    """Resolves severity hierarchy: llm_review -> llm_assessment -> scanner_severity."""
    review = finding.get("llm_review", {})
    assessment = finding.get("llm_assessment", {})
    sev = (
        review.get("final_severity")
        or assessment.get("severity")
        or finding.get("scanner_severity")
        or finding.get("scanner_risk")
        or "LOW"
    )
    return str(sev).upper()


def get_location_info(finding: dict) -> dict:
    """Returns location details formatted for SAST (file/lines) vs DAST (URL/Method)."""
    f_type = get_finding_type(finding)
    if f_type == "DAST":
        target_url = finding.get("target", "N/A")
        http_method = finding.get("http_method", "GET")
        return {
            "type": "DAST",
            "display_text": f"Target URL: `{target_url}`",
            "html_display": f"<code>{http_method} {target_url}</code>",
            "context_label": "Live HTTP Evidence Context:",
            "context_data": finding.get("evidence_context", "No HTTP evidence context available."),
        }
    else:
        file_path = finding.get("file_path", "Unknown File")
        start_line = finding.get("start_line", 0)
        end_line = finding.get("end_line", 0)
        lines_str = f"{start_line}-{end_line}" if start_line != end_line else str(start_line)
        return {
            "type": "SAST",
            "display_text": f"`{file_path}` (Lines {lines_str})",
            "html_display": f"<code>{Path(file_path).name}:{lines_str}</code>",
            "context_label": "Source Code Context:",
            "context_data": finding.get("code_context", "No source code context available."),
        }


def get_llm_engine_info(findings: list) -> str:
    """Dynamically detects the LLM Provider and Model from processed findings."""
    for f in findings:
        model = f.get("llm_review", {}).get("llm_model") or f.get("llm_assessment", {}).get("llm_model")
        if model:
            model_str = str(model)
            model_lower = model_str.lower()
            if "gpt" in model_lower:
                return f"OpenAI ({model_str})"
            elif "qwen" in model_lower or "ollama" in model_lower:
                return f"Local Ollama ({model_str})"
            return f"AI Engine ({model_str})"
    return "AI Reasoning Engine"


def get_report_meta(findings: list) -> dict:
    """Determines report title, target system info, and LLM engine dynamically."""
    dast_count = sum(1 for f in findings if get_finding_type(f) == "DAST")
    sast_count = len(findings) - dast_count

    if dast_count > 0 and sast_count == 0:
        title = "CCPL DAST Security Assessment Report"
        first_target = next((f.get("target") for f in findings if f.get("target")), "DVWA Application")
        target_system = f"DVWA Live Application (`{first_target}`)"
    elif sast_count > 0 and dast_count == 0:
        title = "CCPL SAST Security Assessment Report"
        target_system = "DVWA Source Code (`targets/DVWA`)"
    else:
        title = "CCPL Hybrid Security Assessment Report"
        target_system = "DVWA Web Application & Source Code"

    return {
        "title": title,
        "target_system": target_system,
        "llm_engine": get_llm_engine_info(findings),
    }


def generate_markdown_report(reviewed_findings: list, output_md_path: str = "reports/sast_report.md") -> str:
    """Generates a clean, structured Markdown security report from reviewed findings."""
    meta = get_report_meta(reviewed_findings)

    # Strictly require Reviewer verdict == 'confirmed'
    confirmed = [f for f in reviewed_findings if get_review_verdict(f) == "confirmed"]
    discarded = [f for f in reviewed_findings if f not in confirmed]

    # Calculate severity counts for confirmed findings
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in confirmed:
        sev = get_final_severity(f)
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["LOW"] += 1

    md_lines = [
        f"# {meta['title']}",
        "",
        f"**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Target System:** {meta['target_system']}",
        f"**LLM Engine:** {meta['llm_engine']}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- **Total Candidate Findings Evaluated:** {len(reviewed_findings)}",
        f"- **Confirmed Vulnerabilities:** {len(confirmed)}",
        f"- **Discarded / Unconfirmed Findings:** {len(discarded)}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, count in severity_counts.items():
        md_lines.append(f"| **{sev}** | {count} |")

    md_lines.extend(["", "---", "", "## Confirmed Security Vulnerabilities", ""])

    if not confirmed:
        md_lines.append("*No confirmed vulnerabilities detected in the evaluated sample.*")
    else:
        for f in confirmed:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title") or f.get("vulnerability_type") or "Security Issue"
            rule_id = f.get("rule_id", "unknown_rule")
            sev = get_final_severity(f)

            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            reasoning = review.get("review_reason") or assessment.get("reasoning", "No explanation available.")
            remediation = assessment.get("remediation", "No remediation recommendation available.")

            loc = get_location_info(f)

            md_lines.append(f"### [{sev}] {f_id}: {title}")
            md_lines.append(f"- **Rule ID:** `{rule_id}`")
            md_lines.append(f"- **Location:** {loc['display_text']}")
            md_lines.append(f"- **AI Review Verdict:** `{review.get('decision', 'confirmed').upper()}` (Confidence: `{review.get('confidence', 'HIGH')}`)")
            md_lines.append("")
            md_lines.append("**Analysis & Evidence:**")
            md_lines.append(f"> {reasoning}")
            md_lines.append("")
            md_lines.append("**Recommended Developer Remediation:**")
            md_lines.append(f"```text\n{remediation}\n```")
            md_lines.append("")
            md_lines.append(f"#### {loc['context_label']}")
            md_lines.append("```text")
            md_lines.append(loc["context_data"])
            md_lines.append("```")
            md_lines.append("")
            md_lines.append("---")
            md_lines.append("")

    md_lines.extend(["## Appendix: Discarded / Unconfirmed Findings", ""])
    if not discarded:
        md_lines.append("*No findings were discarded during this evaluation.*")
    else:
        md_lines.append("| Finding ID | Rule ID | Location | Reviewer Verdict | Audit Reason |")
        md_lines.append("|---|---|---|---|---|")
        for f in discarded:
            f_id = f.get("finding_id", "UNKNOWN")
            rule_id = f.get("rule_id", "UNKNOWN")
            loc = get_location_info(f)
            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            verdict = get_review_verdict(f).upper()
            reason = review.get("review_reason") or assessment.get("reasoning") or "Evaluated as non-exploitable context."
            md_lines.append(f"| `{f_id}` | `{rule_id}` | {loc['display_text']} | `{verdict}` | {reason} |")

    report_content = "\n".join(md_lines)
    output_file = Path(output_md_path).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info(f"Generated Markdown report at: {output_file}")
    return report_content


def generate_html_report(reviewed_findings: list, output_html_path: str = "reports/sast_report.html") -> str:
    """Generates a modern HTML security dashboard report using reports/report_template.html."""
    meta = get_report_meta(reviewed_findings)

    # Strictly require Reviewer verdict == 'confirmed'
    confirmed = [f for f in reviewed_findings if get_review_verdict(f) == "confirmed"]
    discarded = [f for f in reviewed_findings if f not in confirmed]

    # Convert frontend/logo.webp to base64 if present
    logo_b64 = ""
    logo_path = Path(__file__).resolve().parent.parent / "frontend" / "logo.webp"
    if logo_path.exists():
        with open(logo_path, "rb") as img_f:
            logo_b64 = base64.b64encode(img_f.read()).decode("utf-8")

    logo_tag = f'<img src="data:image/webp;base64,{logo_b64}" alt="CCPL Logo" style="height: 38px; max-height: 38px; width: auto; max-width: 160px; object-fit: contain; vertical-align: middle; margin-right: 0.75rem; flex-shrink: 0;">' if logo_b64 else ''

    # Load HTML template
    template_path = Path(__file__).resolve().parent / "report_template.html"
    if not template_path.exists():
        logger.error(f"HTML Template file missing at: {template_path}")
        raise FileNotFoundError(f"Template missing: {template_path}")

    template_str = template_path.read_text(encoding="utf-8")

    # Build Summary Matrix Rows
    matrix_rows = []
    for f in reviewed_findings:
        f_id = f.get("finding_id", "UNKNOWN")
        title = f.get("title") or f.get("vulnerability_type") or "Security Issue"
        loc = get_location_info(f)
        verdict = get_review_verdict(f)
        is_conf = verdict == "confirmed"
        sev = get_final_severity(f)

        verdict_badge = "<span class='badge badge-high'>CONFIRMED</span>" if is_conf else f"<span class='badge badge-low'>{verdict.upper()}</span>"
        sev_badge = f"<span class='badge badge-high'>{sev}</span>" if sev in ("CRITICAL", "HIGH") else (f"<span class='badge badge-medium'>{sev}</span>" if sev == "MEDIUM" else f"<span class='badge badge-low'>{sev}</span>")

        matrix_rows.append(f"""
            <tr style="border-bottom: 1px solid var(--card-border);">
                <td style="padding: 0.75rem;"><strong>{f_id}</strong></td>
                <td style="padding: 0.75rem;">{title}<br><code style="font-size: 0.75rem; color: var(--text-muted);">{f.get('rule_id')}</code></td>
                <td style="padding: 0.75rem;">{loc['html_display']}</td>
                <td style="padding: 0.75rem;">{sev_badge}</td>
                <td style="padding: 0.75rem;">{verdict_badge}</td>
            </tr>
        """)

    # Build Confirmed Cards
    confirmed_cards = []
    if not confirmed:
        confirmed_cards.append("<div class='finding-card'><p>No confirmed vulnerabilities detected in the evaluated sample.</p></div>")
    else:
        for f in confirmed:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title") or f.get("vulnerability_type") or "Security Issue"
            loc = get_location_info(f)
            sev = get_final_severity(f)
            badge_class = "badge-high" if sev in ("CRITICAL", "HIGH") else ("badge-medium" if sev == "MEDIUM" else "badge-low")

            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            reasoning = review.get("review_reason") or assessment.get("reasoning", "No explanation available.")
            remediation = assessment.get("remediation", "No remediation recommendation available.")

            confirmed_cards.append(f"""
        <div class="finding-card">
            <div>
                <span class="badge {badge_class}">{sev}</span>
                <strong style="margin-left: 0.5rem; font-size: 1.1rem;">{f_id}: {title}</strong>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.5rem;">
                <strong>Location:</strong> {loc['html_display']} | <strong>Rule:</strong> <code>{f.get('rule_id')}</code>
            </p>

            <div class="reasoning-box">
                <strong>AI Security Reasoning & Evidence:</strong>
                <p style="margin-top: 0.4rem;">{reasoning}</p>
            </div>

            <strong>Remediation Recommendation:</strong>
            <pre><code>{remediation}</code></pre>

            <strong style="display: block; margin-top: 0.75rem;">{loc['context_label']}</strong>
            <pre><code>{loc['context_data']}</code></pre>
        </div>
        """)

    # Build Discarded Cards
    discarded_cards = []
    if not discarded:
        discarded_cards.append("<div class='finding-card'><p>No false positives were discarded in this evaluation.</p></div>")
    else:
        for f in discarded:
            f_id = f.get("finding_id", "UNKNOWN")
            title = f.get("title") or f.get("vulnerability_type") or "Security Issue"
            loc = get_location_info(f)
            verdict = get_review_verdict(f).upper()

            review = f.get("llm_review", {})
            assessment = f.get("llm_assessment", {})
            reasoning = review.get("review_reason") or assessment.get("reasoning", "Evaluated as non-exploitable context.")

            discarded_cards.append(f"""
        <div class="finding-card" style="border-left: 4px solid var(--accent-green-text);">
            <div>
                <span class="badge badge-low">{verdict}</span>
                <strong style="margin-left: 0.5rem; font-size: 1.1rem;">{f_id}: {title}</strong>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-top: 0.5rem;">
                <strong>Location:</strong> {loc['html_display']} | <strong>Rule:</strong> <code>{f.get('rule_id')}</code>
            </p>

            <div class="reasoning-box" style="background: var(--accent-green-bg); border-left-color: var(--accent-green-text); color: var(--accent-green-text);">
                <strong>AI Reason for Verdict ({verdict}):</strong>
                <p style="margin-top: 0.4rem;">{reasoning}</p>
            </div>

            <strong style="display: block; margin-top: 0.75rem;">{loc['context_label']}</strong>
            <pre><code>{loc['context_data']}</code></pre>
        </div>
        """)

    # Fill template placeholders
    html_content = (
        template_str
        .replace("{{LOGO_TAG}}", logo_tag)
        .replace("{{REPORT_TITLE}}", meta["title"])
        .replace("{{TARGET_SYSTEM}}", meta["target_system"])
        .replace("{{LLM_ENGINE}}", meta["llm_engine"])
        .replace("{{REPORT_TIMESTAMP}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        .replace("{{TOTAL_EVALUATED}}", str(len(reviewed_findings)))
        .replace("{{CONFIRMED_COUNT}}", str(len(confirmed)))
        .replace("{{DISCARDED_COUNT}}", str(len(discarded)))
        .replace("{{MATRIX_ROWS}}", "".join(matrix_rows))
        .replace("{{CONFIRMED_CARDS}}", "".join(confirmed_cards))
        .replace("{{DISCARDED_CARDS}}", "".join(discarded_cards))
    )

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
