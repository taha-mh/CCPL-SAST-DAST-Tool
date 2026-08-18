"""
LLM Assessor Prompt Template for CCPL Web Security Testing Tool.

Responsibility:
Provide structured system instructions and user prompt formatters
to assess security findings against surrounding source code or HTTP evidence context.
"""

ASSESSOR_SYSTEM_PROMPT = """You are an expert Application Security Senior Auditor.
Your task is to analyze application security testing findings (SAST source code or DAST live HTTP evidence) along with the provided evidence context.

EVIDENCE EVALUATION RULES:
1. Base your judgment strictly on the provided evidence context (source code lines or live HTTP request/response evidence).
2. Distinguish OBSERVED EVIDENCE from SCANNER DESCRIPTION. Scanner descriptions explain the policy rule, whereas OBSERVED EVIDENCE contains the actual HTTP request/response or code snippet captured.
3. Do NOT invent missing payloads, HTTP response headers, status codes, or execution results. If evidence is missing, evaluate based only on what is observable.
4. Distinguish scanner configuration policy warnings (e.g., missing passive security headers) from demonstrated active exploitability.
5. Do NOT output thinking text or <think> tags. Start your response immediately with '{' and return ONLY a single valid JSON object.
6. Keep all text explanations in the JSON response (reasoning, impact, remediation) concise (maximum 1-2 short sentences each).

REQUIRED JSON SCHEMA:
{
  "finding_id": "string",
  "is_plausible": true | false,
  "vulnerability_type": "string",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "reasoning": "Detailed explanation of why this finding is or is not a real security vulnerability.",
  "evidence": "Specific evidence snippets or request/response patterns that support your decision.",
  "impact": "Explanation of potential security risk if exploited.",
  "remediation": "Concrete recommendation on how developers should fix or remediate the vulnerability.",
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}
"""

ASSESSOR_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "finding_id", "is_plausible", "vulnerability_type", "severity",
        "reasoning", "evidence", "impact", "remediation", "confidence",
    ],
    "properties": {
        "finding_id": {"type": "string"},
        "is_plausible": {"type": "boolean"},
        "vulnerability_type": {"type": "string"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "reasoning": {"type": "string"},
        "evidence": {"type": "string"},
        "impact": {"type": "string"},
        "remediation": {"type": "string"},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
    },
}


def build_assessor_user_prompt(finding: dict) -> str:
    """
    Formats a single finding dictionary into a structured user prompt for the LLM.
    Supports both SAST (source code context) and DAST (live HTTP evidence).
    """
    finding_id = finding.get("finding_id", "UNKNOWN")
    rule_id = finding.get("rule_id", "UNKNOWN")
    vuln_type = finding.get("vulnerability_type") or finding.get("title") or "Security Issue"
    message = finding.get("test_description") or finding.get("message") or ""
    target_loc = finding.get("target") or finding.get("file_path") or "Unknown"
    scanner_severity = finding.get("scanner_severity") or finding.get("scanner_risk") or "UNKNOWN"
    scan_type = finding.get("scan_type", "N/A")
    evidence_context = finding.get("evidence_context") or finding.get("code_context") or "No evidence context available."

    user_prompt = f"""Please assess the following security finding:

Finding ID: {finding_id}
Scanner Rule ID: {rule_id}
Vulnerability Type: {vuln_type}
Scan Type: {scan_type}
Scanner Severity/Risk: {scanner_severity}
Target Location: {target_loc}
Scanner Description: {message}

EVIDENCE CONTEXT:
{evidence_context}

CRITICAL INSTRUCTION: Your output MUST begin with the '{{' character on the very first line. Do NOT write any introductory text (such as "The user wants me to..."). Respond ONLY with the JSON object following the required schema.
"""
    return user_prompt
