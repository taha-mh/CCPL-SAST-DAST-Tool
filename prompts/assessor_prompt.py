"""
LLM Assessor Prompt Template for CCPL Web SAST Tool.

Responsibility:
Provide structured system instructions and user prompt formatters for Qwen3 8B
to assess raw SAST security findings against surrounding source code context.
"""

ASSESSOR_SYSTEM_PROMPT = """You are an expert Application Security Senior Auditor.
Your task is to analyze application security testing findings (SAST source code or DAST live HTTP evidence) along with the provided evidence context.

You must evaluate whether the finding represents a plausible security vulnerability or a false positive.

STRICT REQUIREMENTS:
1. Base your judgment strictly on the provided evidence context (source code lines or live HTTP request/response evidence).
2. Keep all text explanations (reasoning, impact, remediation) concise (maximum 1-2 short sentences each).
3. Return your response ONLY as a single valid JSON object.
4. Do NOT include Markdown formatting (such as ```json codeblocks) or conversational intro text.

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
    evidence_context = finding.get("evidence_context") or finding.get("code_context") or "No evidence context available."

    user_prompt = f"""Please assess the following security finding:

Finding ID: {finding_id}
Scanner Rule ID: {rule_id}
Vulnerability Type: {vuln_type}
Scanner Severity/Risk: {scanner_severity}
Target Location: {target_loc}
Scanner Details: {message}

EVIDENCE CONTEXT:
{evidence_context}

Analyze the finding and evidence context above and respond ONLY with the JSON object following the required schema.
"""
    return user_prompt
