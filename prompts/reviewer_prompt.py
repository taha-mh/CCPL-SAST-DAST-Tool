"""
LLM Reviewer Prompt Template for CCPL Web Security Testing Tool.

Responsibility:
Provide structured system instructions and user prompt formatters
to perform a second logical review pass on initial security assessments.
"""

REVIEWER_SYSTEM_PROMPT = """You are the Chief Application Security Officer reviewing an initial security assessment.
Your job is to perform a strict 2nd pass review to confirm, reject, or flag security findings based on provided evidence.

STRICT REVIEW RULES:
1. Examine both the evidence context (source code lines or live HTTP request/response evidence) and the initial Assessor's reasoning.
2. Do NOT output thinking text or <think> tags. Start your response immediately with '{' and return ONLY a single valid JSON object.
3. If the evidence shows proper sanitization, safe configuration, or non-exploitable headers, REJECT the finding as a false positive.
4. If the finding represents a genuine security risk, CONFIRM the finding.
5. Keep the review_reason concise (maximum 1-2 short sentences).
6. If evidence is ambiguous, mark as NEEDS_REVIEW.

REQUIRED JSON SCHEMA:
{
  "finding_id": "string",
  "decision": "confirmed" | "rejected" | "needs_review",
  "review_reason": "Detailed justification explaining why the finding was confirmed, rejected, or flagged.",
  "final_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}
"""

REVIEWER_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id", "decision", "review_reason", "final_severity", "confidence"],
    "properties": {
        "finding_id": {"type": "string"},
        "decision": {"type": "string", "enum": ["confirmed", "rejected", "needs_review"]},
        "review_reason": {"type": "string"},
        "final_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
    },
}


def build_reviewer_user_prompt(finding: dict) -> str:
    """
    Formats an assessed finding dictionary into a structured user prompt for the Reviewer LLM.
    Supports both SAST (source code context) and DAST (live HTTP evidence).
    """
    finding_id = finding.get("finding_id", "UNKNOWN")
    rule_id = finding.get("rule_id", "UNKNOWN")
    vuln_type = finding.get("vulnerability_type") or finding.get("title") or "Security Issue"
    target_loc = finding.get("target") or finding.get("file_path") or "Unknown"
    evidence_context = finding.get("evidence_context") or finding.get("code_context") or "No evidence context available."
    assessment = finding.get("llm_assessment", {})

    assessor_plausible = assessment.get("is_plausible", False)
    assessor_severity = assessment.get("severity", "UNKNOWN")
    assessor_reasoning = assessment.get("reasoning", "No reasoning provided.")
    assessor_remediation = assessment.get("remediation", "No remediation provided.")

    user_prompt = f"""Please review the following initial security assessment:

Finding ID: {finding_id}
Rule ID: {rule_id}
Vulnerability Type: {vuln_type}
Target Location: {target_loc}

EVIDENCE CONTEXT:
{evidence_context}

INITIAL ASSESSOR EVALUATION:
- Plausible Vulnerability: {assessor_plausible}
- Assessed Severity: {assessor_severity}
- Assessor Reasoning: {assessor_reasoning}
- Proposed Remediation: {assessor_remediation}

CRITICAL INSTRUCTION: Your output MUST begin with the '{{' character on the very first line. Do NOT write any introductory text. Respond ONLY with the JSON object following the required schema.
"""
    return user_prompt
