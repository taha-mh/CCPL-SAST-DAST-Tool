"""
LLM Reviewer Prompt Template for CCPL Web SAST Tool.

Responsibility:
Provide structured system instructions and user prompt formatters for Qwen3 8B
to perform a second logical review pass on the initial LLM assessment.
"""

REVIEWER_SYSTEM_PROMPT = """You are the Chief Application Security Officer reviewing an initial security assessment.
Your job is to perform a strict 2nd pass review to confirm, reject, or flag security findings.

STRICT REVIEW RULES:
1. Examine both the raw code evidence and the initial Assessor's reasoning.
2. If the code context shows proper sanitization, validation, or a safe configuration, REJECT the finding as a false positive.
3. If the finding represents a genuine security risk, CONFIRM the finding.
4. Keep the review_reason concise (maximum 1-2 short sentences).
5. If evidence is ambiguous, mark as NEEDS_REVIEW.
6. Return your verdict ONLY as a single valid JSON object.

REQUIRED JSON SCHEMA:
{
  "finding_id": "string",
  "decision": "confirmed" | "rejected" | "needs_review",
  "review_reason": "Detailed justification explaining why the finding was confirmed, rejected, or flagged.",
  "final_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}
"""


def build_reviewer_user_prompt(finding: dict) -> str:
    """
    Formats an assessed finding dictionary into a structured user prompt for the Reviewer LLM.

    :param finding: Dictionary containing normalized finding keys, code_context, and llm_assessment.
    :return: Formatted prompt string for the reviewer role message.
    """
    finding_id = finding.get("finding_id", "UNKNOWN")
    rule_id = finding.get("rule_id", "UNKNOWN")
    title = finding.get("title", "Security Issue")
    file_path = finding.get("file_path", "")
    start_line = finding.get("start_line", 0)
    end_line = finding.get("end_line", 0)
    code_context = finding.get("code_context", "No code context available.")
    assessment = finding.get("llm_assessment", {})

    assessor_plausible = assessment.get("is_plausible", False)
    assessor_severity = assessment.get("severity", "UNKNOWN")
    assessor_reasoning = assessment.get("reasoning", "No reasoning provided.")
    assessor_remediation = assessment.get("remediation", "No remediation provided.")

    user_prompt = f"""Please review the following initial SAST assessment:

Finding ID: {finding_id}
Rule ID: {rule_id}
Title: {title}
Target File: {file_path} (Lines {start_line}-{end_line})

Source Code Context (Vulnerable line marked with ->):
```
{code_context}
```

Initial Assessor Diagnosis:
- Plausible Vulnerability: {assessor_plausible}
- Assessed Severity: {assessor_severity}
- Assessor Reasoning: {assessor_reasoning}
- Proposed Remediation: {assessor_remediation}

Perform your 2nd pass review and return your JSON verdict.
"""
    return user_prompt
