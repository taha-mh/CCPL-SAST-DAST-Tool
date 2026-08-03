"""
LLM Assessor Prompt Template for CCPL Web SAST Tool.

Responsibility:
Provide structured system instructions and user prompt formatters for Qwen3 8B
to assess raw SAST security findings against surrounding source code context.
"""

ASSESSOR_SYSTEM_PROMPT = """You are an expert Application Security Senior Auditor.
Your task is to analyze static application security testing (SAST) findings along with the provided source code context.

You must evaluate whether the finding represents a plausible security vulnerability or a false positive.

STRICT REQUIREMENTS:
1. Base your judgment strictly on the provided source code lines and rule metadata.
2. Return your response ONLY as a single valid JSON object.
3. Do NOT include Markdown formatting (such as ```json codeblocks) or conversational intro text.

REQUIRED JSON SCHEMA:
{
  "finding_id": "string",
  "is_plausible": true | false,
  "vulnerability_type": "string",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "reasoning": "Detailed explanation of why this finding is or is not a real security vulnerability.",
  "evidence": "Specific lines or code patterns from the context that support your decision.",
  "impact": "Explanation of potential security risk if exploited.",
  "remediation": "Concrete recommendation on how developers should fix or refactor the code.",
  "confidence": "HIGH" | "MEDIUM" | "LOW"
}
"""


def build_assessor_user_prompt(finding: dict) -> str:
    """
    Formats a single finding dictionary into a structured user prompt for the LLM.

    :param finding: Dictionary containing normalized finding keys and code_context.
    :return: Formatted prompt string for the user role message.
    """
    finding_id = finding.get("finding_id", "UNKNOWN")
    rule_id = finding.get("rule_id", "UNKNOWN")
    title = finding.get("title", "Security Issue")
    message = finding.get("message", "")
    file_path = finding.get("file_path", "")
    start_line = finding.get("start_line", 0)
    end_line = finding.get("end_line", 0)
    scanner_severity = finding.get("scanner_severity", "UNKNOWN")
    code_context = finding.get("code_context", "No code context available.")

    user_prompt = f"""Please assess the following SAST security finding:

Finding ID: {finding_id}
Scanner Rule ID: {rule_id}
Title: {title}
Scanner Severity: {scanner_severity}
Target File: {file_path}
Vulnerable Lines: {start_line}-{end_line}
Scanner Message: {message}

Source Code Context (Vulnerable line marked with ->):
```
{code_context}
```

Assess this finding according to the required JSON schema.
"""
    return user_prompt
