"""
LLM Reviewer Module for CCPL Web SAST Tool.

Responsibility:
1. Load assessed findings from data/normalized/assessed_findings.json.
2. Perform a 2nd logical review pass using local Ollama (qwen3:8b) API.
3. Classify findings into 'confirmed', 'rejected', or 'needs_review'.
4. Save reviewed findings to data/normalized/reviewed_findings.json.
"""

import json
import logging
import sys
from pathlib import Path

# Import prompt templates and central LLM provider
sys.path.append(str(Path(__file__).resolve().parents[1]))
from prompts.reviewer_prompt import REVIEWER_SYSTEM_PROMPT, build_reviewer_user_prompt
from llm.provider import query_llm

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_llm_reviewer(
    input_json_path: str = "data/normalized/assessed_findings.json",
    output_json_path: str = "data/normalized/reviewed_findings.json",
    max_findings: int | None = 3,
) -> list[dict]:
    """
    Reads assessed findings, performs 2nd pass Senior Audit Reviewer evaluation
    via central query_llm provider, and attaches the review verdict dictionary.
    """
    input_file = Path(input_json_path).resolve()
    output_file = Path(output_json_path).resolve()

    if not input_file.exists():
        logger.error(f"Input assessed findings file not found at: {input_file}")
        return []

    logger.info(f"Loading assessed findings from: {input_file}")
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        findings = json.load(f)

    target_findings = findings[:max_findings] if max_findings else findings
    logger.info(f"Running LLM Reviewer on {len(target_findings)} findings...")

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")
        logger.info(f"[{index}/{len(target_findings)}] Reviewing {finding_id} ({finding.get('rule_id')})...")

        # Safely handle Pass 1 Assessor failures without wasting tokens or making false assumptions
        assessment = finding.get("llm_assessment", {})
        if assessment.get("llm_status") == "error":
            err_type = assessment.get("error_type", "system_failure")
            logger.warning(f"Skipping Pass 2 LLM call for {finding_id} due to Pass 1 error ({err_type}).")
            finding["llm_review"] = {
                "decision": "needs_review",
                "review_reason": f"Pass 1 LLM evaluation failed due to {err_type}. Flagged for manual security review.",
                "final_severity": finding.get("scanner_severity", "LOW"),
                "confidence": "LOW",
            }
            continue

        user_prompt = build_reviewer_user_prompt(finding)
        review_verdict = query_llm(REVIEWER_SYSTEM_PROMPT, user_prompt)

        # Attach 2nd pass LLM review verdict to finding dictionary
        finding["llm_review"] = review_verdict

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(target_findings, f, indent=2, ensure_ascii=False)

    logger.info(f"Successfully reviewed {len(target_findings)} findings!")
    logger.info(f"Saved reviewed findings to: {output_file}")

    return target_findings


if __name__ == "__main__":
    print("--- Running Milestone 6: LLM Reviewer (Qwen3 8B 2nd Pass) Test ---")
    results = run_llm_reviewer(max_findings=3)
    print(f"\nTotal Reviewed Findings: {len(results)}")
    if results:
        print("\nSample Reviewed Finding (First Item):")
        sample = results[0]
        print(f"ID: {sample.get('finding_id')}")
        print(f"Rule: {sample.get('rule_id')}")
        print("\n--- LLM Review Verdict ---")
        print(json.dumps(sample.get("llm_review"), indent=2))
