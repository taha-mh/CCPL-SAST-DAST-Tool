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
    try:
        with open(input_file, "r", encoding="utf-8", errors="replace") as f:
            findings = json.load(f)
    except Exception as exc:
        logger.error(f"Failed to parse input assessed findings JSON file ({input_file}): {exc}")
        return []

    if not isinstance(findings, list):
        logger.error(f"Input assessed findings JSON must contain a list, got {type(findings).__name__}.")
        return []

    target_findings = findings if max_findings is None else findings[:max_findings]
    logger.info(f"Running LLM Reviewer on {len(target_findings)} findings...")

    # Load existing output file if present to resume progress cleanly
    existing_map = {}
    if output_file.exists():
        try:
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                existing_list = json.load(f)
                if isinstance(existing_list, list):
                    for item in existing_list:
                        if isinstance(item, dict) and "finding_id" in item and "llm_review" in item:
                            existing_map[item["finding_id"]] = item["llm_review"]
        except Exception:
            pass

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")

        # Resume Check: Skip if finding was already reviewed in previous run
        if finding_id in existing_map:
            finding["llm_review"] = existing_map[finding_id]
            logger.info(f"[{index}/{len(target_findings)}] Skipping {finding_id} (already reviewed).")
            continue

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
        else:
            user_prompt = build_reviewer_user_prompt(finding)
            review_verdict = query_llm(REVIEWER_SYSTEM_PROMPT, user_prompt)
            finding["llm_review"] = review_verdict

        # Incremental Auto-Save to disk after every finding (zero loss if interrupted)
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
