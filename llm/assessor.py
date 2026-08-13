"""
LLM Assessor Module for CCPL Web SAST Tool.

Responsibility:
1. Load enriched findings from data/normalized/findings_with_context.json.
2. Send each finding and code context to local Ollama (qwen3:8b) API using the requests library.
3. Parse and validate the LLM's structured JSON assessment.
4. Save results to data/normalized/assessed_findings.json.
"""

import json
import logging
import sys
from pathlib import Path

# Import prompt templates and central LLM provider
sys.path.append(str(Path(__file__).resolve().parents[1]))
from prompts.assessor_prompt import ASSESSOR_SYSTEM_PROMPT, build_assessor_user_prompt
from llm.provider import query_llm

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_llm_assessor(
    input_json_path: str = "data/normalized/findings_with_context.json",
    output_json_path: str = "data/normalized/assessed_findings.json",
    max_findings: int | None = 3,
) -> list[dict]:
    """
    Reads normalized findings with code context, executes LLM assessment pass
    via central query_llm provider, and attaches the AI assessment dictionary.
    """
    input_file = Path(input_json_path).resolve()
    output_file = Path(output_json_path).resolve()

    if not input_file.exists():
        logger.error(f"Input findings file not found at: {input_file}")
        return []

    logger.info(f"Loading findings from: {input_file}")
    try:
        with open(input_file, "r", encoding="utf-8", errors="replace") as f:
            findings = json.load(f)
    except Exception as exc:
        logger.error(f"Failed to parse input findings JSON file ({input_file}): {exc}")
        return []

    if not isinstance(findings, list):
        logger.error(f"Input findings JSON must contain a list, got {type(findings).__name__}.")
        return []

    target_findings = findings if max_findings is None else findings[:max_findings]
    logger.info(f"Running LLM Assessor on {len(target_findings)} findings...")

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")
        logger.info(f"[{index}/{len(target_findings)}] Assessing {finding_id} ({finding.get('rule_id')})...")

        user_prompt = build_assessor_user_prompt(finding)
        assessment = query_llm(ASSESSOR_SYSTEM_PROMPT, user_prompt)

        # Attach LLM assessment to finding dictionary
        finding["llm_assessment"] = assessment

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(target_findings, f, indent=2, ensure_ascii=False)

    logger.info(f"Successfully assessed {len(target_findings)} findings!")
    logger.info(f"Saved assessed findings to: {output_file}")

    return target_findings


if __name__ == "__main__":
    print("--- Running Milestone 5: LLM Assessor (Qwen3 8B) Test ---")
    results = run_llm_assessor(max_findings=3)  # Set to process 3 findings for test
    print(f"\nTotal Assessed Findings: {len(results)}")
    if results:
        print("\nSample Assessed Finding (First Item):")
        sample = results[0]
        print(f"ID: {sample.get('finding_id')}")
        print(f"Rule: {sample.get('rule_id')}")
        print("\n--- LLM Assessment Output ---")
        print(json.dumps(sample.get("llm_assessment"), indent=2))
