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
    start_index: int | None = None,
    end_index: int | None = None,
    max_findings: int | None = None,
) -> list[dict]:
    """
    Reads normalized findings with code context, executes LLM assessment pass
    via central query_llm provider, and attaches the AI assessment dictionary.
    Supports start_index, end_index, and backward-compatible max_findings.
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

    limit = end_index if end_index is not None else max_findings
    start = (start_index - 1) if (start_index and start_index > 0) else 0
    target_findings = findings[start:limit] if limit is not None else findings[start:]
    logger.info(f"Running LLM Assessor on {len(target_findings)} findings...")

    # Load existing output file if present to resume progress cleanly
    existing_map = {}
    if output_file.exists():
        try:
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                existing_list = json.load(f)
                if isinstance(existing_list, list):
                    for item in existing_list:
                        if isinstance(item, dict) and "finding_id" in item and "llm_assessment" in item:
                            existing_map[item["finding_id"]] = item["llm_assessment"]
        except Exception:
            pass

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")

        # Resume Check: Skip if finding was already assessed in previous run
        if finding_id in existing_map:
            finding["llm_assessment"] = existing_map[finding_id]
            logger.info(f"[{index}/{len(target_findings)}] Skipping {finding_id} (already assessed).")
            continue

        logger.info(f"[{index}/{len(target_findings)}] Assessing {finding_id} ({finding.get('rule_id')})...")

        user_prompt = build_assessor_user_prompt(finding)
        assessment = query_llm(ASSESSOR_SYSTEM_PROMPT, user_prompt)

        # Attach LLM assessment to finding dictionary
        finding["llm_assessment"] = assessment

        # Incremental Auto-Save to disk after every finding (zero loss if interrupted)
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
