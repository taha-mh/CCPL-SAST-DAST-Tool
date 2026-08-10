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
import os
import sys
from pathlib import Path
import requests


# Import prompt templates
sys.path.append(str(Path(__file__).resolve().parents[1]))
from prompts.reviewer_prompt import REVIEWER_SYSTEM_PROMPT, build_reviewer_user_prompt

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")


def query_ollama(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Sends a chat request to the local Ollama API using the requests library.

    :param system_prompt: Instructions defining the reviewer role and schema.
    :param user_prompt: Assessed finding details and initial AI diagnosis.
    :param model: Ollama model name (default: qwen3:8b).
    :return: Parsed JSON review verdict dictionary from the LLM.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "temperature": 0.0,   # Deterministic 0.0 temperature for instant JSON output
            "num_predict": 384,   # Bounded token limit for fast CPU inference
            "num_thread": 8,      # Utilize all 8 vCPUs of the VM
        },
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
        response.raise_for_status()

        # Safely decode UTF-8 response bytes to avoid Windows cp1252 charmap errors
        raw_text = response.content.decode("utf-8", errors="replace")
        response_data = json.loads(raw_text)
        message_content = response_data.get("message", {}).get("content", "").strip()
        if not message_content:
            message_content = response_data.get("message", {}).get("thinking", "").strip()

        # Robustly extract JSON object substring {...} from Qwen3.5 thinking models
        start_idx = message_content.find("{")
        end_idx = message_content.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            cleaned_content = message_content[start_idx : end_idx + 1].strip()
        else:
            cleaned_content = message_content.strip()

        try:
            review = json.loads(cleaned_content)
            return review
        except json.JSONDecodeError as err:
            logger.warning(f"Could not parse LLM JSON response string ({err}): {message_content[:200]}")
            return {
                "decision": "needs_review",
                "review_reason": f"LLM returned non-JSON string ({err}): {message_content[:200]}",
                "final_severity": "LOW",
                "confidence": "LOW",
                "raw_response": message_content,
            }

    except Exception as e:
        logger.error(f"Failed to communicate with Ollama API at {OLLAMA_API_URL}: {e}")
        return {
            "decision": "needs_review",
            "error": f"Ollama connection error: {str(e)}",
        }


def run_llm_reviewer(
    input_json_path: str = "data/normalized/assessed_findings.json",
    output_json_path: str = "data/normalized/reviewed_findings.json",
    max_findings: int = 3,  # Set to 3 for test runs; pass None to process all findings
) -> list:
    """
    Processes assessed findings through local Qwen3 8B LLM for a 2nd pass review.

    :param input_json_path: Path to assessed findings JSON.
    :param output_json_path: Path to save final reviewed findings JSON.
    :param max_findings: Max number of findings to review.
    :return: List of reviewed finding dictionaries.
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
    logger.info(f"Running LLM Reviewer (Qwen3 8B 2nd Pass) on {len(target_findings)} findings...")

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
        review_verdict = query_ollama(REVIEWER_SYSTEM_PROMPT, user_prompt)

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
