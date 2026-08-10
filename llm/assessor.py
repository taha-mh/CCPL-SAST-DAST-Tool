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
import os
import sys
from pathlib import Path
import requests

# Import prompt templates
sys.path.append(str(Path(__file__).resolve().parents[1]))
from prompts.assessor_prompt import ASSESSOR_SYSTEM_PROMPT, build_assessor_user_prompt

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")


def query_ollama(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Sends a chat request to the local Ollama API using the requests library
    and returns the parsed JSON response.

    :param system_prompt: Instructions defining the LLM role and schema.
    :param user_prompt: Finding details and code context.
    :param model: Ollama model name (default: qwen3:8b).
    :return: Parsed JSON assessment dictionary from the LLM.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "keep_alive": "30m",  # Keep model loaded in RAM for 30 minutes so it doesn't reload
        "options": {
            "temperature": 0.2,   # Low temperature for deterministic reasoning
            "num_predict": 1024,  # Allow up to 1024 tokens so Qwen3 reasoning completes
        },
    }

    try:
        # Use requests.post to send JSON payload with a 300-second timeout
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
        response.raise_for_status()  # Raises HTTPError if status code is 4xx/5xx

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

        # Parse the inner JSON string returned by Qwen
        try:
            assessment = json.loads(cleaned_content)
            if isinstance(assessment, dict):
                assessment["llm_status"] = "success"
            return assessment
        except json.JSONDecodeError:
            logger.warning(f"Could not parse LLM JSON response string: {message_content[:100]}")
            return {
                "llm_status": "error",
                "error_type": "json_parse_error",
                "error_message": f"LLM returned non-JSON string: {message_content[:200]}",
                "raw_response": message_content,
            }

    except requests.exceptions.Timeout:
        logger.error("Ollama API request timed out.")
        return {
            "llm_status": "error",
            "error_type": "timeout",
            "error_message": "LLM API request timed out (300s).",
        }
    except Exception as e:
        logger.error(f"Failed to communicate with Ollama API at {OLLAMA_API_URL}: {e}")
        return {
            "llm_status": "error",
            "error_type": "connection_error",
            "error_message": f"Ollama connection error: {str(e)}",
        }


def run_llm_assessor(
    input_json_path: str = "data/normalized/findings_with_context.json",
    output_json_path: str = "data/normalized/assessed_findings.json",
    max_findings: int = 3,  # Set to 3 for test runs; pass None to process all 85 findings
) -> list:
    """
    Processes findings through local Qwen3 8B LLM via Ollama and saves assessments.

    :param input_json_path: Path to findings with code context.
    :param output_json_path: Path to save LLM assessed findings.
    :param max_findings: Max number of findings to assess.
    :return: List of assessed finding dictionaries.
    """
    input_file = Path(input_json_path).resolve()
    output_file = Path(output_json_path).resolve()

    if not input_file.exists():
        logger.error(f"Input findings file not found at: {input_file}")
        return []

    logger.info(f"Loading findings from: {input_file}")
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        findings = json.load(f)

    target_findings = findings[:max_findings] if max_findings else findings
    logger.info(f"Running LLM Assessor (Qwen3 8B) on {len(target_findings)} findings...")

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")
        logger.info(f"[{index}/{len(target_findings)}] Assessing {finding_id} ({finding.get('rule_id')})...")

        user_prompt = build_assessor_user_prompt(finding)
        assessment = query_ollama(ASSESSOR_SYSTEM_PROMPT, user_prompt)

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
