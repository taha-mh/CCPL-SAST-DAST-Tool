"""Independent Pass 2 security review through the OpenAI Responses API."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.append(str(Path(__file__).resolve().parents[1]))
from prompts.reviewer_prompt import REVIEWER_SYSTEM_PROMPT, build_reviewer_user_prompt

logger = logging.getLogger(__name__)

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-5.4-nano"
DEFAULT_REASONING_EFFORT = "low"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_OUTPUT_TOKENS = 700

REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "decision": {
            "type": "string",
            "enum": ["confirmed", "rejected", "needs_review"],
        },
        "review_reason": {"type": "string"},
        "final_severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        },
        "confidence": {
            "type": "string",
            "enum": ["HIGH", "MEDIUM", "LOW"],
        },
    },
    "required": [
        "finding_id",
        "decision",
        "review_reason",
        "final_severity",
        "confidence",
    ],
    "additionalProperties": False,
}


def _configuration_error(error_type: str, reason: str) -> dict[str, Any]:
    """Return a safe auditable verdict when independent review cannot run."""
    return {
        "decision": "needs_review",
        "review_reason": reason,
        "final_severity": "LOW",
        "confidence": "LOW",
        "review_status": "error",
        "error_type": error_type,
    }


def _extract_output_text(response_data: dict[str, Any]) -> str:
    """Extract the assistant text from a raw Responses API response."""
    if isinstance(response_data.get("output_text"), str):
        return response_data["output_text"].strip()

    for item in response_data.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"].strip()
    return ""


def _validate_review(review: Any) -> dict[str, Any]:
    """Defensively validate the fields guaranteed by Structured Outputs."""
    if not isinstance(review, dict):
        raise ValueError("Reviewer response is not a JSON object")

    required = set(REVIEW_SCHEMA["required"])
    missing = sorted(required.difference(review))
    if missing:
        raise ValueError(f"Reviewer response is missing fields: {', '.join(missing)}")

    if review["decision"] not in {"confirmed", "rejected", "needs_review"}:
        raise ValueError("Reviewer returned an invalid decision")
    if review["final_severity"] not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError("Reviewer returned an invalid severity")
    if review["confidence"] not in {"HIGH", "MEDIUM", "LOW"}:
        raise ValueError("Reviewer returned an invalid confidence")
    return review


def query_openai(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str | None = None,
    api_key: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Request one strict reviewer verdict from the OpenAI Responses API."""
    selected_model = model or os.getenv("OPENAI_REVIEWER_MODEL", DEFAULT_MODEL)
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        return _configuration_error(
            "missing_api_key",
            "OpenAI Reviewer is not configured; manual security review is required.",
        )

    reasoning_effort = os.getenv(
        "OPENAI_REVIEWER_REASONING_EFFORT", DEFAULT_REASONING_EFFORT
    )
    if reasoning_effort not in {"none", "low", "medium", "high", "xhigh"}:
        return _configuration_error(
            "invalid_configuration",
            "OpenAI reviewer reasoning effort is invalid; manual security review is required.",
        )

    payload = {
        "model": selected_model,
        "instructions": system_prompt,
        "input": user_prompt,
        "reasoning": {"effort": reasoning_effort},
        "max_output_tokens": int(
            os.getenv("OPENAI_REVIEWER_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS)
        ),
        "store": False,
        "text": {
            "verbosity": "low",
            "format": {
                "type": "json_schema",
                "name": "security_review",
                "strict": True,
                "schema": REVIEW_SCHEMA,
            },
        },
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    owns_client = client is None
    http_client = client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
    try:
        response = http_client.post(OPENAI_RESPONSES_URL, headers=headers, json=payload)
        response.raise_for_status()
        response_data = response.json()
        output_text = _extract_output_text(response_data)
        if not output_text:
            raise ValueError("OpenAI response did not contain reviewer output text")

        review = _validate_review(json.loads(output_text))
        review["review_status"] = "success"
        review["review_model"] = selected_model
        usage = response_data.get("usage", {})
        review["usage"] = {
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        }
        return review
    except httpx.TimeoutException:
        logger.error("OpenAI Reviewer request timed out.")
        return _configuration_error(
            "timeout", "OpenAI Reviewer timed out; manual security review is required."
        )
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        error_type = {
            401: "authentication_error",
            403: "permission_error",
            429: "rate_limit_error",
        }.get(status, "api_error")
        logger.error("OpenAI Reviewer API returned HTTP %s.", status)
        return _configuration_error(
            error_type,
            f"OpenAI Reviewer returned HTTP {status}; manual security review is required.",
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.error("OpenAI Reviewer returned an invalid structured response: %s", exc)
        return _configuration_error(
            "invalid_response",
            "OpenAI Reviewer returned an invalid structured response; manual security review is required.",
        )
    except httpx.HTTPError as exc:
        logger.error("OpenAI Reviewer connection failed: %s", type(exc).__name__)
        return _configuration_error(
            "connection_error",
            "OpenAI Reviewer connection failed; manual security review is required.",
        )
    finally:
        if owns_client:
            http_client.close()


def run_llm_reviewer(
    input_json_path: str = "data/normalized/assessed_findings.json",
    output_json_path: str = "data/normalized/reviewed_findings.json",
    max_findings: int | None = 3,
) -> list[dict[str, Any]]:
    """Review assessed findings one at a time using OpenAI."""
    input_file = Path(input_json_path).resolve()
    output_file = Path(output_json_path).resolve()

    if not input_file.exists():
        logger.error("Input assessed findings file not found at: %s", input_file)
        return []

    findings = json.loads(input_file.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(findings, list):
        raise ValueError("Assessed findings JSON must contain a list")

    target_findings = findings[:max_findings] if max_findings else findings
    model = os.getenv("OPENAI_REVIEWER_MODEL", DEFAULT_MODEL)
    logger.info("Running independent OpenAI Reviewer (%s) on %d findings...", model, len(target_findings))

    for index, finding in enumerate(target_findings, start=1):
        finding_id = finding.get("finding_id", f"FINDING-{index}")
        assessment = finding.get("llm_assessment", {})
        if assessment.get("llm_status") == "error":
            error_type = assessment.get("error_type", "system_failure")
            finding["llm_review"] = _configuration_error(
                "assessor_failure",
                f"Pass 1 failed due to {error_type}; manual security review is required.",
            )
            continue

        logger.info("[%d/%d] Reviewing %s...", index, len(target_findings), finding_id)
        finding["llm_review"] = query_openai(
            REVIEWER_SYSTEM_PROMPT,
            build_reviewer_user_prompt(finding),
            model=model,
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(target_findings, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target_findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
    reviewed = run_llm_reviewer(max_findings=3)
    print(f"Reviewed {len(reviewed)} findings with the OpenAI Reviewer.")
