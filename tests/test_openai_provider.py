import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx

from llm.provider import OPENAI_RESPONSES_URL, query_llm
from llm.reviewer import run_llm_reviewer
from prompts.reviewer_prompt import REVIEWER_RESPONSE_SCHEMA


VALID_REVIEW = {
    "finding_id": "MOBSF-001",
    "decision": "confirmed",
    "review_reason": "The observed evidence supports the finding.",
    "final_severity": "HIGH",
    "confidence": "HIGH",
}


def test_provider_uses_responses_api_and_strict_schema() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json={
            "output_text": json.dumps(VALID_REVIEW),
            "usage": {"input_tokens": 100, "output_tokens": 30, "total_tokens": 130},
        })

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = query_llm(
            "system",
            "user",
            api_key="test-key",
            client=client,
            response_schema=REVIEWER_RESPONSE_SCHEMA,
            schema_name="security_review",
        )

    assert captured["url"] == OPENAI_RESPONSES_URL
    assert captured["payload"]["model"] == "gpt-5.4-nano"
    assert captured["payload"]["text"]["format"]["strict"] is True
    assert captured["payload"]["store"] is False
    assert result["decision"] == "confirmed"
    assert result["llm_status"] == "success"
    assert result["usage"]["total_tokens"] == 130


def test_provider_fails_safe_without_key() -> None:
    with patch.dict(os.environ, {}, clear=True):
        result = query_llm("system", "user", response_schema=REVIEWER_RESPONSE_SCHEMA)
    assert result["llm_status"] == "error"
    assert result["error_type"] == "missing_api_key"


def test_provider_rejects_invalid_schema() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, json={"output_text": json.dumps({"decision": "confirmed"})},
    ))
    with httpx.Client(transport=transport) as client:
        result = query_llm(
            "system", "user", api_key="test-key", client=client,
            response_schema=REVIEWER_RESPONSE_SCHEMA,
        )
    assert result["error_type"] == "invalid_response"


def test_reviewer_skips_api_after_assessor_failure(tmp_path: Path) -> None:
    input_path = tmp_path / "assessed.json"
    output_path = tmp_path / "reviewed.json"
    input_path.write_text(json.dumps([{
        "finding_id": "MOBSF-001",
        "scanner_severity": "HIGH",
        "llm_assessment": {"llm_status": "error", "error_type": "timeout"},
    }]), encoding="utf-8")

    with patch("llm.reviewer.query_llm") as query:
        reviewed = run_llm_reviewer(str(input_path), str(output_path))

    query.assert_not_called()
    assert reviewed[0]["llm_review"]["decision"] == "needs_review"
    assert output_path.exists()
