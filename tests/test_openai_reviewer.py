import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from llm.reviewer import OPENAI_RESPONSES_URL, query_openai, run_llm_reviewer


VALID_REVIEW = {
    "finding_id": "DAST-001",
    "decision": "confirmed",
    "review_reason": "Observed response evidence supports the scanner finding.",
    "final_severity": "HIGH",
    "confidence": "HIGH",
}


def mock_client(status_code=200, output=None):
    def handler(request):
        if status_code != 200:
            return httpx.Response(status_code, json={"error": {"message": "test"}})
        body = output if output is not None else VALID_REVIEW
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(body)}],
                    }
                ],
                "usage": {"input_tokens": 100, "output_tokens": 30, "total_tokens": 130},
            },
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


class OpenAIReviewerTests(unittest.TestCase):
    def test_valid_structured_review(self):
        with mock_client() as client:
            result = query_openai("system", "user", api_key="test-key", client=client)

        self.assertEqual(result["decision"], "confirmed")
        self.assertEqual(result["review_status"], "success")
        self.assertEqual(result["review_model"], "gpt-5.4-nano")
        self.assertEqual(result["usage"]["total_tokens"], 130)

    def test_request_uses_responses_api_and_strict_schema(self):
        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["payload"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"output_text": json.dumps(VALID_REVIEW), "usage": {}},
            )

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            query_openai("system", "user", api_key="test-key", client=client)

        self.assertEqual(captured["url"], OPENAI_RESPONSES_URL)
        self.assertEqual(captured["payload"]["model"], "gpt-5.4-nano")
        self.assertTrue(captured["payload"]["text"]["format"]["strict"])
        self.assertFalse(captured["payload"]["store"])

    def test_missing_key_fails_safe(self):
        with patch.dict(os.environ, {}, clear=True):
            result = query_openai("system", "user")

        self.assertEqual(result["decision"], "needs_review")
        self.assertEqual(result["error_type"], "missing_api_key")

    def test_rate_limit_fails_safe(self):
        with mock_client(status_code=429) as client:
            result = query_openai("system", "user", api_key="test-key", client=client)

        self.assertEqual(result["decision"], "needs_review")
        self.assertEqual(result["error_type"], "rate_limit_error")

    def test_invalid_schema_fails_safe(self):
        with mock_client(output={"decision": "confirmed"}) as client:
            result = query_openai("system", "user", api_key="test-key", client=client)

        self.assertEqual(result["error_type"], "invalid_response")

    def test_assessor_failure_does_not_call_openai(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "assessed.json"
            output_path = root / "reviewed.json"
            input_path.write_text(
                json.dumps(
                    [
                        {
                            "finding_id": "DAST-001",
                            "llm_assessment": {
                                "llm_status": "error",
                                "error_type": "timeout",
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )

            with patch("llm.reviewer.query_openai") as query:
                reviewed = run_llm_reviewer(str(input_path), str(output_path), None)

            query.assert_not_called()
            self.assertEqual(reviewed[0]["llm_review"]["error_type"], "assessor_failure")
            self.assertTrue(output_path.exists())


if __name__ == "__main__":
    unittest.main()
