"""Central OpenAI Responses API provider for structured security verdicts."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from dotenv import load_dotenv


load_dotenv()

logger = logging.getLogger(__name__)

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-5.4-nano"


def _error(error_type: str, message: str, *, model: str) -> dict[str, Any]:
    return {
        "llm_status": "error",
        "error_type": error_type,
        "error_message": message,
        "llm_model": model,
    }


def _extract_output_text(payload: dict[str, Any]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct

    for item in payload.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str) and text.strip():
                    return text
    return ""


def _matches_schema(value: Any, schema: dict[str, Any]) -> bool:
    """Validate the small JSON-Schema subset used by the verdict contracts."""
    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, dict):
            return False
        if any(key not in value for key in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False:
            allowed = set(schema.get("properties", {}))
            if any(key not in allowed for key in value):
                return False
        return all(
            key not in value or _matches_schema(value[key], child)
            for key, child in schema.get("properties", {}).items()
        )
    if schema_type == "string":
        return isinstance(value, str) and ("enum" not in schema or value in schema["enum"])
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "array":
        return isinstance(value, list) and all(
            _matches_schema(item, schema.get("items", {})) for item in value
        )
    return True


def query_llm(
    system_prompt: str,
    user_prompt: str,
    *,
    response_schema: dict[str, Any] | None = None,
    schema_name: str = "security_verdict",
    model: str | None = None,
    reasoning_effort: str | None = None,
    max_output_tokens: int | None = None,
    api_key: str | None = None,
    timeout_seconds: float = 90.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Call OpenAI once and return a validated JSON object or a fail-safe error."""
    selected_model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    selected_key = api_key or os.getenv("OPENAI_API_KEY", "")
    if not selected_key.strip():
        return _error("missing_api_key", "OPENAI_API_KEY is not configured.", model=selected_model)

    effort = reasoning_effort or os.getenv("OPENAI_REASONING_EFFORT", "low")
    token_limit = max_output_tokens or int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "900"))
    payload: dict[str, Any] = {
        "model": selected_model,
        "instructions": system_prompt,
        "input": user_prompt,
        "reasoning": {"effort": effort},
        "max_output_tokens": token_limit,
        "store": False,
    }
    if response_schema is not None:
        payload["text"] = {
            "format": {
                "type": "json_schema",
                "name": schema_name,
                "strict": True,
                "schema": response_schema,
            }
        }

    owns_client = client is None
    http_client = client or httpx.Client(timeout=timeout_seconds)
    try:
        response = http_client.post(
            OPENAI_RESPONSES_URL,
            headers={"Authorization": f"Bearer {selected_key}"},
            json=payload,
        )
        if response.status_code == 401:
            return _error("authentication_error", "OpenAI rejected the API key.", model=selected_model)
        if response.status_code == 429:
            return _error("rate_limit_error", "OpenAI rate limit or quota was reached.", model=selected_model)
        response.raise_for_status()
        response_payload = response.json()
        text = _extract_output_text(response_payload)
        if not text:
            return _error("empty_response", "OpenAI returned no output text.", model=selected_model)
        result = json.loads(text)
        if not isinstance(result, dict) or (
            response_schema is not None and not _matches_schema(result, response_schema)
        ):
            return _error("invalid_response", "OpenAI output did not match the required schema.", model=selected_model)
        result["llm_status"] = "success"
        result["llm_model"] = selected_model
        result["usage"] = response_payload.get("usage", {})
        return result
    except httpx.TimeoutException:
        return _error("timeout", "OpenAI request timed out.", model=selected_model)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        logger.error("OpenAI structured response failed: %s", exc)
        return _error("api_error", "OpenAI request or response processing failed.", model=selected_model)
    finally:
        if owns_client:
            http_client.close()
