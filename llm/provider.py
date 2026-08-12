"""
Central LLM Provider Module supporting OpenAI API & Local Ollama.
"""
import json
import logging
import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


def query_llm(system_prompt: str, user_prompt: str) -> dict:
    """
    Centralized LLM provider for OpenAI API. Returns parsed JSON assessment.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("OPENAI_API_KEY is missing or invalid in .env file!")
        return {
            "llm_status": "error",
            "error_type": "missing_api_key",
            "error_message": "OPENAI_API_KEY missing in .env file.",
        }

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},  # Native JSON mode
        "temperature": 0.0,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        res_data = response.json()
        content_str = res_data["choices"][0]["message"]["content"]
        assessment = json.loads(content_str)
        if isinstance(assessment, dict):
            assessment["llm_status"] = "success"
            assessment["llm_model"] = model
        return assessment

    except requests.exceptions.Timeout:
        logger.error("OpenAI API request timed out (30s).")
        return {
            "llm_status": "error",
            "error_type": "timeout",
            "error_message": "OpenAI API request timed out (30s).",
        }
    except Exception as e:
        logger.error(f"OpenAI API Error: {e}")
        return {
            "llm_status": "error",
            "error_type": "api_error",
            "error_message": str(e),
        }
