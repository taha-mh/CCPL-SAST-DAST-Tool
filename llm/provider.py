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
    Unified LLM caller. Automatically routes to OpenAI API or local Ollama
    based on LLM_PROVIDER environment variable.
    """
    provider = os.getenv("LLM_PROVIDER", "openai").lower()

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key :
            logger.error("OPENAI_API_KEY is missing or invalid in .env file!")
            return {
                "llm_status": "error",
                "error_type": "missing_api_key",
                "error_message": "OPENAI_API_KEY missing in .env",
            }

        model = os.getenv("OPENAI_MODEL", "5.4-nano")
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

    else:
        # Fallback to local Ollama
        ollama_url = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/chat")
        model = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.0},
        }
        try:
            response = requests.post(ollama_url, json=payload, timeout=300)
            response.raise_for_status()
            res_data = response.json()
            content_str = res_data.get("message", {}).get("content", "")
            if not content_str:
                content_str = res_data.get("message", {}).get("thinking", "")

            import re

            match = re.search(r"\{[\s\S]*\}", content_str)
            if match:
                content_str = match.group(0)
            assessment = json.loads(content_str)
            if isinstance(assessment, dict):
                assessment["llm_status"] = "success"
            return assessment
        except Exception as e:
            return {
                "llm_status": "error",
                "error_type": "ollama_error",
                "error_message": str(e),
            }
