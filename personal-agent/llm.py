"""Unified LLM wrapper — Anthropic Claude.

Replaces the previous Gemini integration. Provides:
- generate_text() for free-form generation
- generate_json() for structured output via forced tool use

Default models:
- claude-sonnet-4-6 — analysis, digests, pattern synthesis
- claude-haiku-4-5 — fast/cheap tasks (fact extraction)

Environment:
- ANTHROPIC_API_KEY must be set.
"""

import os
import logging
from typing import Any

import anthropic

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

MODEL_SONNET = "claude-sonnet-4-6"
MODEL_HAIKU = "claude-haiku-4-5"
DEFAULT_MODEL = MODEL_SONNET

_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        _client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    return _client


async def generate_text(
    prompt: str,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 1024,
) -> str:
    """Generate a free-form text response from Claude."""
    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set; cannot call Claude")
        return ""

    client = _get_client()
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    try:
        response = await client.messages.create(**kwargs)
    except anthropic.APIError as e:
        logger.error("Claude generate_text error (%s): %s", type(e).__name__, e)
        return ""
    except Exception as e:
        logger.error("Claude generate_text unexpected error: %s", e)
        return ""

    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


async def generate_json(
    prompt: str,
    schema: dict,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 1024,
    tool_name: str = "return_structured_output",
    tool_description: str = "Return the structured output according to the schema.",
) -> dict | None:
    """Generate a structured JSON response via forced tool use.

    schema must be a valid JSON Schema object describing the tool's input.
    Returns the parsed tool input dict, or None on failure.
    """
    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set; cannot call Claude")
        return None

    client = _get_client()
    tool = {
        "name": tool_name,
        "description": tool_description,
        "input_schema": schema,
    }
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "tools": [tool],
        "tool_choice": {"type": "tool", "name": tool_name},
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    try:
        response = await client.messages.create(**kwargs)
    except anthropic.APIError as e:
        logger.error("Claude generate_json error (%s): %s", type(e).__name__, e)
        return None
    except Exception as e:
        logger.error("Claude generate_json unexpected error: %s", e)
        return None

    for block in response.content:
        if block.type == "tool_use":
            return dict(block.input)
    return None
