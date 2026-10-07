"""Thin wrapper around an OpenAI-compatible chat endpoint (NVIDIA NIM)."""

import os
import time

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            base_url=os.environ["NVIDIA_BASE_URL"],
            api_key=os.environ["NVIDIA_API_KEY"],
        )
    return _client


def chat(system: str, messages: list, tools: list | None = None):
    """Send a chat completion request and return the response object.

    *tools* uses OpenAI function-calling format::

        [{"type": "function", "function": {"name": ..., "parameters": ...}}]
    """
    model = os.environ.get("MODEL", "nvidia/nemotron-3-super-120b-a12b")
    client = _get_client()

    kwargs: dict = {
        "model": model,
        "max_tokens": 1024,
        "temperature": 0.2,
        "messages": [{"role": "system", "content": system}] + messages,
    }

    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    for attempt in range(3):
        try:
            return client.chat.completions.create(**kwargs)
        except Exception as e:
            if "503" in str(e) and attempt < 2:
                time.sleep(2)
                continue
            raise
