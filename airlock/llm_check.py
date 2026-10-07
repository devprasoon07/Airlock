"""Quick smoke test: one tiny call to the NVIDIA endpoint."""

import sys

from airlock.llm import chat

try:
    response = chat(
        system="You are a helpful assistant.",
        messages=[{"role": "user", "content": "Say 'OK' and nothing else."}],
    )
    text = response.choices[0].message.content or ""
    print("OK" if "OK" in text.upper() else f"Unexpected: {text}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
