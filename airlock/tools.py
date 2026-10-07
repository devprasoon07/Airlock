"""Tool schemas (OpenAI function-calling format) and dispatcher."""

from __future__ import annotations

import json
from typing import Any

from airlock.guard.sandbox import run_sandboxed
from airlock.world import FakeWorld


# OpenAI function-calling format
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_emails",
            "description": "Search the user's inbox. Use query 'unread' to list unread messages.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text to search, or 'unread'."},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_email",
            "description": "Read one full email by its id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Email id from search_emails."},
                },
                "required": ["id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a local file. Available under data/files/ and data/secrets/.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path, e.g. data/files/notes.txt."},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browse_web",
            "description": "Read a local fake company web page by name, e.g. benefits.html.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Fake page URL or filename."},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email. Appends the message to outbox.jsonl and returns 'sent'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient address."},
                    "subject": {"type": "string", "description": "Email subject."},
                    "body": {"type": "string", "description": "Email body text."},
                },
                "required": ["to", "subject", "body"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_code",
            "description": "Run code in the sandbox (unavailable in S1).",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Code to execute."},
                },
                "required": ["code"],
                "additionalProperties": False,
            },
        },
    },
]


def _json_result(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def execute_tool(name: str, args: dict[str, Any], world: FakeWorld, guard=None) -> str:
    """Execute one named tool against the supplied fake world.

    `guard` is optional (S1 compatibility). When a Guard is passed, run_code
    executes inside the demo sandbox instead of returning the S1 stub.
    """
    if name == "search_emails":
        return _json_result(world.search_emails(str(args.get("query", ""))))
    if name == "read_email":
        return _json_result(world.read_email(str(args.get("id", ""))))
    if name == "read_file":
        return world.read_file(str(args.get("path", "")))
    if name == "browse_web":
        return world.browse_web(str(args.get("url", "")))
    if name == "send_email":
        return world.send_email(
            str(args.get("to", "")),
            str(args.get("subject", "")),
            str(args.get("body", "")),
        )
    if name == "run_code":
        if guard is None:
            return "sandbox not built yet"
        res = run_sandboxed(str(args.get("code", "")))
        if res["blocked"]:
            return f"Sandbox refused: {res['blocked']}"
        out = res["stdout"] or ""
        if res["stderr"]:
            out += ("\n" if out else "") + "[stderr]\n" + res["stderr"]
        if res["timed_out"]:
            out += ("\n" if out else "") + "[killed: timeout]"
        return out or "(no output)"
    raise ValueError(f"Unknown tool: {name}")
