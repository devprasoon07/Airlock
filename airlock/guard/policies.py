"""Policy engine: default-deny, per-tool allow/deny rules loaded from JSON."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _strip_data_prefix(pattern: str) -> str:
    p = pattern.strip().replace("\\", "/").lower()
    if p.startswith("data/"):
        p = p[len("data/"):]
    return p


def _normalize_web_url(raw_url: str) -> str | None:
    """Mirror world._web_file resolution: 'web/<file>.html' form, or None.

    The policy must judge the same URL the tool will actually fetch —
    otherwise benign calls like browse_web("benefits") get wrongly blocked.
    """
    raw = (raw_url or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        # Absolute external URL: this tool only serves local fake pages.
        return None
    path_text = parsed.path if parsed.scheme else raw
    path_text = path_text.replace("\\", "/").strip("/")
    if not path_text or ".." in Path(path_text).parts:
        return None
    filename = Path(path_text).name
    if not filename.endswith(".html"):
        filename += ".html"
    return f"web/{filename}".lower()


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]):
        self.policy = policy
        self.default = policy.get("default", "deny")
        self.tools: dict[str, Any] = policy.get("tools", {})

    @classmethod
    def load(cls, path: str | Path) -> "PolicyEngine":
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _match_any(self, value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(value.lower(), p.lower()) for p in patterns)

    def evaluate(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        rule = self.tools.get(tool_name)
        if rule is None:
            return {
                "action": "deny",
                "reason": f"no policy rule for tool '{tool_name}' (default-deny)",
                "rule": "default",
            }
        if rule.get("allow") is True:
            return {
                "action": "allow",
                "reason": f"tool '{tool_name}' explicitly allowed",
                "rule": tool_name,
            }

        if tool_name == "send_email":
            to = str(args.get("to", ""))
            allow_to = rule.get("allow_to", [])
            if allow_to and not self._match_any(to, allow_to):
                return {
                    "action": "deny",
                    "reason": f"recipient '{to}' not in allow-list",
                    "rule": f"{tool_name}.allow_to",
                }
            return {"action": "allow", "reason": "recipient within allow-list", "rule": tool_name}

        if tool_name == "read_file":
            path = str(args.get("path", "")).replace("\\", "/")
            for pat in rule.get("deny_paths", []):
                if fnmatch.fnmatch(path.lower(), pat.lower()):
                    return {
                        "action": "deny",
                        "reason": f"path '{path}' matches deny pattern '{pat}'",
                        "rule": f"{tool_name}.deny_paths",
                    }
            allow_paths = rule.get("allow_paths", [])
            if allow_paths and not self._match_any(path, allow_paths):
                return {
                    "action": "deny",
                    "reason": f"path '{path}' not in allow-list",
                    "rule": f"{tool_name}.allow_paths",
                }
            return {"action": "allow", "reason": "path within allow-list", "rule": tool_name}

        if tool_name == "browse_web":
            norm = _normalize_web_url(str(args.get("url", "")))
            if norm is None:
                return {
                    "action": "deny",
                    "reason": f"url '{args.get('url', '')}' is invalid",
                    "rule": f"{tool_name}.allow_paths",
                }
            allow_paths = [_strip_data_prefix(p) for p in rule.get("allow_paths", [])]
            if allow_paths and not self._match_any(norm, allow_paths):
                return {
                    "action": "deny",
                    "reason": f"url '{args.get('url', '')}' not in allow-list",
                    "rule": f"{tool_name}.allow_paths",
                }
            return {"action": "allow", "reason": "url within allow-list", "rule": tool_name}

        if tool_name == "run_code":
            if "sandbox" in rule.get("require", []):
                return {
                    "action": "allow",
                    "reason": "sandboxed execution required and provided",
                    "rule": tool_name,
                }
            return {"action": "deny", "reason": "run_code requires sandbox", "rule": tool_name}

        if self.default == "deny":
            return {
                "action": "deny",
                "reason": f"tool '{tool_name}' not explicitly allowed (default-deny)",
                "rule": "default",
            }
        return {"action": "allow", "reason": "default-allow", "rule": "default"}
