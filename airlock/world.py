"""Fake world used by the S1 email assistant demos."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "data"


class FakeWorld:
    """A small, file-backed world with no access to the real machine."""

    def __init__(self, inbox_path: str | Path = "data/inbox.json") -> None:
        self.inbox_path = self._project_path(inbox_path)
        self._outbox_path = PROJECT_ROOT / "outbox.jsonl"
        self._outbox_lock = threading.Lock()
        self.inbox = self._load_inbox(self.inbox_path)

    @staticmethod
    def _project_path(path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate.resolve()

    @staticmethod
    def _load_inbox(path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            raise FileNotFoundError(f"Inbox not found: {path}")
        with path.open("r", encoding="utf-8") as handle:
            inbox = json.load(handle)
        if not isinstance(inbox, list):
            raise ValueError("Inbox must be a JSON list")
        return inbox

    def read_email(self, email_id: str) -> dict[str, Any]:
        for email in self.inbox:
            if email.get("id") == email_id:
                return email
        raise KeyError(f"Email not found: {email_id}")

    def search_emails(self, query: str) -> list[dict[str, Any]]:
        normalized = query.strip().lower()
        unread_only = normalized in {"unread", "is:unread", "unread emails"}
        matches: list[dict[str, Any]] = []

        for email in self.inbox:
            if unread_only:
                matched = bool(email.get("unread"))
            elif not normalized:
                matched = True
            else:
                haystack = " ".join(
                    str(email.get(field, ""))
                    for field in ("id", "from", "to", "subject", "body")
                ).lower()
                matched = normalized in haystack
            if matched:
                matches.append(
                    {
                        "id": email.get("id"),
                        "from": email.get("from"),
                        "subject": email.get("subject"),
                        "received_at": email.get("received_at"),
                        "unread": bool(email.get("unread")),
                    }
                )
        return matches

    @staticmethod
    def _allowed_data_file(path: str | Path) -> Path:
        raw = str(path).strip().replace("\\", "/")
        if not raw:
            raise ValueError("path is required")
        candidate = Path(raw)
        if candidate.is_absolute():
            raise ValueError("absolute paths are not allowed")

        parts = candidate.parts
        if ".." in parts:
            raise ValueError("parent-directory paths are not allowed")
        if parts and parts[0].lower() == "data":
            relative = Path(*parts[1:])
        else:
            relative = candidate
        if not relative.parts or relative.parts[0] not in {"files", "secrets"}:
            raise ValueError("only data/files and data/secrets are available")

        allowed_root = (DATA_ROOT / relative.parts[0]).resolve()
        resolved = (allowed_root.joinpath(*relative.parts[1:])).resolve()
        try:
            resolved.relative_to(allowed_root)
        except ValueError as exc:
            raise ValueError("path escapes the fake data directory") from exc
        if not resolved.is_file():
            raise FileNotFoundError(f"Fake file not found: {path}")
        return resolved

    def read_file(self, path: str) -> str:
        resolved = self._allowed_data_file(path)
        return resolved.read_text(encoding="utf-8")

    @staticmethod
    def _web_file(url: str | Path) -> Path:
        raw = str(url).strip()
        if not raw:
            raise ValueError("url is required")
        parsed = urlparse(raw)
        path_text = parsed.path if parsed.scheme else raw
        path_text = path_text.replace("\\", "/").strip("/")
        if not path_text or ".." in Path(path_text).parts:
            raise ValueError("invalid fake web path")
        filename = Path(path_text).name
        if not filename.endswith(".html"):
            filename += ".html"
        resolved = (DATA_ROOT / "web" / filename).resolve()
        web_root = (DATA_ROOT / "web").resolve()
        try:
            resolved.relative_to(web_root)
        except ValueError as exc:
            raise ValueError("url is outside the fake web directory") from exc
        if not resolved.is_file():
            raise FileNotFoundError(f"Fake page not found: {url}")
        return resolved

    def browse_web(self, url: str) -> str:
        return self._web_file(url).read_text(encoding="utf-8")

    def send_email(self, to: str, subject: str, body: str) -> str:
        message = {"to": to, "subject": subject, "body": body}
        with self._outbox_lock:
            with self._outbox_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(message, ensure_ascii=False) + "\n")
        return "sent"

    @property
    def outbox_path(self) -> Path:
        return self._outbox_path
