"""Tamper-evident, append-only audit log (hash-chained JSONL).

Each record embeds the SHA-256 of the previous record, so deleting or editing
any entry breaks the chain and `verify()` reports the first bad sequence number.
Only argument *hashes* are stored, never raw secrets.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical(event: dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(prev_hash: str, event: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(event)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._seq = 0
        self._last_hash = GENESIS_HASH
        if self.path.is_file():
            last: dict[str, Any] | None = None
            with self.path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
            if last:
                self._seq = int(last.get("seq", 0))
                self._last_hash = str(last.get("hash", GENESIS_HASH))

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            **event,
            "prev_hash": self._last_hash,
        }
        record["hash"] = _hash(self._last_hash, {k: v for k, v in record.items() if k != "hash"})
        self._last_hash = record["hash"]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(record) + "\n")
        return record

    def verify(self) -> dict[str, Any]:
        prev = GENESIS_HASH
        checked = 0
        if not self.path.is_file():
            return {"ok": True, "checked": 0}
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                checked += 1
                if record.get("prev_hash") != prev:
                    return {"ok": False, "checked": checked, "first_bad_seq": record.get("seq")}
                recomputed = _hash(prev, {k: v for k, v in record.items() if k != "hash"})
                if recomputed != record.get("hash"):
                    return {"ok": False, "checked": checked, "first_bad_seq": record.get("seq")}
                prev = record["hash"]
        return {"ok": True, "checked": checked}
