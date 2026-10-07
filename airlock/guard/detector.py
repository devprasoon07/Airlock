"""Layer-A heuristic detector: injection directives in tool outputs,
exfiltration shapes in tool-call arguments. No LLM calls here."""

from __future__ import annotations

import re

# (compiled regex, confidence, label)
INJECTION_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(p, re.IGNORECASE), c, label)
    for p, c, label in [
        (r"ignore\s+(all\s+)?previous\s+instructions", 0.95, "ignore-previous-instructions"),
        (r"disregard\s+(all\s+)?(previous|above)\s+(instructions|directives|orders)", 0.95, "disregard-instructions"),
        (r"override\s+(the\s+)?(default|previous)\s+(task|instructions|directive)", 0.90, "override-task"),
        (r"(urgent\s+)?system\s+(directive|command|override|instruction)\b", 0.90, "fake-system-directive"),
        (r"execute\s+the\s+following\s+tools?\s+immediately", 0.90, "forced-tool-execution"),
        (r"do\s+not\s+(tell|inform|notify|alert|mention).*user", 0.85, "concealment"),
        (r"you\s+are\s+now\s+(an?\s+)?(admin|root|system|superuser)\b", 0.90, "role-reassignment"),
        (r"act\s+as\s+(if\s+you\s+were\s+)?(a\s+)?(system|administrator|root)\b", 0.80, "role-play-escalation"),
        (r"disable\s+(the\s+)?(guard|firewall|filter|safety|protection)", 0.95, "guard-disable-attempt"),
        (r"bypass\s+(the\s+)?(guard|firewall|filter|policy|safety)", 0.90, "guard-bypass-attempt"),
    ]
]

EXFIL_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(p), c, label)
    for p, c, label in [
        (r"sk-[A-Za-z0-9\-_]{6,}", 0.99, "canary-shaped-secret"),
        (r"(api[_-]?key|secret[_-]?key|password|credential)\s*[:=]\s*\S+", 0.70, "credential-label"),
    ]
]

AUTHORITY_SENDER_HINTS = (
    "security-daemon", "admin@", "compliance", "system@", "root@", "no-reply@internal",
)


def _score(text: str, patterns: list[tuple[re.Pattern, float, str]]) -> tuple[float, list[str]]:
    hits: list[str] = []
    best = 0.0
    for rx, conf, label in patterns:
        if rx.search(text):
            hits.append(label)
            best = max(best, conf)
    return best, hits


def score_injection(text: str) -> tuple[float, list[str]]:
    """How likely `text` (a tool *result*) contains an injected instruction."""
    if not text:
        return 0.0, []
    return _score(text, INJECTION_PATTERNS)


def score_exfiltration(text: str) -> tuple[float, list[str]]:
    """How likely `text` (tool-call *arguments* or output) exfiltrates secrets."""
    if not text:
        return 0.0, []
    return _score(text, EXFIL_PATTERNS)


def has_external_recipient(address: str) -> bool:
    """True if an email address is outside company.com."""
    m = re.search(r"@([\w.-]+\.\w+)", address or "")
    if not m:
        return False
    domain = m.group(1).lower()
    return domain != "company.com" and not domain.endswith(".company.com")


def looks_like_authority_spoof(sender: str) -> bool:
    s = (sender or "").lower()
    return any(h in s for h in AUTHORITY_SENDER_HINTS)


def tag_untrusted(text: str, source: str) -> str:
    return f'<untrusted-data source="{source}">\n{text}\n</untrusted-data>'


def redact_spans(text: str) -> tuple[str, list[str]]:
    """Replace matched injection spans with a marker; returns (cleaned, labels)."""
    redacted_labels: list[str] = []
    cleaned = text
    for rx, _conf, label in INJECTION_PATTERNS:
        cleaned, n = rx.subn("[redacted: suspected injected instruction]", cleaned)
        if n:
            redacted_labels.append(label)
    return cleaned, redacted_labels
