"""Best-effort redaction of likely secrets. Pattern-based: it reduces exposure but cannot catch everything."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

_SECRET_KEY = (
    r"(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credentials?|auth[_-]?key|session[_-]?key|signing[_-]?key)"
)
SECRET_KEY_RE = re.compile(rf"(?i)[\w.-]*{_SECRET_KEY}[\w.-]*")

_Repl = Callable[[re.Match[str]], str]


def _fixed(label: str) -> _Repl:
    return lambda _m: f"[REDACTED:{label}]"


def _kv(m: re.Match[str]) -> str:
    value = m.group("value")
    if value.startswith("[REDACTED") or value.startswith("${") or value.startswith("$"):
        return m.group(0)
    return f"{m.group('key')}{m.group('sep')}{m.group('q')}[REDACTED]{m.group('q')}"


_PATTERNS: list[tuple[str, re.Pattern[str], _Repl]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"),
        _fixed("private_key"),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _fixed("aws_access_key")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), _fixed("github_token")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), _fixed("slack_token")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), _fixed("google_api_key")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), _fixed("stripe_key")),
    ("sk_token", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), _fixed("api_key")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), _fixed("jwt")),
    (
        "auth_header",
        re.compile(r"(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*)(?:(bearer|basic|token|digest)\s+)?[^\s,;'\"]+"),
        lambda m: f"{m.group(1)}{m.group(2)}{(m.group(3) + ' ') if m.group(3) else ''}[REDACTED]",
    ),
    ("bearer", re.compile(r"(?i)\bbearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}"), lambda _m: "Bearer [REDACTED]"),
    (
        "url_credentials",
        re.compile(r"\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE),
        lambda m: f"{m.group(1)}{m.group(2)}:[REDACTED]@",
    ),
    (
        "key_value",
        re.compile(
            rf"(?i)(?P<key>[\w.-]*{_SECRET_KEY}[\w.-]*)(?P<sep>[\"']?\s*[:=]\s*)(?P<q>[\"']?)(?P<value>[^\s\"',;}}]+)(?P=q)"
        ),
        _kv,
    ),
]


@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str) -> Redaction:
    counts: Counter[str] = Counter()
    for name, pattern, repl in _PATTERNS:

        def _sub(m: re.Match[str], _name: str = name, _repl: _Repl = repl) -> str:
            out = _repl(m)
            if out != m.group(0):
                counts[_name] += 1
            return out

        text = pattern.sub(_sub, text)
    return Redaction(text=text, counts=dict(counts))


def redact_text(text: str) -> str:
    return redact(text).text


def is_secret_key(name: str) -> bool:
    return bool(SECRET_KEY_RE.fullmatch(name))
