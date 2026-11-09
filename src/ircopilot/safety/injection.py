"""Prompt-injection heuristics and delimiting of untrusted content.

Heuristics catch common, low-effort injection attempts only. The main defences are structural:
untrusted text is delimited with a per-request nonce, the system rules are fixed in code, model
output is validated against retrieved sources, and nothing the model says is ever executed.
"""

from __future__ import annotations

import re
import secrets

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_instructions",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,40}?"
            r"\b(?:previous|prior|above|earlier|all|any|system|your|these|those)\b[^\n]{0,20}?"
            r"\b(?:instructions?|rules?|prompts?|directions?|guidelines?|polic(?:y|ies))\b"
        ),
    ),
    ("role_reassignment", re.compile(r"(?i)\byou are now\b|\bfrom now on,? you (?:are|will|must)\b")),
    ("new_instructions", re.compile(r"(?i)\b(?:new|updated|revised|real|actual) (?:system )?(?:instructions?|rules?|prompt)\s*:")),
    (
        "prompt_exfiltration",
        re.compile(r"(?i)\b(?:reveal|print|show|output|repeat|leak)\b[^\n]{0,30}\b(?:system prompt|hidden instructions|your (?:instructions|rules))"),
    ),
    ("fake_role_header", re.compile(r"(?im)^\s*(?:#+\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*:")),
    ("chat_template_token", re.compile(r"<\|[^|>\n]{1,40}\|>|\[/?INST\]|<</?SYS>>")),
    ("fake_authorization", re.compile(r"(?i)\b(?:this|the following) (?:message|text|document|log) (?:authorizes|permits|grants|allows) (?:you|the assistant)\b")),
    ("tool_invocation", re.compile(r"(?i)\b(?:call|invoke) the [\w-]+ tool\b|\bexecute (?:this|the following) (?:command|code|script)\b")),
]

_SPECIAL_TOKENS = re.compile(r"<\|[^|>\n]{1,40}\|>|\[/?INST\]|<</?SYS>>")
_DELIM_RE = re.compile(r"</?untrusted[-\w]*[^>]*>", re.IGNORECASE)
_LABEL_RE = re.compile(r"[^\w .:/#-]")


def detect_injection(text: str) -> list[str]:
    """Return the names of injection heuristics that match `text`."""
    return [name for name, pattern in _INJECTION_PATTERNS if pattern.search(text)]


def neutralize(text: str) -> str:
    """Remove chat-template control tokens and anything resembling our delimiters."""
    text = _SPECIAL_TOKENS.sub("[token removed]", text)
    return _DELIM_RE.sub("[tag removed]", text)


def new_nonce() -> str:
    return secrets.token_hex(8)


def wrap_untrusted(label: str, text: str, nonce: str) -> str:
    """Delimit untrusted text. The nonce is unguessable, so the content cannot close the block."""
    safe_label = _LABEL_RE.sub("", label)[:80]
    body = neutralize(text).replace(nonce, "")
    return f'<untrusted-{nonce} label="{safe_label}">\n{body}\n</untrusted-{nonce}>'
