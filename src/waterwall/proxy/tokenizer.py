# src/waterwall/proxy/tokenizer.py
"""Placeholder tokenizer.

Spec §6 placeholder format.
Format: <pl:TYPE:HMAC8>  where HMAC8 = HMAC-SHA256(session_key, plaintext)[:16] in lowercase hex.
"""

from __future__ import annotations

import hmac
import hashlib
import re

PLACEHOLDER_REGEX = re.compile(
    r"<pl:(?P<type>[A-Z0-9_]+):(?P<hmac8>[0-9a-f]{16})>"
)
_TYPE_LABEL_REGEX = re.compile(r"[A-Z0-9_]+")


class Tokenizer:
    def __init__(self, session_key: bytes) -> None:
        if len(session_key) < 16:
            raise ValueError("session_key must be at least 16 bytes")
        self._key = session_key

    def tokenize(self, plaintext: str, type_label: str) -> str:
        if not _TYPE_LABEL_REGEX.fullmatch(type_label):
            raise ValueError(
                f"type_label must match [A-Z0-9_]+; got {type_label!r} which "
                "would produce a placeholder unmatchable by PLACEHOLDER_REGEX"
            )
        digest = hmac.new(
            self._key, plaintext.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"<pl:{type_label}:{digest[:16]}>"


def escape_literal_placeholders(body: str) -> str:
    """Escape any literal `<pl:` in user input so we don't double-tokenize.

    Spec §4.6.
    """
    return body.replace("<pl:", "<pl-esc:")


def unescape_literal_placeholders(body: str) -> str:
    """Inverse of escape_literal_placeholders.

    MUST be invoked AFTER placeholder substitution on the inbound path —
    otherwise an unescaped `<pl:` could be re-substituted (spec §5.2).

    Caveat: not idempotent on the sentinel itself. If the original user input
    contains the literal string `<pl-esc:`, escape() leaves it untouched but
    unescape() converts it to `<pl:`. The Waterwall-internal sentinel is
    unlikely in legitimate LLM input, so practical blast radius is low — but
    callers handling adversarial or fuzz-test input should be aware. v2 may
    add double-escape (`<pl-esc-esc:`) to make the round-trip safe.
    """
    return body.replace("<pl-esc:", "<pl:")
