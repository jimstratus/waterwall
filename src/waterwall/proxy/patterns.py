# src/waterwall/proxy/patterns.py
"""Pattern set + scanner.

Spec §8 — single-line and multi-line patterns.
Patterns target the Python `re` engine (NOT POSIX-ERE); they use \\b, named
groups, and re.DOTALL.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

PEM_LEAF_MAX_BYTES = 64 * 1024  # spec §8.2 size cap


@dataclass(frozen=True)
class Match:
    type: str
    start: int
    end: int
    text: str


# Single-line patterns (spec §8.1). Order matters only for traceability — every
# pattern is tested independently.
SINGLE_LINE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ANTHROPIC_KEY",         r"\bsk-ant-api03-[A-Za-z0-9_-]{40,}\b"),
    ("ANTHROPIC_OAUTH_TOKEN", r"\bsk-ant-oat01-[A-Za-z0-9_-]{80,}\b"),
    ("OPENAI_KEY",            r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b"),
    ("AWS_ACCESS_KEY",        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("GITHUB_TOKEN",          r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("CLOUDFLARE_API_TOKEN",  r"\bcf(?:k|wt|ut|s)_[A-Za-z0-9]{32,48}\b"),
    ("SUPABASE_SECRET_KEY",   r"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
    ("GROQ_KEY",              r"\bgsk_[A-Za-z0-9]{48,52}\b"),
    ("VERCEL_TOKEN",          r"\bvrcl_[A-Za-z0-9]{24,}\b"),
    ("JWT_TOKEN",             r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("TWILIO_ACCOUNT_SID",    r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_API_KEY",        r"\bSK[a-f0-9]{32}\b"),
    ("SENDGRID_KEY",          r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b"),
    ("LINEAR_API_KEY",        r"\blin_api_[A-Za-z0-9]{30,}\b"),
    ("NOTION_TOKEN",          r"\bntn_[A-Za-z0-9_-]{30,}\b"),
    ("ATLASSIAN_TOKEN",       r"\bATATT3[A-Za-z0-9_=\-]{30,}\b"),
    ("HUGGINGFACE_TOKEN",     r"\bhf_[a-zA-Z]{34}\b"),
    ("PERPLEXITY_KEY",        r"\bpplx-[a-zA-Z0-9]{48}\b"),
    ("DROPBOX_KEY",           r"\bdpf_[A-Za-z0-9]{40,}\b"),
    ("TURSO_KEY",             r"\btfp_[A-Za-z0-9]{40,}\b"),
    # HCV-inventory uplift batch 1 (formats verified on prod-host 2026-05-09 via no-leak shape probe)
    ("GOOGLE_AI_KEY",         r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ("OPENROUTER_KEY",        r"\bsk-or-v1-[a-f0-9]{64}\b"),
    ("DISCORD_BOT_TOKEN",     r"\bM[A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}\b"),
    ("TELEGRAM_BOT_TOKEN",    r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("ELEVENLABS_KEY",        r"\bsk_[a-f0-9]{48}\b"),
    ("JINA_KEY",              r"\bjina_[A-Za-z0-9_-]{40,}\b"),
    ("BRAVE_SEARCH_KEY",      r"\bBSA[A-Za-z0-9_-]{28}\b"),
    ("CLICKUP_TOKEN",         r"\bpk_\d+_[A-Z0-9]{32}\b"),
    # Homelab-inventory batch 2 (issue #22). Mistral + CF Global API Key
    # assessed and skipped: no distinctive prefix, FP-prone.
    # Bech32 is one-case-only: uppercase as emitted by age-keygen, plus the
    # all-lowercase form (still a working key after case-normalizing tooling).
    # Data charset is the Bech32 alphabet — no 1/B/I/O (Copilot review, PR #23).
    ("AGE_SECRET_KEY",        r"\b(?:AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]{58}|age-secret-key-1[ac-hj-np-z02-9]{58})\b"),
    # hv[sbr] = service/batch/recovery prefixes. No trailing \b on the hv
    # branch: tokens are base64url and a terminal '-' would backtrack out.
    # Legacy s. needs the lookbehind so `a.s.<24>` property chains don't fire.
    ("VAULT_TOKEN",           r"(?:\bhv[sbr]\.[A-Za-z0-9_-]{24,}|(?<![\w.])s\.[A-Za-z0-9]{24}\b)"),
)

PEM_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?P<kind>OPENSSH PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|"
    r"PRIVATE KEY|DSA PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    r"(?P<body>.{0,32768}?)"
    r"-----END (?P=kind)-----",
    re.DOTALL,
)

_COMPILED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(p)) for label, p in SINGLE_LINE_PATTERNS
)

# Active scan set. Defaults to the built-ins; the addon swaps in
# built-ins + deployed extensions on hot-reload (argus issue #10 — the
# loader used to swap a dict nothing read). Swap is a single attribute
# assignment: atomic under the GIL for readers.
_ACTIVE: tuple[tuple[str, re.Pattern[str]], ...] = _COMPILED


def set_active_patterns(extensions: list[tuple[str, re.Pattern[str]]]) -> None:
    """Activate built-ins + extensions. Extensions APPEND — replacing the
    built-ins would silently drop REQUIRED_BASE_LABELS coverage."""
    global _ACTIVE
    _ACTIVE = _COMPILED + tuple(extensions)


def reset_active_patterns() -> None:
    """Restore the built-in-only scan set (test hygiene + loader teardown)."""
    global _ACTIVE
    _ACTIVE = _COMPILED


def scan_string(s: str) -> list[Match]:
    """Run all active single-line patterns + (size-permitting) PEM_BLOCK on s.

    Contract: returned spans are start-sorted and NON-OVERLAPPING (issue #21).
    Overlapping raw matches are merged into a union span carrying the longest
    constituent's label: identical spans (duplicate patterns) collapse to one,
    a match inside a PEM body folds into the PEM span, and partial overlaps
    (e.g. TELEGRAM_BOT_TOKEN over a JWT's head) widen to cover both — dropping
    either side would leak its non-overlapped tail in plaintext, and
    substituting both corrupts offsets.
    """
    out: list[Match] = []
    for label, regex in _ACTIVE:
        for m in regex.finditer(s):
            out.append(Match(type=label, start=m.start(), end=m.end(), text=m.group(0)))

    if len(s.encode("utf-8", errors="replace")) <= PEM_LEAF_MAX_BYTES:
        for m in PEM_BLOCK_PATTERN.finditer(s):
            out.append(Match(type="PEM_BLOCK", start=m.start(), end=m.end(), text=m.group(0)))

    out.sort(key=lambda x: (x.start, -x.end))
    merged: list[Match] = []
    best_len: list[int] = []  # longest RAW constituent per merged group — the
    # label comparison must not use the running union's length, which inflates
    # past any constituent as the group widens (Copilot review, PR #23)
    for m in out:
        m_len = m.end - m.start
        if merged and m.start < merged[-1].end:
            last = merged[-1]
            # Strict > keeps the earlier match's label on ties, so built-ins
            # win (they precede extensions in _ACTIVE; sort is stable).
            label = m.type if m_len > best_len[-1] else last.type
            best_len[-1] = max(best_len[-1], m_len)
            end = max(last.end, m.end)
            merged[-1] = Match(type=label, start=last.start, end=end, text=s[last.start:end])
            continue
        merged.append(m)
        best_len.append(m_len)
    return merged


def policy_hash() -> str:
    """SHA-256 of canonical-JSON of the active pattern set (spec §8.3)."""
    payload = [(label, p.pattern, p.flags) for label, p in _ACTIVE]
    payload.append(("PEM_BLOCK", PEM_BLOCK_PATTERN.pattern, PEM_BLOCK_PATTERN.flags))
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def pattern_count() -> int:
    return len(_ACTIVE) + 1  # +1 for PEM


# Required base labels — verify-install Check #3 (spec §11.4) asserts every one
# is present in the loaded pattern set. Adding new patterns is OK; removing or
# renaming any of these MUST also update REQUIRED_BASE_LABELS or verify-install fails.
REQUIRED_BASE_LABELS: frozenset[str] = frozenset({
    "ANTHROPIC_KEY",
    "ANTHROPIC_OAUTH_TOKEN",
    "OPENAI_KEY",
    "AWS_ACCESS_KEY",
    "GITHUB_TOKEN",
    "JWT_TOKEN",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_API_KEY",
    "SENDGRID_KEY",
    "ATLASSIAN_TOKEN",
    "HUGGINGFACE_TOKEN",
    "PERPLEXITY_KEY",
    "GROQ_KEY",
    "VERCEL_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    # HCV-inventory uplift batch 1 (verified against operator's HCV on 2026-05-09)
    "GOOGLE_AI_KEY",
    "OPENROUTER_KEY",
    "DISCORD_BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "ELEVENLABS_KEY",
    "JINA_KEY",
    "BRAVE_SEARCH_KEY",
    "CLICKUP_TOKEN",
    # Homelab-inventory batch 2 (issue #22)
    "AGE_SECRET_KEY",
    "VAULT_TOKEN",
    "PEM_BLOCK",
})


def loaded_labels() -> frozenset[str]:
    """All labels currently present in the active pattern set, including PEM_BLOCK."""
    return frozenset({label for label, _ in _ACTIVE}) | {"PEM_BLOCK"}


def pattern_breakdown() -> dict[str, int]:
    """For /admin/state.patterns.breakdown.

    Counts are derived from REQUIRED_BASE_LABELS membership, not tuple position.
    """
    labels = loaded_labels()
    base = sum(1 for label in labels if label in REQUIRED_BASE_LABELS) - 1  # exclude PEM
    ext = len(labels) - base - 1
    return {"base": max(0, base), "ext": max(0, ext), "pem": 1 if "PEM_BLOCK" in labels else 0}
