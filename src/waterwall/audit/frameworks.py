# src/waterwall/audit/frameworks.py
"""Compliance framework mapping. Spec §9.5.

Tags are JSON metadata only — no runtime logic, no auditor pretensions, just
navigability when an auditor asks 'where do you log access to credentials?'
"""

from __future__ import annotations

EVENT_FRAMEWORK_MAP: dict[str, list[str]] = {
    "redaction": [
        "SOC2-CC7.2", "SOC2-CC9.2",
        "OWASP-LLM-02", "OWASP-LLM-06",
        "EU-AI-Act-Art-12", "EU-AI-Act-Art-13",
        "MITRE-ATLAS-T0048",
        "NIST-800-53-AC-4",
    ],
    "detokenization": ["SOC2-CC7.2", "OWASP-LLM-02"],
    "killswitch": ["SOC2-CC7.3", "EU-AI-Act-Art-15"],
    "policy_change": ["SOC2-CC8.1"],
    "manifest": ["SOC2-CC4.1", "EU-AI-Act-Art-12"],
    "verify_install": ["SOC2-CC4.2"],
}


def tags_for(line_type: str) -> list[str]:
    return list(EVENT_FRAMEWORK_MAP.get(line_type, []))
