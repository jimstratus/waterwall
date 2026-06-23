# tests/test_frameworks.py
from waterwall.audit.frameworks import tags_for, EVENT_FRAMEWORK_MAP


def test_redaction_carries_required_framework_set():
    tags = set(tags_for("redaction"))
    required = {
        "SOC2-CC7.2", "OWASP-LLM-02", "OWASP-LLM-06",
        "EU-AI-Act-Art-12", "MITRE-ATLAS-T0048",
    }
    assert required.issubset(tags), f"redaction must carry {required}, got {tags}"


def test_unknown_event_returns_empty_list():
    assert tags_for("nonsense") == []


def test_all_known_event_types_have_tags():
    for event_type in ("redaction", "detokenization", "killswitch", "policy_change", "manifest", "verify_install"):
        assert tags_for(event_type), f"{event_type} must have at least one framework tag"
