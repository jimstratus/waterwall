# tests/test_permitted_hosts.py
import pytest
from pathlib import Path
from waterwall.ops.permitted_hosts import load_permitted_hosts, PermittedHost, PermittedHostsError


def test_loads_v2_default_set(tmp_path):
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
  - host: api.openai.com
    sse_handler: openai
  - host: openrouter.ai
    sse_handler: openai
"""
    p = tmp_path / "permitted_hosts.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    entries = load_permitted_hosts(p)
    assert len(entries) == 4
    assert entries[0] == PermittedHost(host="api.anthropic.com", sse_handler="anthropic")
    assert entries[1].host == "api.deepseek.com"
    assert entries[1].sse_handler == "openai"


def test_rejects_invalid_sse_handler(tmp_path):
    yaml_text = """
hosts:
  - host: api.example.com
    sse_handler: bogus
"""
    p = tmp_path / "permitted_hosts.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(PermittedHostsError, match="sse_handler must be one of"):
        load_permitted_hosts(p)


def test_rejects_empty_hosts(tmp_path):
    p = tmp_path / "permitted_hosts.yaml"
    p.write_text("hosts: []\n", encoding="utf-8")
    with pytest.raises(PermittedHostsError, match="at least one host"):
        load_permitted_hosts(p)


def test_rejects_duplicate_host(tmp_path):
    yaml_text = """
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.anthropic.com
    sse_handler: openai
"""
    p = tmp_path / "permitted_hosts.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(PermittedHostsError, match="duplicate host"):
        load_permitted_hosts(p)


def test_rejects_invalid_hostname(tmp_path):
    yaml_text = """
hosts:
  - host: "not a valid hostname!"
    sse_handler: openai
"""
    p = tmp_path / "permitted_hosts.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(PermittedHostsError, match="invalid hostname"):
        load_permitted_hosts(p)
