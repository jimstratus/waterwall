# src/waterwall/ops/permitted_hosts.py
"""Operator-extensible permitted-hosts list for the v2 multi-agent CA.

Spec §4.1: YAML schema is `hosts: [{host: str, sse_handler: anthropic|openai|none}]`.
Loaded by `waterwall regen-ca` to derive permittedSubtrees, AND by the addon at
init time to register SSE handlers per host.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

# RFC 1123 hostname (letters/digits/dots/hyphens, 1-253 chars total, no leading dot)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_VALID_SSE_HANDLERS = frozenset({"anthropic", "openai", "none"})


class PermittedHostsError(ValueError):
    """Raised when permitted_hosts.yaml fails schema validation."""


@dataclass(frozen=True)
class PermittedHost:
    host: str
    sse_handler: str


def load_permitted_hosts(path: Path) -> list[PermittedHost]:
    """Parse + validate permitted_hosts.yaml. Returns ordered list of entries.

    Raises PermittedHostsError on any schema violation.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "hosts" not in raw:
        raise PermittedHostsError("top-level must be a mapping with key 'hosts'")
    hosts_raw = raw["hosts"]
    if not isinstance(hosts_raw, list) or len(hosts_raw) == 0:
        raise PermittedHostsError("'hosts' must be a list with at least one host")

    seen: set[str] = set()
    out: list[PermittedHost] = []
    for i, entry in enumerate(hosts_raw):
        if not isinstance(entry, dict):
            raise PermittedHostsError(f"hosts[{i}] must be a mapping, got {type(entry).__name__}")
        host = entry.get("host")
        sse_handler = entry.get("sse_handler")
        if not isinstance(host, str):
            raise PermittedHostsError(f"hosts[{i}].host must be a string")
        if not _HOSTNAME_RE.match(host):
            raise PermittedHostsError(f"hosts[{i}]: invalid hostname {host!r}")
        if host in seen:
            raise PermittedHostsError(f"hosts[{i}]: duplicate host {host!r}")
        if sse_handler not in _VALID_SSE_HANDLERS:
            raise PermittedHostsError(
                f"hosts[{i}].sse_handler must be one of {sorted(_VALID_SSE_HANDLERS)}, got {sse_handler!r}"
            )
        seen.add(host)
        out.append(PermittedHost(host=host, sse_handler=sse_handler))
    return out
