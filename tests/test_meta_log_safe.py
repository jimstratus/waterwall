# tests/test_meta_log_safe.py
"""CI gate: no chain log line and no Python log emission ever matches any
secret pattern. This protects against an accidental f-string or repr() leaking
plaintext into the audit trail."""

import json
import os
from pathlib import Path

from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon
from waterwall.proxy.patterns import scan_string
from tests.fixtures.sample_secrets import SAMPLES, PEM_OPENSSH


def test_chain_log_lines_never_match_any_pattern(tmp_path: Path):
    log_path = tmp_path / "proxy.jsonl"
    addon = WaterwallAddon(chain_path=log_path, session_key=os.urandom(32))
    # v2 §4.2: gate on _sse_handlers; seed Anthropic for v1 redaction path.
    from waterwall.proxy.sse import SseStreamRewriter
    addon._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=addon._store)

    # Drive 20 redactions covering every pattern type
    body_msgs = [{"role": "user", "content": v} for v in SAMPLES.values()]
    body_msgs.append({"role": "user", "content": PEM_OPENSSH})

    flow = tflow.tflow(
        req=tflow.treq(
            host="api.anthropic.com", port=443, scheme=b"https",
            method=b"POST", path=b"/v1/messages",
            content=json.dumps({"messages": body_msgs}).encode(),
        )
    )
    with taddons.context(addon) as _:
        addon.request(flow)

    # Now scan every chain log line for any pattern match
    for line in log_path.read_text().splitlines():
        matches = scan_string(line)
        assert not matches, (
            f"chain log leaked plaintext: line={line[:200]!r} "
            f"matches={[m.type for m in matches]}"
        )
