# tests/test_addon_audit.py
import json
import os
import time
from pathlib import Path

import pytest
from mitmproxy.test import tflow, taddons

from waterwall.proxy.addon import WaterwallAddon
from waterwall.audit.signer import EdSigner, EdVerifier, generate_keypair


@pytest.fixture
def addon_with_signer(tmp_path: Path):
    priv = tmp_path / "k.key"; pub = tmp_path / "k.pub"
    generate_keypair(priv, pub)
    addon = WaterwallAddon(
        chain_path=tmp_path / "proxy.jsonl",
        session_key=os.urandom(32),
        signer_path=priv,
        receipts_dir=tmp_path / "receipts",
        manifests_dir=tmp_path / "manifests",
    )
    # v2 §4.2: gate on _sse_handlers; seed Anthropic for v1 audit-path tests.
    from waterwall.proxy.sse import SseStreamRewriter
    addon._sse_handlers["api.anthropic.com"] = SseStreamRewriter(store=addon._store)
    return addon, tmp_path


def _build_request(content_text: str, session_id: str = "sess_a") -> "tflow.tflow":
    return tflow.tflow(req=tflow.treq(
        host="api.anthropic.com", port=443, scheme=b"https",
        method=b"POST", path=b"/v1/messages",
        headers=(
            (b"content-type", b"application/json"),
            (b"x-claude-code-session-id", session_id.encode()),
        ),
        content=json.dumps({"messages": [{"role": "user", "content": content_text}]}).encode(),
    ))


def test_receipt_emitted_per_redacting_request(addon_with_signer):
    addon, tmp = addon_with_signer
    flow = _build_request("AKIAIOSFODNN7EXAMPLE here")
    with taddons.context(addon) as _:
        addon.request(flow)
    receipts = list((tmp / "receipts").iterdir())
    assert len(receipts) == 1
    body = json.loads(receipts[0].read_text())
    assert body["redaction_count"] == 1
    assert body["types"] == ["AWS_ACCESS_KEY"]


def test_no_receipt_when_no_redactions(addon_with_signer):
    addon, tmp = addon_with_signer
    flow = _build_request("nothing to redact here")
    with taddons.context(addon) as _:
        addon.request(flow)
    assert not (tmp / "receipts").exists() or not list((tmp / "receipts").iterdir())


def test_checkpoint_emitted_after_100_lines(addon_with_signer):
    addon, tmp = addon_with_signer
    for _ in range(100):
        flow = _build_request("AKIAIOSFODNN7EXAMPLE")
        with taddons.context(addon) as _:
            addon.request(flow)
    chain_text = (tmp / "proxy.jsonl").read_text()
    checkpoint_lines = [l for l in chain_text.splitlines() if '"line_type":"checkpoint"' in l]
    assert len(checkpoint_lines) >= 1


def test_manifest_emitted_on_session_change(addon_with_signer):
    addon, tmp = addon_with_signer
    with taddons.context(addon) as _:
        addon.request(_build_request("AKIAIOSFODNN7EXAMPLE", session_id="sess_a"))
        addon.request(_build_request("AKIAIOSFODNN7EXAMPLE", session_id="sess_b"))
    manifests = list((tmp / "manifests").iterdir())
    assert len(manifests) == 1, "session A's manifest should land when sess_b appears"
    body = json.loads(manifests[0].read_text())
    assert body["session_id"] == "sess_a"
    assert body["redaction_total"] == 1
