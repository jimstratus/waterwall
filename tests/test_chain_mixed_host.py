# tests/test_chain_mixed_host.py
"""Integration: mixed-host chain log + verify-chain.

Spec §7.3: a chain log containing entries with the new `host` field
interleaved with entries lacking it must verify cleanly. Both
verify_chain_file and export_evidence use .get() — schema-permissive.
"""
from waterwall.audit.chain import ChainWriter
from waterwall.audit.signer import EdSigner, generate_keypair
from waterwall.cli.verify_chain import verify_chain_file


def test_mixed_host_chain_verifies(tmp_path):
    """Chain with v1-style entries (no host) and v2-style entries (with host)
    must produce a valid hash-chain that verify-chain accepts."""
    chain_path = tmp_path / "proxy.jsonl"
    signer_key = tmp_path / "signing.key"
    pubkey = tmp_path / "signing.pub"
    generate_keypair(signer_key, pubkey)
    signer = EdSigner.load(signer_key)

    writer = ChainWriter(chain_path, signer=signer, signing_key_id="test")
    # v1-style line (no host)
    writer.append({
        "line_type": "redaction", "direction": "out",
        "redactions": [{"type": "AWS_ACCESS_KEY", "hmac8": "aaaaaaaa"}],
    })
    # v2-style line (with host)
    writer.append({
        "line_type": "redaction", "direction": "out",
        "host": "api.deepseek.com",
        "redactions": [{"type": "OPENAI_KEY", "hmac8": "bbbbbbbb"}],
    })
    # v2-style detokenization
    writer.append({
        "line_type": "detokenization", "direction": "in",
        "host": "api.deepseek.com",
        "detok_count": 1,
        "unknown_placeholders": 0,
        "types": ["OPENAI_KEY"],
    })
    writer.close()

    result = verify_chain_file(chain_path, pubkey_path=pubkey)
    assert result.ok, f"verify-chain rejected mixed-host log: {result.failure_reason}"
    assert result.lines_verified == 3
