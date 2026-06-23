"""Argus issue #8: ChainWriter must resume seq/prev_hash from an existing log."""
import pytest

from waterwall.audit.chain import ChainWriter, ChainAppendError
from waterwall.audit.signer import EdSigner, generate_keypair
from waterwall.cli.verify_chain import verify_chain_file


def test_restart_continues_chain_and_verifies(tmp_path):
    key_path, pub_path = tmp_path / "k", tmp_path / "k.pub"
    generate_keypair(key_path, pub_path)
    log = tmp_path / "chain.jsonl"

    w1 = ChainWriter(log, signer=EdSigner.load(key_path))
    w1.append({"line_type": "redaction", "redactions": []})
    w1.append({"line_type": "redaction", "redactions": []})
    w1.close()

    # Simulated restart: a fresh writer on the same path.
    w2 = ChainWriter(log, signer=EdSigner.load(key_path))
    line = w2.append({"line_type": "redaction", "redactions": []})
    assert line["seq"] == 3          # not 1 — resumed, not genesis
    w2.emit_checkpoint()
    w2.close()

    result = verify_chain_file(log, pub_path)
    assert result.ok, result.failure_reason
    assert result.lines_verified == 4


def test_torn_tail_fails_loud(tmp_path):
    log = tmp_path / "chain.jsonl"
    w = ChainWriter(log)
    w.append({"line_type": "redaction", "redactions": []})
    w.close()
    with log.open("a", encoding="utf-8") as fp:
        fp.write('{"v": 1, "seq": 2, "torn')   # no newline, invalid JSON

    with pytest.raises(ChainAppendError, match="unparseable"):
        ChainWriter(log)


def test_fresh_empty_file_starts_at_genesis(tmp_path):
    log = tmp_path / "chain.jsonl"
    log.touch()                      # rotate-chain leaves exactly this
    w = ChainWriter(log)
    line = w.append({"line_type": "redaction", "redactions": []})
    assert line["seq"] == 1
    w.close()
