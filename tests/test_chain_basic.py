# tests/test_chain_basic.py
import hashlib
import json
from pathlib import Path
from waterwall.audit.chain import ChainWriter, GENESIS_PREV_HASH


def test_genesis_prev_hash_is_64_zeros():
    assert GENESIS_PREV_HASH == "0" * 64


def test_chain_writes_first_line_with_genesis_prev_hash(tmp_path: Path):
    log = tmp_path / "proxy.jsonl"
    cw = ChainWriter(log)
    cw.append({"line_type": "redaction", "redactions": []})
    cw.close()

    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["seq"] == 1
    assert parsed["prev_hash"] == GENESIS_PREV_HASH
    assert parsed["line_type"] == "redaction"


def test_chain_links_subsequent_lines(tmp_path: Path):
    log = tmp_path / "proxy.jsonl"
    cw = ChainWriter(log)
    cw.append({"line_type": "redaction"})
    cw.append({"line_type": "redaction"})
    cw.close()

    lines = [json.loads(l) for l in log.read_text().strip().splitlines()]
    expected_prev = hashlib.sha256(
        json.dumps(lines[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert lines[1]["prev_hash"] == expected_prev
    assert lines[1]["seq"] == 2


def test_canonical_json_handles_non_ascii(tmp_path: Path):
    """Migration regression: ensure_ascii=False canonicalization round-trips
    UTF-8 stably so prev_hash links survive non-ASCII content."""
    log = tmp_path / "proxy.jsonl"
    cw = ChainWriter(log)
    cw.append({"line_type": "redaction", "reason": "résumé"})
    cw.append({"line_type": "redaction", "reason": "another"})
    cw.close()

    lines = [json.loads(l) for l in log.read_text(encoding="utf-8").strip().splitlines()]
    assert lines[0]["reason"] == "résumé"  # round-trips through write+read

    expected_prev = hashlib.sha256(
        json.dumps(lines[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert lines[1]["prev_hash"] == expected_prev


def test_chainwriter_creates_lockfile_on_open(tmp_path: Path):
    """v2 §5 (R5): ChainWriter MUST touch a .lock sibling file so external
    tools (rotate-chain) can detect a live writer."""
    chain_path = tmp_path / "proxy.jsonl"
    lock_path = tmp_path / "proxy.jsonl.lock"
    writer = ChainWriter(chain_path)
    assert lock_path.exists(), "ChainWriter must create .lock alongside chain log"
    writer.close()
    assert not lock_path.exists(), "ChainWriter.close() must remove .lock"
