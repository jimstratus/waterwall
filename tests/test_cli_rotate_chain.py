import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_rotate_chain_archives_existing(tmp_path):
    chain_path = tmp_path / "proxy.jsonl"
    chain_path.write_text(
        json.dumps({"v": 1, "seq": 1, "line_type": "redaction"}) + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "rotate-chain",
         "--chain-path", str(chain_path)],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    archives = list(tmp_path.glob("proxy.jsonl.v*-archived-*"))
    assert len(archives) == 1
    # New chain file is empty
    assert chain_path.exists()
    assert chain_path.stat().st_size == 0


def test_rotate_chain_aborts_when_proxy_running(tmp_path):
    """R5: lockfile presence = proxy running. rotate-chain MUST refuse."""
    chain_path = tmp_path / "proxy.jsonl"
    chain_path.write_text("dummy\n", encoding="utf-8")
    lock_path = tmp_path / "proxy.jsonl.lock"
    lock_path.touch()
    result = subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "rotate-chain",
         "--chain-path", str(chain_path)],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "is running" in (result.stdout + result.stderr).lower() \
        or "lock" in (result.stdout + result.stderr).lower()
    # Original chain untouched
    assert chain_path.read_text() == "dummy\n"


def test_rotate_chain_writes_rotation_marker(tmp_path):
    """rotate-chain emits a final line_type=rotation entry to the OLD log
    before archiving, so future readers can follow archive->fresh continuity."""
    chain_path = tmp_path / "proxy.jsonl"
    chain_path.write_text(
        json.dumps({"v": 1, "seq": 5, "line_type": "redaction"}) + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [sys.executable, "-m", "waterwall.cli", "rotate-chain",
         "--chain-path", str(chain_path)],
        check=True, timeout=15, capture_output=True,
    )
    archives = list(tmp_path.glob("proxy.jsonl.v*-archived-*"))
    archived = archives[0].read_text(encoding="utf-8")
    last_line = archived.strip().splitlines()[-1]
    last_obj = json.loads(last_line)
    assert last_obj["line_type"] == "rotation"
    assert "archive_path" in last_obj


def test_archived_chain_verifies_after_rotation(tmp_path, monkeypatch, capsys):
    """Argus issue #8: the archive (with its terminal rotation entry) must
    still pass verify-chain — that is the entire point of archiving."""
    from waterwall.audit.chain import ChainWriter
    from waterwall.audit.signer import EdSigner, generate_keypair
    from waterwall.cli.rotate_chain import main_cli
    from waterwall.cli.verify_chain import verify_chain_file

    key_path, pub_path = tmp_path / "k", tmp_path / "k.pub"
    generate_keypair(key_path, pub_path)
    log = tmp_path / "proxy.jsonl"
    w = ChainWriter(log, signer=EdSigner.load(key_path))
    w.append({"line_type": "redaction", "redactions": []})
    w.emit_checkpoint()
    w.close()

    monkeypatch.setattr(sys, "argv", ["waterwall rotate-chain", "--chain-path", str(log)])
    assert main_cli() == 0

    archives = list(tmp_path.glob("proxy.jsonl.v*-archived-*"))
    assert len(archives) == 1
    result = verify_chain_file(archives[0], pub_path)
    assert result.ok, result.failure_reason
    # terminal line is the rotation entry, properly chained
    last = archives[0].read_text(encoding="utf-8").strip().splitlines()[-1]
    obj = json.loads(last)
    assert obj["line_type"] == "rotation"
    assert "prev_hash" in obj


@pytest.mark.skipif(os.name == "nt", reason="Windows never probes PIDs "
                    "(os.kill terminates there) — every lock is treated as live")
def test_stale_lockfile_detected_and_rotation_proceeds(tmp_path, monkeypatch, capsys):
    """Argus issue #8: a lockfile left by a SIGKILLed proxy (dead PID) must
    not block rotation forever. POSIX-only: Windows treats all locks as live."""
    from waterwall.audit.chain import ChainWriter
    from waterwall.cli.rotate_chain import main_cli

    log = tmp_path / "proxy.jsonl"
    w = ChainWriter(log)
    w.append({"line_type": "redaction", "redactions": []})
    w.close()
    # Simulate crash: lockfile with a PID that cannot be alive.
    lock = log.with_suffix(log.suffix + ".lock")
    lock.write_text("999999999", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["waterwall rotate-chain", "--chain-path", str(log)])
    assert main_cli() == 0
    err = capsys.readouterr().err
    assert "stale" in err.lower()


def test_live_lockfile_still_refuses(tmp_path, monkeypatch):
    from waterwall.audit.chain import ChainWriter
    from waterwall.cli.rotate_chain import main_cli

    log = tmp_path / "proxy.jsonl"
    w = ChainWriter(log)
    w.append({"line_type": "redaction", "redactions": []})
    # do NOT close — lock contains THIS live test process's PID
    monkeypatch.setattr(sys, "argv", ["waterwall rotate-chain", "--chain-path", str(log)])
    assert main_cli() == 2
    w.close()
