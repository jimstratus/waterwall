# src/waterwall/cli/rotate_chain.py
"""`waterwall rotate-chain` — archive the current chain log and start fresh.

Spec §5, §6. Required as part of the v1->v2 upgrade ceremony so the v2
chain starts at GENESIS without using the v1.1 prev_hash bug as cover.

Lockfile semantics (spec-reviewer R5): if proxy.jsonl.lock exists,
ChainWriter is live (proxy running) -> refuse with exit 2. Operator
must `systemctl stop waterwall-proxy` before running this verb.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path


def main_cli() -> int:
    parser = argparse.ArgumentParser(prog="waterwall rotate-chain")
    parser.add_argument(
        "--chain-path",
        type=Path,
        default=Path("/var/log/waterwall/proxy.jsonl"),
        help="Path to the chain log file to rotate (default: %(default)s)",
    )
    args = parser.parse_args()

    chain_path: Path = args.chain_path
    if not chain_path.exists():
        print(f"warn: {chain_path} does not exist; nothing to rotate", file=sys.stderr)
        return 0

    lock_path = chain_path.with_suffix(chain_path.suffix + ".lock")
    if lock_path.exists():
        # Argus issue #8: PID-bearing lockfile. A lock whose PID is dead
        # (SIGKILL/OOM left it behind) is stale — warn and proceed instead
        # of wedging rotation forever.
        if os.name == "nt":
            # On Windows os.kill(pid, 0) is NOT a probe — any signal other
            # than CTRL_C/CTRL_BREAK unconditionally TERMINATES the target
            # via TerminateProcess. Never probe there: treat every lock as
            # live (Windows is dev-only; production rotation runs on Linux).
            pid_alive = True
        else:
            pid_alive = False
            try:
                pid = int(lock_path.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)      # signal 0: POSIX existence probe
                pid_alive = True
            except PermissionError:
                # NOTE: PermissionError subclasses OSError, so this clause must
                # come FIRST or the broader tuple below would swallow it.
                pid_alive = True     # exists but owned by another user
            except (ValueError, ProcessLookupError, OSError):
                pid_alive = False
        if pid_alive:
            print(
                f"error: {lock_path} present and PID is alive — proxy is running. "
                f"Stop the service (systemctl stop waterwall-proxy) before rotating.",
                file=sys.stderr,
            )
            return 2
        print(
            f"warn: stale lockfile (dead PID) at {lock_path} — removing and proceeding",
            file=sys.stderr,
        )
        lock_path.unlink()

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Append the terminal rotation entry THROUGH chain discipline: a
    # short-lived ChainWriter resumes (seq, prev_hash) from the tail
    # (argus issue #8 — raw json.dumps with no prev_hash made every
    # archive permanently fail verify-chain).
    from waterwall.audit.chain import ChainAppendError, ChainWriter
    try:
        writer = ChainWriter(chain_path)
        last_seq = writer._seq
        archive_path = chain_path.with_name(f"{chain_path.name}.v{last_seq}-archived-{ts}")
        writer.append({
            "line_type": "rotation",
            "archive_path": str(archive_path),
            "reason": "v1->v2 upgrade ceremony (or operator-initiated rotation)",
        })
        writer.close()
    except ChainAppendError as e:
        print(f"error: cannot append rotation entry: {e}", file=sys.stderr)
        return 2

    chain_path.rename(archive_path)
    chain_path.touch()

    print(f"archived: {archive_path}")
    print(f"fresh chain at: {chain_path}")
    print("(start the proxy with: systemctl start waterwall-proxy)")
    return 0
