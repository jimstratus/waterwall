# src/waterwall/cli/__main__.py
"""waterwall CLI entry point.

Subcommands:
  verify-install     — startup or runtime mode
  verify-receipt     — verify a single receipt
  verify-chain       — verify a Flight Recorder JSONL log
  verify-evidence    — verify an evidence bundle
  export-evidence    — bundle chain + receipts + manifests
  pre-launch-hook    — Claude Code SessionStart hook
  dashboard          — launch the TUI (Plan 3)
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="waterwall")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify-install")
    sub.add_parser("verify-receipt")
    sub.add_parser("verify-chain")
    sub.add_parser("verify-evidence")
    sub.add_parser("export-evidence")
    sub.add_parser("pre-launch-hook")
    sub.add_parser("dashboard")
    sub.add_parser("regen-ca")
    sub.add_parser("rotate-chain")
    sub.add_parser("report")
    sub.add_parser("monitor-gateway")

    # Each subcommand parses its own args via re-parse on remainder
    args, remainder = parser.parse_known_args()
    sys.argv = [f"waterwall {args.cmd}"] + remainder

    if args.cmd == "verify-install":
        from waterwall.ops.verify_install import main_cli; return main_cli()
    if args.cmd == "verify-receipt":
        from waterwall.cli.verify_receipt import main_cli; return main_cli()
    if args.cmd == "verify-chain":
        from waterwall.cli.verify_chain import main_cli; return main_cli()
    if args.cmd == "verify-evidence":
        from waterwall.cli.verify_evidence import main_cli; return main_cli()
    if args.cmd == "export-evidence":
        from waterwall.cli.export_evidence import main_cli; return main_cli()
    if args.cmd == "pre-launch-hook":
        from waterwall.cli.pre_launch_hook import run; return run()
    if args.cmd == "dashboard":
        from waterwall.tui.__main__ import main_cli; return main_cli()
    if args.cmd == "regen-ca":
        from waterwall.cli.regen_ca import main_cli; return main_cli()
    if args.cmd == "rotate-chain":
        from waterwall.cli.rotate_chain import main_cli; return main_cli()
    if args.cmd == "report":
        from waterwall.monitor.reporter import main_cli; return main_cli()
    if args.cmd == "monitor-gateway":
        from waterwall.monitor.gateway.__main__ import main_cli; return main_cli()
    return 2


if __name__ == "__main__":
    sys.exit(main())
