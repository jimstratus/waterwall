# src/waterwall/cli/regen_ca.py
"""`waterwall regen-ca` — generate a multi-permittedSubtree CA from
operator-extensible YAML.

Spec §4.1, §5.
"""
from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path

from waterwall.ops.ca_generator import generate_ca
from waterwall.ops.permitted_hosts import load_permitted_hosts, PermittedHostsError


def main_cli() -> int:
    parser = argparse.ArgumentParser(prog="waterwall regen-ca")
    parser.add_argument(
        "--hosts-file",
        type=Path,
        default=Path("/etc/waterwall/permitted_hosts.yaml"),
        help="YAML file listing permitted hosts and their SSE handlers (default: %(default)s)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("/etc/waterwall"),
        help="Output directory for ca.pem / ca.key / mitmproxy-ca.pem (default: %(default)s)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365 * 10,
        help="CA validity period in days (default: %(default)s)",
    )
    parser.add_argument(
        "--common-name",
        type=str,
        default="Waterwall Operator CA",
        help="CA Common Name (default: %(default)s)",
    )
    args = parser.parse_args()

    try:
        hosts = load_permitted_hosts(args.hosts_file)
    except FileNotFoundError:
        print(f"error: hosts file not found: {args.hosts_file}", file=sys.stderr)
        return 2
    except PermittedHostsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Generate into a temp dir FIRST; only on success back up + swap
    # (argus issue #11: rename-before-generate left no CA on failure).
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tmp_out = args.out_dir / f".regen-{ts}"
    try:
        generate_ca(hosts=hosts, out_dir=tmp_out, days=args.days, common_name=args.common_name)
    except Exception as e:
        print(f"error: CA generation failed, existing CA untouched: {e}", file=sys.stderr)
        shutil.rmtree(tmp_out, ignore_errors=True)
        return 1

    for name in ("ca.pem", "ca.key", "mitmproxy-ca.pem"):
        existing = args.out_dir / name
        if existing.exists():
            backup = args.out_dir / f"{name}.bak-{ts}"
            existing.rename(backup)
            print(f"backed up: {existing} -> {backup}")
        (tmp_out / name).rename(existing)
    tmp_out.rmdir()
    print(f"wrote CA with {len(hosts)} permittedSubtree(s):")
    for h in hosts:
        print(f"  - {h.host} (sse_handler={h.sse_handler})")
    print(f"output: {args.out_dir}/{{ca.pem, ca.key, mitmproxy-ca.pem}}")
    return 0
