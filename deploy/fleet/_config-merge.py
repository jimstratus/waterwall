#!/usr/bin/env python3
"""Deep-merge a YAML snippet (stdin) into /etc/waterwall/config.yaml.

Used by the fleet deploy helpers to idempotently set `monitor.*` keys without
clobbering operator hand-edits. Reads a snippet from stdin, deep-merges it into
the existing config (dicts recurse, scalars/lists overwrite), backs up the
original to <config>.bak-<ts>, and writes the result back.

NB: PyYAML does not preserve comments. The deployed /etc/waterwall/config.yaml is
operator-managed and minimal (install.sh writes only `kill_switch: false`); if
you keep local comments there, this helper will drop them on a merge. Hand-edit
commented reference configs elsewhere (e.g. docs/monitor.md).

Usage:
    printf 'monitor:\n  gate:\n    enabled: true\n' | \
        sudo /opt/waterwall/deploy/fleet/_config-merge.py [--config <path>]
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import shutil
import sys
from pathlib import Path

import yaml


def deep_merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/waterwall/config.yaml", type=Path)
    args = ap.parse_args()

    snippet = yaml.safe_load(sys.stdin.read())
    if snippet is None:
        print("error: empty snippet on stdin", file=sys.stderr)
        return 2
    if not isinstance(snippet, dict):
        print(f"error: snippet must be a YAML mapping, got {type(snippet).__name__}", file=sys.stderr)
        return 2

    cfg_path: Path = args.config
    if cfg_path.exists():
        base = yaml.safe_load(cfg_path.read_text()) or {}
        if not isinstance(base, dict):
            print(f"error: {cfg_path} top level must be a mapping", file=sys.stderr)
            return 2
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(cfg_path, cfg_path.with_suffix(cfg_path.suffix + f".bak-{ts}"))
    else:
        base = {}

    # Snapshot BEFORE deep-copying: deep_merge mutates nested dicts in place, so a
    # shallow ref would alias the post-merge values and falsely report "no changes"
    # when nested keys actually changed (argus #4). The merged FILE is always
    # correct; this only fixes the operator-facing diff report.
    before = {k: copy.deepcopy(base.get(k)) for k in snippet}
    merged = deep_merge(base, snippet)

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(merged, sort_keys=False, default_flow_style=False))

    changed = [k for k in snippet if before.get(k) != merged.get(k)]
    if changed:
        print(f"merged {len(changed)} top-level key(s) into {cfg_path}: {', '.join(changed)}")
    else:
        print(f"no changes; {cfg_path} already matched the snippet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())