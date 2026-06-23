# src/waterwall/ops/verify_install.py
"""verify-install — startup + runtime modes per spec §11.4."""

from __future__ import annotations

import os
import socket
import stat
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = field(default="")


def _check_mitmproxy_ca(mca: Path) -> CheckResult:
    """Check #7: mitmproxy-ca.pem exists + contains private key block AND
    certificate block. Per argus 2026-05-06 review (kimi-k2.6 conf 85 +
    opencode conf 80, corroborated): the previous stub that always returned
    True was a silent-failure bug. Shared by startup AND runtime modes
    (argus issue #13: runtime delegated to a hardcoded ca_mode string)."""
    try:
        assert mca.exists() and mca.is_file(), f"mitmproxy-ca.pem missing at {mca}"
        contents = mca.read_text(encoding="ascii", errors="replace")
        has_key = "BEGIN PRIVATE KEY" in contents or "BEGIN RSA PRIVATE KEY" in contents
        assert has_key, "no private key block in mitmproxy-ca.pem"
        assert "BEGIN CERTIFICATE" in contents, "no certificate block in mitmproxy-ca.pem"
        return CheckResult("mitmproxy_ca_file", True)
    except Exception as e:
        return CheckResult("mitmproxy_ca_file", False, str(e))


def run_startup_checks(
    ca_path: Path,
    signer_path: Path,
    patterns_path: Path | None,
    chain_log_dir: Path,
    sentinel_dir: Path,
    listen_port: int,
    admin_port: int,
    upstream_host: str,
    permitted_hosts_path: Path | None = None,
) -> list[CheckResult]:
    results: list[CheckResult] = []

    # 1. CA file — Name-Constrained to exactly the permitted_hosts.yaml set
    # (argus issue #11: the api.anthropic.com hardcode bricked the service
    # after `regen-ca` wrote a multi-host CA). Missing/invalid yaml fails the
    # check with the load error — fail-closed, no anthropic-only fallback.
    try:
        from waterwall.ops.ca_validator import validate_ca_for_waterwall
        from waterwall.ops.permitted_hosts import load_permitted_hosts
        if permitted_hosts_path is None:
            permitted_hosts_path = Path(os.environ.get(
                "WATERWALL_PERMITTED_HOSTS", "/etc/waterwall/permitted_hosts.yaml"
            ))
        expected = frozenset(h.host for h in load_permitted_hosts(permitted_hosts_path))
        validate_ca_for_waterwall(ca_path, expected_hosts=expected)
        results.append(CheckResult("ca_file", True))
    except Exception as e:
        results.append(CheckResult("ca_file", False, str(e)))

    # 2. Signing key — POSIX mode 0o400 (root-only) OR 0o440 (root + group-readable
    # for systemd-managed deploys where the service drops to a non-root user).
    # Both are no-world-access; 0o440 requires the file to be group-owned by a
    # restricted group (typically `waterwall`).
    try:
        if os.name == "posix":
            mode = stat.S_IMODE(signer_path.stat().st_mode)
            assert mode in (0o400, 0o440), f"mode {oct(mode)} not in (0o400, 0o440)"
        from waterwall.audit.signer import EdSigner
        EdSigner.load(signer_path)
        results.append(CheckResult("signing_key", True))
    except Exception as e:
        results.append(CheckResult("signing_key", False, str(e)))

    # 3. Patterns — built-ins satisfy pattern_count() >= 16 AND
    # REQUIRED_BASE_LABELS ⊆ loaded_labels(), AND the deployed extensions file
    # (if provided and existing) parses cleanly. The patterns_path parameter
    # was previously dead (argus issues #10/#13): the deployed file was never
    # checked, so a syntactically broken /etc/waterwall/patterns.py passed.
    # PatternLoader.__init__ parses synchronously and raises ValueError on a
    # bad file; it does NOT start its watcher thread (start() is separate),
    # so no thread leaks from verify-install.
    try:
        from waterwall.proxy.patterns import REQUIRED_BASE_LABELS, loaded_labels, pattern_count
        count = pattern_count()
        assert count >= 16, f"only {count} patterns loaded"
        labels = loaded_labels()
        missing = REQUIRED_BASE_LABELS - labels
        assert not missing, f"missing required labels: {missing}"
        if patterns_path is not None and patterns_path.exists():
            from waterwall.proxy.pattern_loader import PatternLoader
            from waterwall.proxy.patterns import SINGLE_LINE_PATTERNS
            loader = PatternLoader(patterns_path)  # raises ValueError on bad file
            # Extensions APPEND to built-ins; a re-declared built-in label or
            # regex yields overlapping scan spans for every match (issue #21 —
            # this exact misconfig shipped on prod-host and passed all 10 checks).
            builtin_labels = {label for label, _ in SINGLE_LINE_PATTERNS}
            builtin_regexes = {pattern for _, pattern in SINGLE_LINE_PATTERNS}
            dups = [
                label
                for label, compiled in loader.compiled()
                if label in builtin_labels or compiled.pattern in builtin_regexes
            ]
            assert not dups, (
                f"extensions file duplicates built-in pattern(s): {dups} — "
                f"remove them from {patterns_path}"
            )
        results.append(CheckResult("patterns_complete", True))
    except Exception as e:
        results.append(CheckResult("patterns_complete", False, f"patterns: {e}"))

    # 4. Chain log dir writable — write a test file then remove it
    try:
        test_path = chain_log_dir / ".write_test"
        test_path.write_text("ok")
        test_path.unlink()
        results.append(CheckResult("chain_dir_writable", True))
    except Exception as e:
        results.append(CheckResult("chain_dir_writable", False, str(e)))

    # 5. listener_bindable + 6. admin_bindable (startup) — bind the proxy + admin
    # ports to verify availability. Use `with` to guarantee close on exception.
    for name, port in [("listener_bindable", listen_port), ("admin_bindable", admin_port)]:
        if port == 0:
            results.append(CheckResult(name, True, "port=0 skipped"))
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
            results.append(CheckResult(name, True))
        except Exception as e:
            results.append(CheckResult(name, False, str(e)))

    # 7. mitmproxy CA file — exists + contains private key block AND certificate
    # block (see _check_mitmproxy_ca; shared with runtime mode).
    results.append(_check_mitmproxy_ca(ca_path.parent / "mitmproxy-ca.pem"))

    # 8. session_key (startup) — trivial pass; the addon generates a session key on init
    results.append(CheckResult("session_key", True))

    # 9. sentinel_dir — mkdir parents so it exists for kill-switch sentinel writes
    try:
        sentinel_dir.mkdir(parents=True, exist_ok=True)
        results.append(CheckResult("sentinel_dir", True))
    except Exception as e:
        results.append(CheckResult("sentinel_dir", False, str(e)))

    # 10. upstream_reachable — TCP connect to api.anthropic.com:443
    try:
        s = socket.create_connection((upstream_host, 443), timeout=5)
        s.close()
        results.append(CheckResult("upstream_reachable", True))
    except Exception as e:
        results.append(CheckResult("upstream_reachable", False, str(e)))

    return results


def run_runtime_checks(
    state_provider: Callable[[], dict],
    ca_path: Path | None = None,
    permitted_hosts_path: Path | None = None,
) -> list[CheckResult]:
    """Read state from aggregator snapshot, plus on-disk CA re-validation.

    Runtime mode is invoked while the proxy is already running.  Bind-tests
    (checks 5+6) would fail because mitmproxy already holds those ports, so
    those read the live state dict returned by StateAggregator.snapshot()
    (which now carries a real TCP probe). The CA checks (#1 + #7) re-validate
    the files on disk — runtime has filesystem access, and the previous
    "trust the ca_mode string" delegation was vacuous (argus issue #13).

    `ca_path` / `permitted_hosts_path` default to the WATERWALL_CA /
    WATERWALL_PERMITTED_HOSTS env vars, then /etc/waterwall — mirroring the
    explicit-path treatment run_startup_checks gives permitted_hosts_path.
    """
    state = state_provider()
    results: list[CheckResult] = []
    health = state.get("health", {})

    # 1 + 7. CA files — runtime re-validates on disk (the ca_mode string was
    # a hardcoded literal; argus issue #13).
    if ca_path is None:
        ca_path = Path(os.environ.get("WATERWALL_CA", "/etc/waterwall/ca.pem"))
    try:
        from waterwall.ops.ca_validator import validate_ca_for_waterwall
        from waterwall.ops.permitted_hosts import load_permitted_hosts
        if permitted_hosts_path is None:
            permitted_hosts_path = Path(os.environ.get(
                "WATERWALL_PERMITTED_HOSTS", "/etc/waterwall/permitted_hosts.yaml"
            ))
        expected = frozenset(h.host for h in load_permitted_hosts(permitted_hosts_path))
        validate_ca_for_waterwall(ca_path, expected_hosts=expected)
        results.append(CheckResult("ca_file", True))
    except Exception as e:
        results.append(CheckResult("ca_file", False, str(e)))

    # 2. Signing key readable — read from health sub-dict
    results.append(CheckResult(
        "signing_key", bool(health.get("signer_key_readable", False))
    ))

    # 3. Patterns complete — patterns_loaded >= 16 (base requirement)
    results.append(CheckResult(
        "patterns_complete", int(health.get("patterns_loaded", 0)) >= 16
    ))

    # 4. Chain dir writable — use chain_intact as proxy for log dir health
    results.append(CheckResult(
        "chain_dir_writable", bool(health.get("chain_intact", False))
    ))

    # 5. listener_bound — read from aggregator state (proxy already holds port)
    results.append(CheckResult(
        "listener_bound", bool(state.get("_runtime_listener_bound", False))
    ))

    # 6. admin_bound_loopback — same pattern
    results.append(CheckResult(
        "admin_bound_loopback", bool(state.get("_runtime_admin_bound_loopback", False))
    ))

    # 7. mitmproxy CA file — same on-disk content check as startup mode
    #    (existence + key block + cert block); argus issue #13 removed the
    #    "delegated to startup via ca_mode" vacuous pass.
    results.append(_check_mitmproxy_ca(ca_path.parent / "mitmproxy-ca.pem"))

    # 8. session_key_age_sane — key is present and not stale (< 24 h).
    #    0 <= age: `0 < age` rejected the first second after start (issue #13).
    age = state.get("session_key_age_seconds", 0)
    results.append(CheckResult(
        "session_key_age_sane", 0 <= age < 86400, f"age={age}s"
    ))

    # 9. sentinel_dir — trivially true at runtime (startup already mkdir'd it)
    results.append(CheckResult("sentinel_dir", True))

    # 10. upstream_reachable — read from health
    results.append(CheckResult(
        "upstream_reachable", bool(health.get("upstream_reachable", False))
    ))

    return results


def main_cli() -> int:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(prog="waterwall verify-install")
    ap.add_argument(
        "--runtime",
        action="store_true",
        help="Runtime mode (read from /admin/state). Default: startup mode.",
    )
    args = ap.parse_args()

    if args.runtime:
        import httpx
        admin_port = int(os.environ.get("WATERWALL_ADMIN_PORT", "8889"))
        try:
            state = httpx.get(f"http://127.0.0.1:{admin_port}/admin/state", timeout=5).json()
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}))
            return 1
        results = run_runtime_checks(state_provider=lambda: state)
    else:
        results = run_startup_checks(
            ca_path=Path(os.environ.get("WATERWALL_CA", "/etc/waterwall/ca.pem")),
            signer_path=Path(
                os.environ.get("WATERWALL_SIGNING_KEY", "/etc/waterwall/signing.key")
            ),
            patterns_path=Path("/etc/waterwall/patterns.py"),
            chain_log_dir=Path("/var/log/waterwall"),
            sentinel_dir=Path("/run/waterwall"),
            listen_port=int(os.environ.get("WATERWALL_PORT", "8888")),
            admin_port=int(os.environ.get("WATERWALL_ADMIN_PORT", "8889")),
            upstream_host="api.anthropic.com",
        )

    print(json.dumps(
        {
            "ok": all(r.ok for r in results),
            "checks": [{"name": r.name, "ok": r.ok, "detail": r.detail} for r in results],
        },
        indent=2,
    ))
    return 0 if all(r.ok for r in results) else 1
