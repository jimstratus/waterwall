"""Per-host backup notifier — gateway-independent alerts. Spec Phase 2.

A pure edge-detector (evaluate) plus emit sinks (Discord webhook + log/journal).
Fires on local canary EXPOSED (immediately) and gateway-unreachable (debounced).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

_log = logging.getLogger(__name__)


@dataclass
class Alert:
    severity: str   # "alert" | "recovery"
    message: str


@dataclass
class BackupState:
    canary_exposed: bool = False     # currently in the alerted-EXPOSED state
    gateway_alerted: bool = False    # currently in the alerted-unreachable state
    gateway_misses: int = 0          # consecutive failed gateway POSTs


def evaluate(state: BackupState, canary: str, gateway_ok: bool,
             miss_threshold: int, host: str) -> tuple[BackupState, list[Alert]]:
    """Edge-detect canary + gateway-reachability transitions. Mutates and returns
    `state` plus the alerts to emit this cycle (empty in steady state)."""
    alerts: list[Alert] = []

    # canary: EXPOSED fires immediately; recovery only on a clean PASS; error is a no-op.
    if canary == "exposed" and not state.canary_exposed:
        state.canary_exposed = True
        alerts.append(Alert("alert",
                            f"⚠️ {host} EXPOSED — secrets bypassing Waterwall (local canary)"))
    elif canary == "pass" and state.canary_exposed:
        state.canary_exposed = False
        alerts.append(Alert("recovery",
                            f"✅ {host} RECOVERED — tokenization confirmed (local canary)"))

    # gateway: debounce by consecutive misses; recover (and reset) on any success.
    if gateway_ok:
        if state.gateway_alerted:
            state.gateway_alerted = False
            alerts.append(Alert("recovery", f"✅ {host} gateway reachable again"))
        state.gateway_misses = 0
    else:
        state.gateway_misses += 1
        if state.gateway_misses >= miss_threshold and not state.gateway_alerted:
            state.gateway_alerted = True
            alerts.append(Alert("alert",
                                f"⛔ {host} cannot reach the monitor gateway "
                                f"(central alerting is blind)"))

    return state, alerts


def _default_post(url: str, json: dict) -> bool:
    try:
        with httpx.Client(timeout=5.0) as c:
            return c.post(url, json=json).status_code < 400
    except Exception as exc:
        _log.warning("backup discord post failed: %s", exc.__class__.__name__)
        return False


def emit(alert: Alert, *, webhook: str, logger, post=_default_post) -> None:
    """Fan an alert to the log/journal (always) and the independent Discord webhook
    (if set). Never raises — a broken sink must not kill the reporter loop."""
    level = logging.WARNING if alert.severity == "alert" else logging.INFO
    (logger or _log).log(level, alert.message)
    if webhook:
        try:
            post(webhook, {"content": alert.message})
        except Exception as exc:
            _log.warning("backup emit error: %s", exc.__class__.__name__)


def make_logger(log_path: str | None) -> logging.Logger:
    """Logger for backup alerts. journald captures the reporter service's stderr
    automatically; a FileHandler additionally writes the offline log at log_path."""
    lg = logging.getLogger("waterwall.monitor.backup")
    lg.setLevel(logging.INFO)
    if log_path and not any(getattr(h, "_waterwall_backup", False) for h in lg.handlers):
        try:
            h = logging.FileHandler(log_path)
        except OSError as exc:
            # A bad log_path must not crash reporter startup — degrade to journald-only
            # (the service's stderr is captured regardless). The file sink is optional.
            _log.warning("backup log_path unusable (%s): %s — journald only",
                         exc.__class__.__name__, log_path)
        else:
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            h._waterwall_backup = True
            lg.addHandler(h)
    return lg


def cycle(state: BackupState, report: dict, gateway_ok: bool, backup_cfg: dict,
          host: str, logger, *, post=_default_post) -> BackupState:
    """One backup cycle: edge-detect from this report + gateway result, emit alerts."""
    state, alerts = evaluate(state, report["canary"], gateway_ok,
                             backup_cfg.get("gateway_miss_threshold", 2), host)
    for a in alerts:
        emit(a, webhook=backup_cfg.get("webhook", ""), logger=logger, post=post)
    return state
