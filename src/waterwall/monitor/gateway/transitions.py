"""Edge-triggered transition + dead-man's-switch detection. Spec §3.4.

Only *transitions* produce events (steady state is silent), so the gateway alerts
on outage/recovery rather than every poll.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    host: str
    severity: str   # "alert" | "recovery"
    message: str


def _bad_canary(v: str) -> bool:
    return v != "pass"


def _bad_health(v: str) -> bool:
    return v != "ok"


def detect_transitions(prev: dict | None, new: dict) -> list[Event]:
    """Compare prev vs new; emit at most one alert/recovery per dimension. An unseen
    host is treated as previously-good, so a first sighting only alerts if already bad."""
    host = new["host"]
    out: list[Event] = []
    pc = prev["canary"] if prev else "pass"
    ph = prev["health"] if prev else "ok"

    if _bad_canary(new["canary"]) and not _bad_canary(pc):
        out.append(Event(host, "alert",
                         f"⚠️ {host} canary {new['canary'].upper()} — secrets may be bypassing Waterwall"))
    elif not _bad_canary(new["canary"]) and _bad_canary(pc):
        out.append(Event(host, "recovery", f"✅ {host} canary RECOVERED — tokenization confirmed"))

    if _bad_health(new["health"]) and not _bad_health(ph):
        out.append(Event(host, "alert", f"⚠️ {host} health {new['health'].upper()}"))
    elif not _bad_health(new["health"]) and _bad_health(ph):
        out.append(Event(host, "recovery", f"✅ {host} health RECOVERED"))

    return out


def detect_stale(fleet: list[dict], now: float, threshold: float) -> list[str]:
    """Host names whose last report is older than `threshold`. Pure; the edge
    (alert-once / recover) is applied by sweep_stale so the dead-man's-switch is
    transition-triggered, not re-emitted every sweep (argus #2)."""
    return [r["host"] for r in fleet if (now - r["ts"]) > threshold]
