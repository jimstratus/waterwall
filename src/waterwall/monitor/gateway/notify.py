"""Discord webhook notifier — transitions only. Spec §3.4."""
from __future__ import annotations

import logging

import httpx

from waterwall.monitor.gateway.transitions import Event

_log = logging.getLogger(__name__)


def format_event(event: Event) -> dict:
    return {"content": event.message}


def _default_post(url: str, json: dict) -> bool:
    try:
        with httpx.Client(timeout=5.0) as c:
            return c.post(url, json=json).status_code < 400
    except Exception as exc:
        _log.warning("discord post failed: %s", exc.__class__.__name__)
        return False


def post_discord(webhook_url: str, event: Event, *, post=_default_post) -> bool:
    """POST the event to a Discord webhook. No-op (returns False) if no URL configured."""
    if not webhook_url:
        return False
    return post(webhook_url, format_event(event))
