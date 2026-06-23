# src/waterwall/tui/state_client.py
"""Polls /admin/state on the loopback admin server.

Spec §13.5: TUI is a read-only renderer; if /admin/state is unreachable,
the TUI shows the offline banner — never approximates state from a stale cache.
"""

from __future__ import annotations

import httpx


class StateUnavailable(Exception):
    """Raised when /admin/state is unreachable or returns non-200."""


class StateClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8889", timeout: float = 1.0) -> None:
        self._url = f"{base_url}/admin/state"
        self._timeout = timeout

    def fetch(self) -> dict:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(self._url)
        except httpx.HTTPError as e:
            raise StateUnavailable(f"proxy unreachable at {self._url}: {e}") from e
        if r.status_code != 200:
            raise StateUnavailable(f"proxy returned {r.status_code}")
        try:
            data = r.json()
        except Exception as e:
            raise StateUnavailable(f"invalid JSON from /admin/state: {e}") from e
        if not isinstance(data, dict):
            # Argus issue #16: a non-dict body (e.g. a JSON list) would
            # otherwise propagate and crash the TUI poll loop.
            raise StateUnavailable(
                f"non-object JSON from /admin/state: {type(data).__name__}"
            )
        return data
