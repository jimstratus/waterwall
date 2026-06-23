# src/waterwall/tui/__main__.py
"""TUI entry point — `python -m waterwall.tui` or `waterwall dashboard`."""

from __future__ import annotations

import sys

from waterwall.tui.app import WaterwallTUI


def main_cli() -> int:
    app = WaterwallTUI()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main_cli())
