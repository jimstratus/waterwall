from waterwall.tui.modals.export_evidence_modal import (
    DEFAULT_CHAIN,
    DEFAULT_MANIFESTS,
    DEFAULT_POLICY,
    DEFAULT_PUBKEY,
    DEFAULT_RECEIPTS,
    DEFAULT_SIGNING_KEY,
    build_export_command,
)


def test_build_export_command():
    cmd = build_export_command(since="2026-05-01", until="2026-05-05", out="/tmp/e.tar.gz")
    assert cmd == ["waterwall", "export-evidence",
                   "--chain", DEFAULT_CHAIN,
                   "--receipts-dir", DEFAULT_RECEIPTS,
                   "--manifests-dir", DEFAULT_MANIFESTS,
                   "--policy", DEFAULT_POLICY,
                   "--pubkey", DEFAULT_PUBKEY,
                   "--signing-key", DEFAULT_SIGNING_KEY,
                   "--since", "2026-05-01", "--until", "2026-05-05",
                   "-o", "/tmp/e.tar.gz"]


def test_build_export_command_omits_until_when_blank():
    cmd = build_export_command(since="2026-05-01", until="", out="/tmp/e.tar.gz")
    assert "--until" not in cmd


def test_build_export_command_includes_required_flags():
    """Argus issue #12: export-evidence requires --chain/--policy/--pubkey/--signing-key;
    the modal previously omitted all of them so every TUI export exited 2."""
    cmd = build_export_command(since="", until="", out="/tmp/e.tar.gz")
    assert "--chain" in cmd and "--policy" in cmd and "--pubkey" in cmd and "--signing-key" in cmd
