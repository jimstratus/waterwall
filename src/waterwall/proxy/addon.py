# src/waterwall/proxy/addon.py
"""Mitmproxy addon entry point.

Spec §3 architecture, §5.1 outbound flow.
Phase 2 mutates outbound request body. Phase 3 adds inbound detok.
Phase 4 adds streaming SSE handling. Phase 5 wires audit signer + receipts.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitmproxy import http
from mitmproxy.http import Response

from waterwall.audit.chain import ChainWriter, ChainAppendError
from waterwall.audit.frameworks import tags_for
from waterwall.audit.idle_watcher import IdleWatcher
from waterwall.audit.manifest import SessionTracker, emit_manifest
from waterwall.audit.receipt import ReceiptEvent, emit_receipt
from waterwall.audit.signer import EdSigner
from waterwall.ops.admin import build_admin_app
from waterwall.ops.state import StateAggregator
from waterwall.proxy.config_loader import ConfigLoader
from waterwall.proxy.killswitch import KillSwitch
from waterwall.proxy.pattern_loader import PatternLoader
from waterwall.proxy.patterns import policy_hash, scan_string
from waterwall.proxy.sse import SseStreamRewriter
from waterwall.proxy.store import PlaceholderStore
from waterwall.proxy.tokenizer import Tokenizer
from waterwall.proxy.walker import redact_in_place, detokenize_in_place

_log = logging.getLogger("waterwall.addon")


def _cors_origins_from_env() -> list[str]:
    """Parse WATERWALL_CORS_ORIGINS into a list for build_admin_app().

    Comma-separated. Empty / unset → no CORS (same-origin only), which
    is the safe default for the loopback-only admin server. Operators
    who serve the webgui from a different host set
    `WATERWALL_CORS_ORIGINS=http://kiosk.lan` (or a comma list, or
    `*` to allow any origin).
    """
    raw = os.environ.get("WATERWALL_CORS_ORIGINS", "").strip()
    if not raw:
        return []
    return [o.strip() for o in raw.split(",") if o.strip()]


def _mount_prefix_from_env() -> str:
    """Read WATERWALL_MOUNT_PREFIX for build_admin_app().

    Default "" (no prefix) — preserves the loopback URL contract
    used by existing internal consumers (TUI's state_client.py,
    verify_install.py), which hardcode `/admin/state` and
    `/healthz`. Setting `WATERWALL_MOUNT_PREFIX=/waterwall` puts
    the admin under `/waterwall/*` for path-scoped reverse-proxy
    deployments (see deploy/caddy/).
    """
    return os.environ.get("WATERWALL_MOUNT_PREFIX", "").strip()



ANTHROPIC_HOST = "api.anthropic.com"

CHECKPOINT_LINES = 100
CHECKPOINT_INTERVAL_SECONDS = 5 * 60
SESSION_IDLE_SECONDS = 30 * 60


class WaterwallAddon:
    def __init__(
        self,
        chain_path: Path,
        session_key: bytes | None = None,
        signer_path: Path | None = None,
        receipts_dir: Path | None = None,
        manifests_dir: Path | None = None,
        signing_key_id: str = "waterwall-2026-05",
    ) -> None:
        self._tokenizer = Tokenizer(session_key or os.urandom(32))
        self._store = PlaceholderStore(capacity=10_000, ttl_seconds=4 * 3600.0)

        # Signer is OPTIONAL — Plan 1 tests pass signer_path=None
        self._signer = EdSigner.load(signer_path) if signer_path else None
        self._signing_key_id = signing_key_id

        self._chain = ChainWriter(
            chain_path,
            signer=self._signer,
            signing_key_id=signing_key_id,
        )
        self._policy_hash = policy_hash()
        self._receipts_dir = receipts_dir or (chain_path.parent / "receipts")
        self._manifests_dir = manifests_dir or (chain_path.parent / "manifests")

        self._lines_since_checkpoint = 0
        self._last_checkpoint_at = time.monotonic()
        self._last_checkpoint_root_hash: str = ""

        self._session_trackers: dict[str, SessionTracker] = {}
        self._idle_watcher = IdleWatcher(
            idle_timeout_seconds=SESSION_IDLE_SECONDS,
            on_idle=self._end_session,
        )

        # Killswitch with 4 OR-composed sources (config/SIGUSR1/sentinel/HTTP).
        self._killswitch = KillSwitch()
        self._killswitch.install_sigusr1_handler()

        self._sessions_lock = threading.Lock()

        self._tokenizer_created_at = time.monotonic()

        self._idle_thread: threading.Thread | None = None
        self._idle_thread_stop = threading.Event()

        # Phase 6 integration surface — populated in running() when env vars
        # opt-in to admin server / hot-reload. Unit tests leave them None.
        self._state_aggregator: StateAggregator | None = None
        self._pattern_loader: PatternLoader | None = None
        self._config_loader: ConfigLoader | None = None
        self._admin_thread: threading.Thread | None = None
        self._admin_server: Any = None  # uvicorn.Server, set in running()
        self._patterns_last_reload_ts: str | None = None
        self._checkpoint_count: int = 0
        self._last_checkpoint_ts: str | None = None

        # v2 spec §4.2 — host→SSE-handler dispatch map. Populated at running()
        # from /etc/waterwall/permitted_hosts.yaml; left empty in unit tests.
        self._sse_handlers: dict[str, Any] = {}

        # Argus issue #7: set when permitted_hosts.yaml is missing or unloadable
        # at running(). While set, request() fails closed (502 everything).
        self._config_error: str | None = None

    def request(self, flow: http.HTTPFlow) -> None:
        # Killswitch check FIRST — an armed switch must 502 every intercepted
        # flow, including hosts with no registered handler (argus issue #7).
        # Fail-closed if any source active (spec §11.1).
        if self._killswitch.is_active():
            sources = self._killswitch.active_sources()
            flow.response = Response.make(
                502,
                json.dumps({"error": "waterwall-killswitch-engaged", "sources_active": sources}).encode(),
                {"content-type": "application/json"},
            )
            try:
                self._chain.append({
                    "line_type": "killswitch",
                    "request_id": flow.request.headers.get("x-request-id"),
                    "sources_active": sources,
                    "frameworks": tags_for("killswitch"),
                })
            except ChainAppendError:
                pass  # killswitch is more important than chain logging
            return
        # Config error (permitted_hosts.yaml missing/unloadable at running())
        # — fail closed rather than forwarding plaintext (argus issue #7).
        if self._config_error is not None:
            flow.response = Response.make(
                502,
                json.dumps({"error": "waterwall-config-error", "reason": self._config_error}).encode(),
                {"content-type": "application/json"},
            )
            return
        if flow.request.host not in self._sse_handlers:
            return
        if not flow.request.content:
            return
        try:
            body = json.loads(flow.request.content)
        except json.JSONDecodeError:
            return  # Phase 4 logs; phase 2 is silent

        events = redact_in_place(
            body,
            tokenizer=self._tokenizer,
            store=self._store,
            scanner=scan_string,
        )

        # ALWAYS rewrite content — redact_in_place runs escape_literal_placeholders on
        # every leaf, so a literal `<pl:` in user input gets converted to `<pl-esc:` in
        # the body dict even when no scanner matches fire. If we only wrote back when
        # `events` was non-empty, the unescaped bytes would forward upstream and Phase 3
        # detok would misread the literal as a real placeholder (spec §4.6 contract).
        flow.request.content = json.dumps(body).encode()

        session_id = flow.request.headers.get("x-claude-code-session-id")
        tracker = self._track_session(session_id)

        if events:
            for e in events:
                if tracker:
                    tracker.record_redaction(e.type_label)

            try:
                line = self._chain.append({
                    "line_type": "redaction",
                    "direction": "out",
                    "host": flow.request.host,  # v2 §4.5 — per-host attribution
                    "request_id": flow.request.headers.get("x-request-id"),
                    "session_id": session_id,
                    "redactions": [
                        {"type": e.type_label, "hmac8": e.hmac8} for e in events
                    ],
                    "path_hashes": [],  # Phase 5 fills these
                    "policy_hash": self._policy_hash,
                    "frameworks": tags_for("redaction"),  # invariant from Phase 2 onward
                })
            except ChainAppendError as e:
                flow.response = Response.make(
                    502,
                    json.dumps({
                        "error": "waterwall-chain-append-failed",
                        "reason": str(e),
                    }).encode(),
                    {"content-type": "application/json"},
                )
                return  # do NOT forward upstream — fail-closed per spec §14
            self._lines_since_checkpoint += 1

            if self._state_aggregator is not None:
                self._state_aggregator.record_activity({
                    "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "direction": "out",
                    "request_id": flow.request.headers.get("x-request-id", "—"),
                    "redactions": len(events),
                    "types": list(dict.fromkeys(e.type_label for e in events)),
                })

            if self._signer:
                emit_receipt(
                    out_dir=self._receipts_dir,
                    request_id=flow.request.headers.get("x-request-id", "unknown"),
                    session_id=session_id,
                    events=[ReceiptEvent(type=e.type_label, hmac8=e.hmac8) for e in events],
                    policy_hash=self._policy_hash,
                    chain_seq=line["seq"],
                    signer=self._signer,
                    signing_key_id=self._signing_key_id,
                )

        self._maybe_emit_checkpoint()

    def _dispatch_sse(self, flow) -> None:
        """Look up the SSE handler for this flow's host and invoke its rewrite.

        Spec §4.2: host→handler map is populated at addon init from
        permitted_hosts.yaml. A missing key here means an install-time
        invariant violation (CA signed cert for a host the addon has no
        handler for). The KeyError re-raises — mitmproxy logs it and the
        response path fails closed (502 to agent). See spec §11 risks row 2
        for the init-time invariant check that prevents this in steady state.
        """
        handler = self._sse_handlers[flow.request.host]
        handler.rewrite(flow)

    def _init_sse_handlers_from_yaml(self, yaml_path) -> None:
        """Register SSE handlers per permitted_hosts.yaml. Spec §4.2."""
        from pathlib import Path
        from waterwall.ops.permitted_hosts import load_permitted_hosts
        from waterwall.proxy.sse import SseStreamRewriter as AnthropicSseHandler
        from waterwall.proxy.sse_openai import OpenAiSseHandler

        class _PassthroughSseHandler:
            def rewrite(self, flow) -> None:  # noqa: D401
                """No-op: emit body unchanged."""
                return

        entries = load_permitted_hosts(Path(yaml_path))
        for entry in entries:
            if entry.sse_handler == "anthropic":
                self._sse_handlers[entry.host] = AnthropicSseHandler(
                    store=self._store,
                    chain=self._chain,
                    state_aggregator=self._state_aggregator,
                    policy_hash=self._policy_hash,
                )
            elif entry.sse_handler == "openai":
                self._sse_handlers[entry.host] = OpenAiSseHandler(
                    store=self._store, chain=self._chain,
                )
            elif entry.sse_handler == "none":
                self._sse_handlers[entry.host] = _PassthroughSseHandler()

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.host not in self._sse_handlers:
            return
        # Any response from a permitted host — even a 4xx — proves upstream is
        # reachable. Surface it on the StateAggregator so verify-install
        # runtime mode and /healthz reflect reality.
        if self._state_aggregator is not None:
            self._state_aggregator.record_upstream_ok()
        if not flow.response or not flow.response.content:
            return

        ct = flow.response.headers.get("content-type", "")
        if ct.startswith("text/event-stream"):
            self._dispatch_sse(flow)
            return

        try:
            body = json.loads(flow.response.content)
        except json.JSONDecodeError:
            return

        result = detokenize_in_place(body, store=self._store)
        flow.response.content = json.dumps(body).encode()

        # Behavioral fingerprint (argus issue #17): surface unknown
        # placeholders on the session tracker so the signed manifest reports
        # measured values, not declared-but-never-updated zeros. JSON path
        # only — the SSE handler doesn't report per-session unknowns in v1.
        if result.unknown_placeholders:
            session_id = flow.request.headers.get("x-claude-code-session-id")
            if session_id:
                with self._sessions_lock:
                    tracker = self._session_trackers.get(session_id)
                if tracker:
                    tracker.record_unknown_placeholders(result.unknown_placeholders)

        try:
            self._chain.append({
                "line_type": "detokenization",
                "direction": "in",
                "host": flow.request.host,  # v2 §4.5 — per-host attribution
                "request_id": flow.request.headers.get("x-request-id"),
                "session_id": flow.request.headers.get("x-claude-code-session-id"),
                "detok_count": result.detok_count,
                "unknown_placeholders": result.unknown_placeholders,
                "policy_hash": self._policy_hash,
            })
        except ChainAppendError as e:
            # Fail closed in BOTH directions (argus issue #17, spec §14):
            # without an audit line the restored secrets must not be delivered.
            flow.response = Response.make(
                502,
                json.dumps({
                    "error": "waterwall-chain-append-failed",
                    "reason": str(e),
                }).encode(),
                {"content-type": "application/json"},
            )
            return
        if self._state_aggregator is not None:
            self._state_aggregator.record_activity({
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "direction": "in",
                "request_id": flow.request.headers.get("x-request-id", "—"),
                "detok_count": result.detok_count,
            })

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # v2 §4.2: per-flow rewriter state lives inside each handler; nothing
        # to set up here. Method retained as a no-op so mitmproxy's hook chain
        # stays predictable and future per-stream wiring has a stable seam.
        if flow.request.host not in self._sse_handlers:
            return
        if not flow.response:
            return

    def running(self) -> None:
        """Called by mitmproxy when the addon is active. Spawns:
          - idle watcher thread (always)
          - pattern hot-reload watcher (if WATERWALL_PATTERNS path exists)
          - config hot-reload watcher (if WATERWALL_CONFIG path exists)
          - StateAggregator (always, used by admin server + TUI)
          - admin HTTP server (if WATERWALL_ADMIN_PORT > 0)

        Idempotent: mitmproxy's script-reloader fires running() again whenever
        addon.py is touched on disk. Each spawn is gated on the existing
        thread/loader state to avoid double-binds and double-watches.
        """

        if self._idle_thread is None or not self._idle_thread.is_alive():
            def _idle_loop() -> None:
                while not self._idle_thread_stop.wait(60):
                    self._idle_watcher.tick()

            self._idle_thread = threading.Thread(
                target=_idle_loop,
                daemon=True,
                name="waterwall-idle",
            )
            self._idle_thread.start()

        if self._state_aggregator is None:
            self._state_aggregator = StateAggregator(addon=self)

        if self._pattern_loader is None:
            patterns_path = Path(os.environ.get("WATERWALL_PATTERNS", "/etc/waterwall/patterns.py"))
            if patterns_path.exists():
                try:
                    self._pattern_loader = PatternLoader(
                        patterns_path,
                        on_reload=self._on_pattern_reload,
                    )
                    self._pattern_loader.start()
                    # Apply the deployed extensions at startup — the loader's
                    # synchronous initial load does NOT fire on_reload, and the
                    # active scan set must include extensions from request #1.
                    self._on_pattern_reload()
                except Exception as exc:
                    _log.warning("pattern hot-reload disabled: %s", exc)

        if self._config_loader is None:
            config_path = Path(os.environ.get("WATERWALL_CONFIG", "/etc/waterwall/config.yaml"))
            if config_path.exists():
                try:
                    self._config_loader = ConfigLoader(config_path, killswitch=self._killswitch)
                    self._config_loader.start()
                except Exception as exc:
                    _log.warning("config hot-reload disabled: %s", exc)

        # v2 §4.2: register SSE handlers from permitted_hosts.yaml.
        # Missing or unloadable yaml is a FAIL-CLOSED condition: with an empty
        # handler map every request would forward in plaintext (argus issue #7).
        permitted_path = Path(os.environ.get(
            "WATERWALL_PERMITTED_HOSTS", "/etc/waterwall/permitted_hosts.yaml"
        ))
        if not self._sse_handlers:
            if not permitted_path.exists():
                self._config_error = f"permitted hosts file not found: {permitted_path}"
                _log.error("FAIL-CLOSED: %s — all requests will be 502'd", self._config_error)
            else:
                try:
                    self._init_sse_handlers_from_yaml(permitted_path)
                    self._config_error = None
                    _log.info(
                        "registered %d SSE handlers from %s",
                        len(self._sse_handlers), permitted_path,
                    )
                except Exception as exc:
                    self._config_error = f"SSE handler registration failed: {exc}"
                    _log.error("FAIL-CLOSED: %s — all requests will be 502'd", self._config_error)

        admin_port = int(os.environ.get("WATERWALL_ADMIN_PORT", "0"))
        if admin_port > 0 and self._state_aggregator is not None:
            self._start_admin_server(admin_port)

    def _on_pattern_reload(self) -> None:
        """Swap the ACTIVE scan set to built-ins + deployed extensions, refresh
        the policy hash, and chain a policy_change event. Spec §11.3 step 3.

        Argus issue #10: the loader used to swap a set nothing read — scanning
        stayed pinned to the module-frozen built-ins forever.
        """
        from waterwall.proxy import patterns as patterns_mod

        if self._pattern_loader is None:
            return
        old_hash = self._policy_hash
        patterns_mod.set_active_patterns(self._pattern_loader.compiled())
        self._policy_hash = patterns_mod.policy_hash()
        self._patterns_last_reload_ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        try:
            self._chain.append({
                "line_type": "policy_change",
                "old_policy_hash": old_hash,
                "new_policy_hash": self._policy_hash,
                "pattern_count": patterns_mod.pattern_count(),
            })
        except ChainAppendError:
            _log.warning("policy_change chain append failed")

    def _reload_patterns_or_raise(self) -> None:
        """Admin /admin/reload entry point. Raises on refusal so the endpoint
        500s instead of lying with 200 (argus issue #10)."""
        if self._pattern_loader is None:
            raise RuntimeError("pattern hot-reload not enabled (no patterns file at startup)")
        if not self._pattern_loader._try_reload():
            raise RuntimeError("reload refused — patterns file failed to parse; previous set still active")

    def _start_admin_server(self, port: int) -> None:
        # Idempotent: if mitmproxy's script-reloader fires (e.g., addon.py
        # touched on disk), running() re-runs but the admin thread is still
        # bound to its port. A second bind would EADDRINUSE — skip cleanly.
        if self._admin_thread is not None and self._admin_thread.is_alive():
            return

        import uvicorn  # local — avoid import cost when admin server disabled

        app = build_admin_app(
            state_provider=self._state_aggregator.snapshot,
            healthz_provider=self._state_aggregator.healthz_subset,
            killswitch_arm=lambda reason: self._killswitch.arm_http(reason),
            killswitch_disarm=lambda: self._killswitch.disarm_http(),
            reload_patterns=self._reload_patterns_or_raise,
            cors_origins=_cors_origins_from_env(),
            mount_prefix=_mount_prefix_from_env(),
        )
        config = uvicorn.Config(
            app, host="127.0.0.1", port=port,
            log_level="warning", access_log=False,
        )
        self._admin_server = uvicorn.Server(config)

        def _run_admin() -> None:
            try:
                self._admin_server.run()
            except Exception as exc:
                _log.warning("admin server stopped: %s", exc)

        self._admin_thread = threading.Thread(
            target=_run_admin, daemon=True, name="waterwall-admin"
        )
        self._admin_thread.start()

    def done(self) -> None:
        """Called by mitmproxy on shutdown / SIGTERM. Flush any open
        sessions' manifests and close the chain log."""
        self._idle_thread_stop.set()
        with self._sessions_lock:
            sids = list(self._session_trackers.keys())
        for sid in sids:
            self._end_session(sid)
        if self._pattern_loader is not None:
            try:
                self._pattern_loader.stop()
            except Exception:
                pass
        if self._config_loader is not None:
            try:
                self._config_loader.stop()
            except Exception:
                pass
        if self._admin_server is not None:
            self._admin_server.should_exit = True
        try:
            self._chain.close()
        except Exception:
            pass

    def _maybe_emit_checkpoint(self) -> None:
        if not self._signer:
            return
        if (
            self._lines_since_checkpoint >= CHECKPOINT_LINES
            or time.monotonic() - self._last_checkpoint_at >= CHECKPOINT_INTERVAL_SECONDS
        ):
            cp = self._chain.emit_checkpoint()
            self._last_checkpoint_root_hash = cp["chain_root_hash"]
            self._lines_since_checkpoint = 0
            self._last_checkpoint_at = time.monotonic()
            self._checkpoint_count += 1
            self._last_checkpoint_ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    def _track_session(self, flow_session_id: str | None) -> "SessionTracker | None":
        """Returns the active SessionTracker; emits a manifest for any session
        that just became inactive (different session_id arrived)."""
        if not flow_session_id:
            return None
        for sid in list(self._session_trackers.keys()):
            if sid != flow_session_id:
                self._end_session(sid)
        with self._sessions_lock:
            if flow_session_id not in self._session_trackers:
                self._session_trackers[flow_session_id] = SessionTracker(
                    session_id=flow_session_id,
                    first_seq=self._chain._seq + 1,
                )
            self._idle_watcher.touch(flow_session_id)
            tracker = self._session_trackers[flow_session_id]
            # Behavioral fingerprint (argus issue #17): every tracked request
            # counts, redacting or not — avg_redactions_per_request needs the
            # true denominator.
            tracker.record_request()
            return tracker

    def _end_session(self, session_id: str) -> None:
        with self._sessions_lock:
            tracker = self._session_trackers.pop(session_id, None)
        if not tracker:
            return
        if not self._signer:
            return  # Plan-1 backward-compat path: no manifest emission.

        try:
            cp = self._chain.emit_checkpoint()
            self._last_checkpoint_root_hash = cp["chain_root_hash"]
            self._lines_since_checkpoint = 0
            self._last_checkpoint_at = time.monotonic()
            self._checkpoint_count += 1
            self._last_checkpoint_ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

            emit_manifest(
                out_dir=self._manifests_dir,
                tracker=tracker,
                chain_seq_range=(tracker.first_seq or 0, self._chain._seq),
                chain_root_hash=self._last_checkpoint_root_hash,
                policy_hash=self._policy_hash,
                signer=self._signer,
                signing_key_id=self._signing_key_id,
            )
        except (ChainAppendError, OSError) as e:
            import logging
            logging.getLogger("waterwall").warning(
                "session-end manifest emission failed for %s: %s", session_id, e,
            )

# mitmproxy hook: instantiated only when actually loaded by mitmdump,
# never at import time (so pytest on Windows / non-root contexts doesn't
# trip filesystem writes during test discovery).
def load(loader):  # noqa: ARG001 — mitmproxy API contract
    # Idempotent: if mitmproxy hot-reloads the script (or otherwise calls load()
    # more than once), return the already-registered instance rather than
    # double-registering. Two registrations cause the second pass to re-escape
    # already-redacted content, corrupting Phase 3 detok.
    if addons:
        return addons[0]
    chain_path = Path(os.environ.get("WATERWALL_CHAIN", "/var/log/waterwall/proxy.jsonl"))
    signer_env = os.environ.get("WATERWALL_SIGNING_KEY")
    signer_path = Path(signer_env) if signer_env else None
    instance = WaterwallAddon(chain_path=chain_path, signer_path=signer_path)
    addons.append(instance)
    return instance


# mitmproxy discovers addons by traversing `module.addons` after `load()` returns.
# `load()` MUST append its instance to this list — returning the instance alone is
# not sufficient to register the hook chain. Phase 2 lab on test-host caught the bug
# where return-only failed silently (request() never fired). See BACKLOG.md.
addons = []  # populated by load()
