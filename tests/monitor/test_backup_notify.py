from waterwall.monitor.backup_notify import Alert, BackupState, evaluate


def _eval(state, canary="pass", gateway_ok=True, thr=2, host="h"):
    return evaluate(state, canary, gateway_ok, thr, host)


def test_canary_pass_to_exposed_alerts_once():
    s = BackupState()
    s, a = _eval(s, canary="exposed")
    assert [x.severity for x in a] == ["alert"]
    assert "EXPOSED" in a[0].message and "h" in a[0].message
    s, a = _eval(s, canary="exposed")     # still exposed -> silent
    assert a == []


def test_canary_exposed_to_pass_recovers_once():
    s = BackupState(canary_exposed=True)
    s, a = _eval(s, canary="pass")
    assert [x.severity for x in a] == ["recovery"]
    s, a = _eval(s, canary="pass")
    assert a == []


def test_canary_error_does_not_change_exposed_state():
    s = BackupState(canary_exposed=True)
    s, a = _eval(s, canary="error")
    assert a == [] and s.canary_exposed is True   # can't-verify != recovered


def test_gateway_down_alerts_only_after_threshold():
    s = BackupState()
    s, a = _eval(s, gateway_ok=False, thr=2)
    assert a == [] and s.gateway_misses == 1      # 1st miss: debounced
    s, a = _eval(s, gateway_ok=False, thr=2)
    assert [x.severity for x in a] == ["alert"]   # 2nd miss: fire
    assert "gateway" in a[0].message.lower()
    s, a = _eval(s, gateway_ok=False, thr=2)
    assert a == []                                # still down: silent


def test_gateway_recovery_resets_and_alerts():
    s = BackupState(gateway_alerted=True, gateway_misses=5)
    s, a = _eval(s, gateway_ok=True)
    assert [x.severity for x in a] == ["recovery"]
    assert s.gateway_misses == 0 and s.gateway_alerted is False


def test_gateway_single_blip_then_recover_is_silent():
    s = BackupState()
    s, a = _eval(s, gateway_ok=False, thr=2)   # one miss, below threshold
    assert a == []
    s, a = _eval(s, gateway_ok=True)           # recovered before alerting
    assert a == [] and s.gateway_misses == 0


def test_exposed_and_gateway_down_can_both_fire():
    s = BackupState()
    s, a = _eval(s, canary="exposed", gateway_ok=False, thr=1)
    sev = sorted(x.severity for x in a)
    assert sev == ["alert", "alert"]


import logging
from waterwall.monitor.backup_notify import emit


def test_emit_logs_and_posts_to_webhook():
    posts = []
    log = logging.getLogger("test.backup.emit1")
    emit(Alert("alert", "boom"), webhook="https://hook",
         logger=log, post=lambda url, json: posts.append((url, json)) or True)
    assert posts == [("https://hook", {"content": "boom"})]


def test_emit_skips_webhook_when_unset_but_still_logs(caplog):
    posts = []
    log = logging.getLogger("test.backup.emit2")
    with caplog.at_level(logging.INFO, logger="test.backup.emit2"):
        emit(Alert("recovery", "ok again"), webhook="",
             logger=log, post=lambda url, json: posts.append(url) or True)
    assert posts == []                                  # no webhook -> no POST
    assert "ok again" in caplog.text                    # still logged/journaled


def test_emit_swallows_raising_post(caplog):
    def boom(url, json):
        raise RuntimeError("network gone")
    log = logging.getLogger("test.backup.emit3")
    # Must not raise — the reporter loop has to survive a broken webhook.
    emit(Alert("alert", "still here"), webhook="https://hook", logger=log, post=boom)


from waterwall.monitor.backup_notify import cycle, make_logger


def test_make_logger_adds_one_filehandler_idempotent(tmp_path):
    p = str(tmp_path / "backup.log")
    lg1 = make_logger(p)
    n1 = len([h for h in lg1.handlers if isinstance(h, logging.FileHandler)])
    lg2 = make_logger(p)
    n2 = len([h for h in lg2.handlers if isinstance(h, logging.FileHandler)])
    assert n1 == 1 and n2 == 1            # no duplicate handler on repeat calls


def test_cycle_emits_on_exposed_even_when_gateway_down():
    posts = []
    log = logging.getLogger("test.backup.cycle")
    state = BackupState()
    report = {"host": "h", "canary": "exposed", "health": "ok", "version": "v", "ts": 1.0}
    state = cycle(state, report, False, {"webhook": "https://hook", "gateway_miss_threshold": 1},
                  "h", log, post=lambda url, json: posts.append(json["content"]) or True)
    # both the EXPOSED alert and the gateway-down alert reach the webhook
    assert any("EXPOSED" in m for m in posts)
    assert any("gateway" in m.lower() for m in posts)


def test_make_logger_survives_unwritable_path(tmp_path):
    # argus MEDIUM: a bad backup log_path must NOT crash the reporter at startup —
    # the file sink degrades to journald-only (logging to stderr still works).
    logging.getLogger("waterwall.monitor.backup").handlers.clear()   # isolate the singleton
    bad = str(tmp_path / "missing-dir" / "backup.log")               # parent does not exist
    lg = make_logger(bad)                                            # must not raise
    assert not any(getattr(h, "_waterwall_backup", False) for h in lg.handlers)
