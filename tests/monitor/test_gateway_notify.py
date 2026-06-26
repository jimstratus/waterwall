from waterwall.monitor.gateway.notify import format_event, post_discord
from waterwall.monitor.gateway.transitions import Event


def test_format_event_content():
    assert format_event(Event("vector", "alert", "boom"))["content"] == "boom"


def test_post_discord_calls_post():
    seen = {}

    def fake(url, json):
        seen["url"] = url
        seen["json"] = json
        return True

    assert post_discord("https://discord/webhook", Event("h", "alert", "m"), post=fake) is True
    assert seen["url"] == "https://discord/webhook"
    assert seen["json"]["content"] == "m"


def test_post_discord_noop_without_url():
    assert post_discord("", Event("h", "alert", "m"), post=lambda *a, **k: True) is False
