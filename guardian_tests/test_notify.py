"""RoomNotifier must not amplify a flood or let identifiers forge log lines."""

import asyncio

from synapse_guardian.notify import (
    WebhookNotifier,
    MAX_NOTICES_PER_WINDOW,
    MAX_RECENT,
    RoomNotifier,
    format_block,
    sanitise,
)


class FakeApi:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def create_and_send_event_into_room(self, event: dict) -> None:
        self.sent.append(event)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def notifier(dedupe_s: float = 300.0) -> tuple[RoomNotifier, FakeApi, FakeClock]:
    api, clock = FakeApi(), FakeClock()
    return RoomNotifier(api, "!ctrl:h.org", "@bot:h.org", dedupe_s, clock), api, clock


def block(n: RoomNotifier, actor: str) -> None:
    """Record one blocked invite (sync wrapper: the suite runs without pytest-asyncio)."""
    asyncio.run(n.notify("invite", actor, "@kid:h.org", "!r:h.org", "default-deny", False))


def test_sanitise_strips_newlines_and_truncates() -> None:
    assert "\n" not in sanitise("@evil\nfake log line:x.org")
    assert "\r" not in sanitise("@evil\r\nx:x.org")
    assert len(sanitise("@" + "a" * 4000 + ":x.org")) < 300


def test_format_block_cannot_forge_a_log_line() -> None:
    line = format_block(
        "invite", "@a\nguardian: blocked nothing:x.org", "@kid:h.org", None, "r", False
    )
    assert "\n" not in line


def test_duplicate_blocks_are_deduped() -> None:
    n, api, _ = notifier()
    block(n, "@spammer:evil.org")
    block(n, "@spammer:evil.org")
    assert len(api.sent) == 1


def test_flood_of_distinct_senders_is_capped() -> None:
    n, api, _ = notifier()
    for i in range(MAX_NOTICES_PER_WINDOW * 5):
        block(n, f"@spammer{i}:evil.org")
    assert len(api.sent) == MAX_NOTICES_PER_WINDOW
    assert n._suppressed > 0


def test_cap_lifts_in_the_next_window() -> None:
    n, api, clock = notifier(dedupe_s=300.0)
    for i in range(MAX_NOTICES_PER_WINDOW * 2):
        block(n, f"@a{i}:evil.org")
    assert len(api.sent) == MAX_NOTICES_PER_WINDOW
    clock.now += 301
    block(n, "@later:evil.org")
    assert len(api.sent) == MAX_NOTICES_PER_WINDOW + 1


def test_recent_dict_stays_bounded() -> None:
    n, _, clock = notifier(dedupe_s=1e9)  # never expires, so only the cap bounds it
    for i in range(MAX_RECENT * 2):
        block(n, f"@a{i}:evil.org")
    assert len(n._recent) <= MAX_RECENT


# --- webhook transport ------------------------------------------------------


class FakeHttpClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict, dict]] = []
        self.fail: Exception | None = None

    async def post_json_get_json(self, uri: str, body: dict, headers: dict) -> dict:
        self.posts.append((uri, body, headers))
        if self.fail is not None:
            raise self.fail
        return {}


class FakeWebhookApi:
    def __init__(self) -> None:
        self.http_client = FakeHttpClient()


def webhook(dedupe_s: float = 300.0) -> tuple[WebhookNotifier, FakeWebhookApi, FakeClock]:
    api, clock = FakeWebhookApi(), FakeClock()
    return WebhookNotifier(api, "http://127.0.0.1:29316/notify", "s3cret", dedupe_s, clock), api, clock


def webhook_block(n: WebhookNotifier, actor: str) -> None:
    asyncio.run(n.notify("invite", actor, "@kid:h.org", "!r:h.org", "default-deny", False))


def test_webhook_posts_text_and_bearer_token() -> None:
    n, api, _ = webhook()
    webhook_block(n, "@a:h.org")
    uri, body, headers = api.http_client.posts[0]
    assert uri == "http://127.0.0.1:29316/notify"
    assert body["text"] == format_block(
        "invite", "@a:h.org", "@kid:h.org", "!r:h.org", "default-deny", False
    )
    assert headers == {"Authorization": ["Bearer s3cret"]}


def test_webhook_failure_is_swallowed_and_logged_once(caplog) -> None:
    n, api, _ = webhook()
    api.http_client.fail = ConnectionRefusedError("bot is down")
    with caplog.at_level("WARNING", logger="synapse_guardian.notify"):
        for i in range(5):
            webhook_block(n, f"@a{i}:h.org")
    # five attempts, but the operator is told once
    assert len(api.http_client.posts) == 5
    warnings = [r for r in caplog.records if "could not deliver notice" in r.message]
    assert len(warnings) == 1


def test_webhook_never_logs_the_secret(caplog) -> None:
    n, api, _ = webhook()
    api.http_client.fail = ConnectionRefusedError("bot is down")
    with caplog.at_level("WARNING", logger="synapse_guardian.notify"):
        webhook_block(n, "@a:h.org")
    assert "s3cret" not in caplog.text


def test_webhook_deduplicates_like_the_room_transport() -> None:
    n, api, _ = webhook()
    for _ in range(3):
        webhook_block(n, "@a:h.org")
    assert len(api.http_client.posts) == 1


def test_webhook_respects_the_flood_cap() -> None:
    n, api, _ = webhook()
    for i in range(MAX_NOTICES_PER_WINDOW + 10):
        webhook_block(n, f"@a{i}:h.org")
    assert len(api.http_client.posts) == MAX_NOTICES_PER_WINDOW


def test_webhook_recovers_after_the_bot_comes_back(caplog) -> None:
    n, api, _ = webhook()
    api.http_client.fail = ConnectionRefusedError("down")
    webhook_block(n, "@a:h.org")
    api.http_client.fail = None
    webhook_block(n, "@b:h.org")
    api.http_client.fail = ConnectionRefusedError("down again")
    with caplog.at_level("WARNING", logger="synapse_guardian.notify"):
        webhook_block(n, "@c:h.org")
    # the warning state reset on success, so the new outage is reported
    assert any("could not deliver notice" in r.message for r in caplog.records)
