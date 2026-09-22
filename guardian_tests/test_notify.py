"""RoomNotifier must not amplify a flood or let identifiers forge log lines."""

import asyncio

from synapse_guardian.notify import (
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
