import asyncio
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from family_guard.config import ConfigError, FamilyGuardConfig
from family_guard.store import PolicyStore

SERVER = "example.org"
ROOM = "!ctl:example.org"
ADMIN = "@parent:example.org"
BOT = "@bot:example.org"


def run(coro: Any) -> Any:
    return asyncio.new_event_loop().run_until_complete(coro)


class FakeApi:
    def __init__(self) -> None:
        self.server_name = SERVER
        self.state: dict[tuple[str, str], Any] = {}
        self.admins: set[str] = {ADMIN}
        self.fail_reads = False
        self.reads = 0

    def is_mine(self, id: str) -> bool:
        return id.endswith(":" + SERVER)

    async def is_user_admin(self, user_id: str) -> bool:
        return user_id in self.admins

    async def get_room_state(self, room_id: str, event_filter: Any = None) -> dict:
        self.reads += 1
        if self.fail_reads:
            raise RuntimeError("db down")
        wanted = {t for t, _ in event_filter} if event_filter else None
        return {
            k: v for k, v in self.state.items() if wanted is None or k[0] in wanted
        }

    def put(self, kind: str, key: str, sender: str = ADMIN, content: dict | None = None) -> None:
        if content is None:
            content = {"added_by": sender}
        self.state[("family_guard." + kind, key)] = SimpleNamespace(
            type="family_guard." + kind, state_key=key, sender=sender, content=content
        )


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_store(
    api: FakeApi, clock: FakeClock | None = None, on_admin: Any = None, **cfg: Any
) -> PolicyStore:
    cfg.setdefault("control_room", ROOM)
    cfg.setdefault("allowed_servers", [SERVER])
    config = FamilyGuardConfig.parse(cfg)
    return PolicyStore(api, config, clock=clock or FakeClock(), on_admin_protected=on_admin)


def test_static_only() -> None:
    api = FakeApi()
    store = make_store(api, control_room=None, protected_users=["@kid:example.org"])
    rules = run(store.get_rules())
    assert rules.is_protected("@kid:example.org")
    assert rules.evaluate("@x:example.org").allowed
    assert api.reads == 0


def test_room_state_parsed_all_five_types() -> None:
    api = FakeApi()
    api.put("protected_user", "@kid:example.org")
    api.put("allowed_server", "friends.org")
    api.put("allowed_user", "@granny:other.org")
    api.put("blocked_user", "@troll:friends.org")
    api.put("blocked_server", "evil.friends.org")
    rules = run(make_store(api).get_rules())
    assert rules.is_protected("@kid:example.org")
    assert rules.evaluate("@a:friends.org").allowed
    assert rules.evaluate("@granny:other.org").allowed
    assert not rules.evaluate("@troll:friends.org").allowed
    assert not rules.evaluate("@a:evil.friends.org").allowed
    assert not rules.evaluate("@a:unknown.org").allowed


def test_empty_content_is_removed() -> None:
    api = FakeApi()
    api.put("allowed_server", "friends.org", content={})
    api.put("protected_user", "@kid:example.org", content={})
    rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:friends.org").allowed
    assert not rules.is_protected("@kid:example.org")


def test_union_static_and_room_static_cannot_be_removed() -> None:
    api = FakeApi()
    api.put("allowed_server", "example.org", content={})  # "remove" own server
    api.put("allowed_server", "friends.org")
    rules = run(make_store(api).get_rules())
    assert rules.evaluate("@a:example.org").allowed  # static baseline survives
    assert rules.evaluate("@a:friends.org").allowed


def test_non_local_sender_ignored() -> None:
    api = FakeApi()
    api.put("allowed_server", "evil.org", sender="@attacker:evil.org")
    rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:evil.org").allowed


def test_untrusted_local_sender_ignored() -> None:
    api = FakeApi()
    api.put("allowed_server", "friends.org", sender="@random:example.org")
    rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:friends.org").allowed


def test_admin_sender_honoured() -> None:
    api = FakeApi()
    api.put("allowed_server", "friends.org", sender=ADMIN)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_notify_user_and_trusted_senders_honoured() -> None:
    api = FakeApi()
    api.put("allowed_server", "friends.org", sender=BOT)
    api.put("allowed_server", "other.org", sender="@helper:example.org")
    store = make_store(
        api,
        notify_room=True,
        notify_user=BOT,
        trusted_senders=["@helper:example.org"],
    )
    rules = run(store.get_rules())
    assert rules.evaluate("@a:friends.org").allowed
    assert rules.evaluate("@a:other.org").allowed


def test_invalid_state_key_skipped_logged(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi()
    api.put("allowed_server", "friends org")
    api.put("allowed_server", "*")  # catch-all in allow list
    api.put("protected_user", "not-a-user")
    api.put("allowed_server", "friends.org")
    with caplog.at_level(logging.WARNING, logger="family_guard.store"):
        rules = run(make_store(api).get_rules())
    assert rules.evaluate("@a:friends.org").allowed
    assert not rules.evaluate("@a:anything.org").allowed
    assert rules.protected_users == frozenset()
    assert sum("ignoring invalid" in r.message for r in caplog.records) == 3


def test_unknown_event_types_ignored() -> None:
    api = FakeApi()
    api.state[("m.room.member", "@x:example.org")] = SimpleNamespace(
        type="m.room.member", state_key="@x:example.org", sender=ADMIN, content={"membership": "join"}
    )
    api.state[("family_guard.bogus", "friends.org")] = SimpleNamespace(
        type="family_guard.bogus", state_key="friends.org", sender=ADMIN, content={"x": 1}
    )
    rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:friends.org").allowed


def test_room_unreadable_at_start_uses_static() -> None:
    api = FakeApi()
    api.fail_reads = True
    store = make_store(api, protected_users=["@kid:example.org"])
    rules = run(store.get_rules())
    assert rules.is_protected("@kid:example.org")
    assert rules.evaluate("@a:example.org").allowed


def test_room_read_failure_keeps_previous_rules() -> None:
    api = FakeApi()
    clock = FakeClock()
    api.put("allowed_server", "friends.org")
    store = make_store(api, clock=clock)
    assert run(store.get_rules()).evaluate("@a:friends.org").allowed
    api.fail_reads = True
    store.invalidate()
    assert run(store.get_rules()).evaluate("@a:friends.org").allowed


def test_ttl_refresh() -> None:
    api = FakeApi()
    clock = FakeClock()
    store = make_store(api, clock=clock, refresh_interval_s=30)
    run(store.get_rules())
    assert api.reads == 1
    clock.now += 10
    run(store.get_rules())
    assert api.reads == 1  # not expired yet
    api.put("allowed_server", "friends.org")
    clock.now += 25
    rules = run(store.get_rules())
    assert api.reads == 2
    assert rules.evaluate("@a:friends.org").allowed


def test_invalidate_rebuilds() -> None:
    api = FakeApi()
    store = make_store(api)
    assert not run(store.get_rules()).evaluate("@a:friends.org").allowed
    api.put("allowed_server", "friends.org")
    assert not run(store.get_rules()).evaluate("@a:friends.org").allowed  # cached
    store.invalidate()
    assert run(store.get_rules()).evaluate("@a:friends.org").allowed


def test_is_our_event_type() -> None:
    assert PolicyStore.is_our_event_type("family_guard.allowed_server")
    assert not PolicyStore.is_our_event_type("m.room.message")


def test_admin_protected_user_warned_once(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi()
    api.admins.add("@kid:example.org")
    notified: list[str] = []

    async def on_admin(user_id: str) -> None:
        notified.append(user_id)

    store = make_store(api, on_admin=on_admin, protected_users=["@kid:example.org"])
    with caplog.at_level(logging.ERROR, logger="family_guard.store"):
        run(store.refresh())
        run(store.refresh())
    assert notified == ["@kid:example.org"]
    assert sum("is a server admin" in r.message for r in caplog.records) == 1


# --- config ---------------------------------------------------------------


def test_parse_config_rejects_unknown_policy() -> None:
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"uninvited_joins": "maybe"})


def test_parse_config_rejects_catch_all_allow() -> None:
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"allowed_servers": ["*"]})


def test_parse_config_rejects_bad_control_room() -> None:
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"control_room": "#alias:example.org"})


def test_parse_config_notify_requires_user_and_room() -> None:
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"notify_room": True, "control_room": ROOM})
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"notify_room": True, "notify_user": BOT})


def test_parse_config_rejects_unknown_keys() -> None:
    with pytest.raises(ConfigError):
        FamilyGuardConfig.parse({"protected": []})


def test_parse_config_defaults() -> None:
    cfg = FamilyGuardConfig.parse(None)
    assert cfg.uninvited_joins == "known_rooms"
    assert cfg.refresh_interval_s == 30
    assert cfg.notify_dedupe_s == 300
    assert not cfg.dry_run
    assert cfg.trusted_senders == frozenset()
