import asyncio
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from synapse_guardian.config import ConfigError, GuardianConfig
from synapse_guardian.store import PolicyStore

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

    def set_power_levels(self, **content: Any) -> None:
        content.setdefault("state_default", 50)
        self.state[("m.room.power_levels", "")] = SimpleNamespace(
            type="m.room.power_levels", state_key="", sender=ADMIN, content=content
        )

    def set_create(self, sender: str = ADMIN, **content: Any) -> None:
        content.setdefault("room_version", "12")
        self.state[("m.room.create", "")] = SimpleNamespace(
            type="m.room.create", state_key="", sender=sender, content=content
        )

    def put(self, kind: str, key: str, sender: str = ADMIN, content: dict | None = None) -> None:
        if content is None:
            content = {"entity": key, "added_by": sender}
        state_key = key[1:] if key.startswith("@") else key
        self.state[("guardian." + kind, state_key)] = SimpleNamespace(
            type="guardian." + kind, state_key=state_key, sender=sender, content=content
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
    config = GuardianConfig.parse(cfg)
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


def test_sender_with_enough_power_is_honoured() -> None:
    """The room decides: PL 50 is what the room asks for, so PL 50 is enough."""
    api = FakeApi()
    api.set_power_levels(users={BOT: 50}, users_default=0, state_default=50)
    api.put("allowed_server", "friends.org", sender=BOT)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_sender_without_enough_power_is_ignored(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi()
    api.set_power_levels(users={BOT: 50}, users_default=0, state_default=50)
    api.put("allowed_server", "friends.org", sender="@random:example.org")
    with caplog.at_level(logging.WARNING, logger="synapse_guardian.store"):
        rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:friends.org").allowed
    assert any(
        "power 0, needs 50 for guardian.allowed_server" in r.getMessage()
        for r in caplog.records
    )


def test_v12_room_creator_is_honoured() -> None:
    """The regression: a v12 creator has infinite power and is absent from `users`."""
    creator = "@creator:example.org"
    api = FakeApi()
    api.set_create(sender=creator, room_version="12")
    api.set_power_levels(users={BOT: 50}, users_default=0, state_default=100)
    api.put("allowed_server", "friends.org", sender=creator)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_additional_creator_is_honoured() -> None:
    extra = "@second:example.org"
    api = FakeApi()
    api.set_create(sender=ADMIN, room_version="12", additional_creators=[extra])
    api.set_power_levels(users={}, users_default=0, state_default=100)
    api.put("allowed_server", "friends.org", sender=extra)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_pre_v12_creator_has_no_implicit_power() -> None:
    creator = "@creator:example.org"
    api = FakeApi()
    api.set_create(sender=creator, room_version="10")
    api.set_power_levels(users={BOT: 50}, users_default=0, state_default=50)
    api.put("allowed_server", "friends.org", sender=creator)
    assert not run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_per_type_events_entry_lowers_the_bar() -> None:
    api = FakeApi()
    api.set_power_levels(
        users={BOT: 50},
        users_default=0,
        state_default=100,
        events={"guardian.allowed_server": 50},
    )
    api.put("allowed_server", "friends.org", sender=BOT)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_per_type_events_entry_raises_the_bar() -> None:
    api = FakeApi()
    api.set_power_levels(
        users={BOT: 50},
        users_default=0,
        state_default=50,
        events={"guardian.allowed_server": 100},
    )
    api.put("allowed_server", "friends.org", sender=BOT)
    assert not run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_server_admin_is_honoured_without_power() -> None:
    api = FakeApi()
    api.set_power_levels(users={}, users_default=0, state_default=100)
    api.put("allowed_server", "friends.org", sender=ADMIN)
    assert run(make_store(api).get_rules()).evaluate("@a:friends.org").allowed


def test_unreadable_power_levels_falls_back_to_admins(
    caplog: pytest.LogCaptureFixture,
) -> None:
    api = FakeApi()  # no m.room.power_levels at all
    api.put("allowed_server", "friends.org", sender=BOT)
    api.put("allowed_server", "admin.org", sender=ADMIN)
    with caplog.at_level(logging.WARNING, logger="synapse_guardian.store"):
        rules = run(make_store(api).get_rules())
    assert not rules.evaluate("@a:friends.org").allowed
    assert rules.evaluate("@a:admin.org").allowed
    messages = [r.getMessage() for r in caplog.records]
    assert any("only server admins may manage rules" in m for m in messages)
    assert any("power levels unreadable" in m for m in messages)


def test_notify_user_confers_no_trust() -> None:
    """notify_user is who we post as, not who may write rules (0.5.0)."""
    api = FakeApi()
    api.set_power_levels(users={}, users_default=0, state_default=50)
    api.put("allowed_server", "friends.org", sender=BOT)
    store = make_store(api, notify_room=True, notify_user=BOT)
    assert not run(store.get_rules()).evaluate("@a:friends.org").allowed


def test_invalid_state_key_skipped_logged(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi()
    api.put("allowed_server", "friends org")
    api.put("allowed_server", "*")  # catch-all in allow list
    api.put("protected_user", "not-a-user")
    api.put("allowed_server", "friends.org")
    with caplog.at_level(logging.WARNING, logger="synapse_guardian.store"):
        rules = run(make_store(api).get_rules())
    assert rules.evaluate("@a:friends.org").allowed
    assert not rules.evaluate("@a:anything.org").allowed
    assert rules.protected_users == frozenset()
    assert sum("ignoring invalid" in r.message for r in caplog.records) == 3


def test_entity_falls_back_to_state_key_and_rejects_non_string() -> None:
    api = FakeApi()
    api.put("allowed_server", "friends.org", content={"added_by": ADMIN})  # no entity
    api.put("allowed_server", "other.org", content={"entity": 42})
    rules = run(make_store(api).get_rules())
    assert rules.evaluate("@a:friends.org").allowed
    assert not rules.evaluate("@a:other.org").allowed


def test_unknown_event_types_ignored() -> None:
    api = FakeApi()
    api.state[("m.room.member", "@x:example.org")] = SimpleNamespace(
        type="m.room.member", state_key="@x:example.org", sender=ADMIN, content={"membership": "join"}
    )
    api.state[("guardian.bogus", "friends.org")] = SimpleNamespace(
        type="guardian.bogus", state_key="friends.org", sender=ADMIN, content={"x": 1}
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
    assert PolicyStore.is_our_event_type("guardian.allowed_server")
    assert not PolicyStore.is_our_event_type("m.room.message")


def test_admin_protected_user_warned_once(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeApi()
    api.admins.add("@kid:example.org")
    notified: list[str] = []

    async def on_admin(user_id: str) -> None:
        notified.append(user_id)

    store = make_store(api, on_admin=on_admin, protected_users=["@kid:example.org"])
    with caplog.at_level(logging.ERROR, logger="synapse_guardian.store"):
        run(store.refresh())
        run(store.refresh())
    assert notified == ["@kid:example.org"]
    assert sum("is a server admin" in r.message for r in caplog.records) == 1


# --- config ---------------------------------------------------------------


def test_parse_config_rejects_unknown_policy() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"uninvited_joins": "maybe"})


def test_parse_config_rejects_catch_all_allow() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"allowed_servers": ["*"]})


def test_parse_config_rejects_bad_control_room() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"control_room": "#alias:example.org"})


def test_parse_config_notify_requires_user_and_room() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"notify_room": True, "control_room": ROOM})
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"notify_room": True, "notify_user": BOT})


def test_parse_config_rejects_unknown_keys() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"protected": []})


def test_parse_config_rejects_removed_trusted_senders() -> None:
    with pytest.raises(ConfigError) as excinfo:
        GuardianConfig.parse({"trusted_senders": ["@a:example.org"]})
    message = str(excinfo.value)
    assert "removed in 0.5.0" in message
    assert "power levels" in message


def test_parse_config_defaults() -> None:
    cfg = GuardianConfig.parse(None)
    assert cfg.uninvited_joins == "known_rooms"
    assert cfg.refresh_interval_s == 15
    assert cfg.notify_dedupe_s == 300
    assert not cfg.dry_run
    # Off by default: registering on_new_event makes Synapse load the room's
    # full current state for every persisted event, server-wide.
    assert not cfg.watch_control_room
    # The module posts notices itself unless told otherwise.
    assert cfg.notify_via == "room"


def test_parse_config_rejects_unknown_notify_via() -> None:
    with pytest.raises(ConfigError, match="notify_via must be one of"):
        GuardianConfig.parse({"notify_via": "carrier-pigeon"})


def test_parse_config_bot_transport_requires_url_and_secret() -> None:
    base = {"notify_room": True, "notify_via": "bot"}
    with pytest.raises(ConfigError, match="requires notify_url"):
        GuardianConfig.parse(base)
    with pytest.raises(ConfigError, match="requires notify_secret"):
        GuardianConfig.parse({**base, "notify_url": "http://127.0.0.1:29316/notify"})


def test_parse_config_bot_transport_needs_no_control_room_or_user() -> None:
    """The bot knows its own room; we only need to reach the bot."""
    cfg = GuardianConfig.parse(
        {
            "notify_room": True,
            "notify_via": "bot",
            "notify_url": "http://127.0.0.1:29316/notify",
            "notify_secret": "s3cret",
        }
    )
    assert cfg.notify_via == "bot"
    assert cfg.notify_secret == "s3cret"
    assert cfg.control_room is None


def test_parse_config_room_transport_still_requires_control_room_and_user() -> None:
    with pytest.raises(ConfigError, match="requires control_room"):
        GuardianConfig.parse({"notify_room": True})
    with pytest.raises(ConfigError, match="requires notify_user"):
        GuardianConfig.parse({"notify_room": True, "control_room": "!r:test"})


def test_parse_config_secret_can_come_from_a_file(tmp_path) -> None:
    path = tmp_path / "secret"
    path.write_text("  from-a-file\n")
    cfg = GuardianConfig.parse(
        {
            "notify_room": True,
            "notify_via": "bot",
            "notify_url": "http://127.0.0.1:29316/notify",
            "notify_secret_path": str(path),
        }
    )
    assert cfg.notify_secret == "from-a-file"


def test_parse_config_rejects_both_secret_forms(tmp_path) -> None:
    path = tmp_path / "secret"
    path.write_text("x")
    with pytest.raises(ConfigError, match="not both"):
        GuardianConfig.parse({"notify_secret": "a", "notify_secret_path": str(path)})


def test_parse_config_rejects_unreadable_or_empty_secret_file(tmp_path) -> None:
    with pytest.raises(ConfigError, match="could not read"):
        GuardianConfig.parse({"notify_secret_path": str(tmp_path / "nope")})
    empty = tmp_path / "empty"
    empty.write_text("   ")
    with pytest.raises(ConfigError, match="is empty"):
        GuardianConfig.parse({"notify_secret_path": str(empty)})


def test_parse_config_watch_control_room_can_be_enabled() -> None:
    cfg = GuardianConfig.parse({"control_room": "!r:test", "watch_control_room": True})
    assert cfg.watch_control_room


def test_parse_config_rejects_non_bool_watch_control_room() -> None:
    with pytest.raises(ConfigError):
        GuardianConfig.parse({"watch_control_room": "yes"})
