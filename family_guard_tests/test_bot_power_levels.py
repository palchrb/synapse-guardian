"""The bot's power-level check must honour room v12 creator power.

Regression: in a v12 room the creator has effectively infinite power and is
forbidden from appearing in `m.room.power_levels.users`, so a plain lookup
reports them as `users_default` (0) and the bot refused its own owner with
"need PL 50, you have 0".
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("mautrix")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bot"))

from mautrix.types import EventType, StateEvent  # noqa: E402

from family_guard_bot import (  # noqa: E402
    event_level,
    power_levels_and_create,
    user_level,
)

CREATOR = "@palchrb:vibb.me"
BOT = "@guardianbot:vibb.me"
STRANGER = "@someone:vibb.me"

PL_CONTENT = {
    "users": {BOT: 50},  # the creator must NOT be listed in a v12 room
    "users_default": 0,
    "state_default": 100,
    "events": {"family_guard.protected_user": 50},
}


def make_state(room_version: str) -> list[StateEvent]:
    create = StateEvent.deserialize(
        {
            "type": "m.room.create",
            "state_key": "",
            "sender": CREATOR,
            "event_id": "$create",
            "room_id": "!room",
            "origin_server_ts": 0,
            "content": {"room_version": room_version},
        }
    )
    powers = StateEvent.deserialize(
        {
            "type": "m.room.power_levels",
            "state_key": "",
            "sender": CREATOR,
            "event_id": "$pl",
            "room_id": "!room",
            "origin_server_ts": 0,
            "content": PL_CONTENT,
        }
    )
    return [create, powers]


def test_creator_outranks_the_rule_event_in_v12() -> None:
    pl, create = power_levels_and_create(make_state("12"))
    needed = event_level(
        pl, EventType.find("family_guard.protected_user", EventType.Class.STATE)
    )
    assert needed == 50
    assert user_level(pl, create, CREATOR) > needed


def test_event_level_matches_the_server_not_the_type_class() -> None:
    """Regression: a typed lookup missed our entry and returned state_default."""
    pl, _ = power_levels_and_create(make_state("12"))
    rule_type = EventType.find("family_guard.protected_user", EventType.Class.STATE)
    assert pl.get_event_level(rule_type) == 100  # mautrix's own typed lookup misses
    assert event_level(pl, rule_type) == 50  # ours matches what Synapse enforces


def test_unlisted_state_event_falls_back_to_state_default() -> None:
    pl, _ = power_levels_and_create(make_state("12"))
    assert event_level(pl, EventType.find("m.room.name", EventType.Class.STATE)) == 100


def test_bot_keeps_its_explicit_level() -> None:
    pl, create = power_levels_and_create(make_state("12"))
    assert user_level(pl, create, BOT) == 50


def test_ordinary_member_is_still_users_default() -> None:
    pl, create = power_levels_and_create(make_state("12"))
    assert user_level(pl, create, STRANGER) == 0


def test_pre_v12_creator_has_no_implicit_power() -> None:
    """Before v12 the creator is listed in `users` like anyone else."""
    pl, create = power_levels_and_create(make_state("10"))
    assert user_level(pl, create, CREATOR) == 0


def test_missing_power_levels_event_does_not_crash() -> None:
    pl, create = power_levels_and_create([])
    assert create is None
    assert user_level(pl, create, CREATOR) == 0
