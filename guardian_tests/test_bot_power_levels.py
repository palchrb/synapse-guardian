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

from guardian_bot import RoomAuthority  # noqa: E402

CREATOR = "@palchrb:vibb.me"
BOT = "@guardianbot:vibb.me"
STRANGER = "@someone:vibb.me"

PL_CONTENT = {
    "users": {BOT: 50},  # the creator must NOT be listed in a v12 room
    "users_default": 0,
    "state_default": 100,
    "events": {"guardian.protected_user": 50},
}


def make_state(room_version: str, **create_extra: object) -> list[StateEvent]:
    create = StateEvent.deserialize(
        {
            "type": "m.room.create",
            "state_key": "",
            "sender": CREATOR,
            "event_id": "$create",
            "room_id": "!room",
            "origin_server_ts": 0,
            "content": {"room_version": room_version, **create_extra},
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
    authority = RoomAuthority.from_state(make_state("12"))
    needed = authority.needed_for(
        EventType.find("guardian.protected_user", EventType.Class.STATE)
    )
    assert needed == 50
    assert authority.power_of(CREATOR) > needed


def test_event_level_matches_the_server_not_the_type_class() -> None:
    """Regression: a typed lookup missed our entry and returned state_default.

    mautrix keys `content.events` by `EventType` and equality includes the type
    class, so `get_event_level` could miss a `Class.UNKNOWN` entry while we
    looked it up as `Class.STATE` -- making the bot stricter than the room. We
    match on the type string, as Synapse does. (We deliberately do not assert
    what mautrix's own lookup returns: that depends on whether the type has
    been registered globally by an earlier test.)
    """
    authority = RoomAuthority.from_state(make_state("12"))
    rule_type = EventType.find("guardian.protected_user", EventType.Class.STATE)
    assert authority.needed_for(rule_type) == 50


def test_additional_creator_also_outranks_everything() -> None:
    state = make_state("12", additional_creators=[BOT])
    assert RoomAuthority.from_state(state).power_of(BOT) > 100


def test_unlisted_state_event_falls_back_to_state_default() -> None:
    authority = RoomAuthority.from_state(make_state("12"))
    assert (
        authority.needed_for(EventType.find("m.room.name", EventType.Class.STATE)) == 100
    )


def test_bot_keeps_its_explicit_level() -> None:
    assert RoomAuthority.from_state(make_state("12")).power_of(BOT) == 50


def test_ordinary_member_is_still_users_default() -> None:
    assert RoomAuthority.from_state(make_state("12")).power_of(STRANGER) == 0


def test_pre_v12_creator_has_no_implicit_power() -> None:
    """Before v12 the creator is listed in `users` like anyone else."""
    assert RoomAuthority.from_state(make_state("10")).power_of(CREATOR) == 0


def test_missing_power_levels_event_does_not_crash() -> None:
    assert RoomAuthority.from_state([]).power_of(CREATOR) == 0
