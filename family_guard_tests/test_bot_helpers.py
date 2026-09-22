"""Pure tests for the bot's state reading and Element pill resolution.

No maubot runtime needed: everything under test is a module-level function.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("mautrix")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bot"))

from mautrix.types import StateEvent  # noqa: E402

from family_guard_bot import (  # noqa: E402
    entries_from_state,
    published_payload,
    resolve_user_arg,
    static_extra_lines,
)

ROOM = "!ctl:vibb.me"


def state_event(event_type: str, state_key: str, content: dict) -> StateEvent:
    return StateEvent.deserialize(
        {
            "type": event_type,
            "state_key": state_key,
            "sender": "@palchrb:vibb.me",
            "event_id": f"${event_type}{state_key}",
            "room_id": ROOM,
            "origin_server_ts": 0,
            "content": content,
        }
    )


# --- Element pills -------------------------------------------------------


def pill(mxid: str, text: str) -> str:
    return f'<a href="https://matrix.to/#/{mxid}">{text}</a>'


def test_pill_resolves_to_mxid() -> None:
    assert (
        resolve_user_arg("palchrb", f"!fg check {pill('@palchrb:vibb.me', 'palchrb')}")
        == "@palchrb:vibb.me"
    )


def test_explicit_mxid_beats_a_mismatched_pill() -> None:
    """An MXID typed in full stays in `body` and must never be overridden."""
    assert (
        resolve_user_arg("@matthew:matrix.org", f"!fg check {pill('@someone:else.org', 'x')}")
        == "@matthew:matrix.org"
    )


def test_two_pills_resolve_by_anchor_text() -> None:
    body = f"!fg allow user {pill('@a:one.org', 'alice')} {pill('@b:two.org', 'bob')}"
    assert resolve_user_arg("bob", body) == "@b:two.org"
    assert resolve_user_arg("alice", body) == "@a:one.org"


def test_percent_encoded_link() -> None:
    body = '<a href="https://matrix.to/#/%40palchrb%3Avibb.me?via=vibb.me">palchrb</a>'
    assert resolve_user_arg("palchrb", body) == "@palchrb:vibb.me"


def test_matrix_uri_form() -> None:
    body = '<a href="matrix:u/palchrb:vibb.me">palchrb</a>'
    assert resolve_user_arg("palchrb", body) == "@palchrb:vibb.me"


def test_html_escaped_href_and_nested_markup() -> None:
    body = '<a href="https://matrix.to/#/@a:one.org?via=one.org&amp;via=two.org"><b>alice</b></a>'
    assert resolve_user_arg("alice", body) == "@a:one.org"


def test_single_pill_is_used_even_if_the_text_differs() -> None:
    assert resolve_user_arg("Alice Smith", pill("@a:one.org", "alice")) == "@a:one.org"


def test_ambiguous_pills_are_left_alone() -> None:
    body = f"{pill('@a:one.org', 'alice')} {pill('@b:two.org', 'bob')}"
    assert resolve_user_arg("carol", body) == "carol"


def test_no_formatted_body_is_unchanged() -> None:
    assert resolve_user_arg("palchrb", None) == "palchrb"
    assert resolve_user_arg("palchrb", "") == "palchrb"


def test_garbage_is_unchanged_so_the_error_path_still_fires() -> None:
    assert resolve_user_arg("palchrb", "not html at all") == "palchrb"
    assert resolve_user_arg("palchrb", "<a href=>broken") == "palchrb"


def test_room_and_alias_links_are_not_users() -> None:
    assert resolve_user_arg("someroom", '<a href="https://matrix.to/#/!abc:vibb.me">someroom</a>') == "someroom"
    assert resolve_user_arg("public", '<a href="https://matrix.to/#/%23public:vibb.me">public</a>') == "public"


def test_event_link_is_not_a_user() -> None:
    body = '<a href="https://matrix.to/#/!r:vibb.me/$evt">link</a>'
    assert resolve_user_arg("link", body) == "link"


# --- room state ----------------------------------------------------------


def test_entries_from_state_reads_rule_events() -> None:
    state = [
        state_event("family_guard.allowed_server", "friends.org", {"entity": "friends.org"}),
        state_event("family_guard.protected_user", "kid:vibb.me", {"entity": "@kid:vibb.me"}),
        state_event("m.room.name", "", {"name": "Control"}),
    ]
    got = {(kind, entity) for kind, entity, _, _ in entries_from_state(state)}
    assert got == {("allowed_server", "friends.org"), ("protected_user", "@kid:vibb.me")}


def test_entries_from_state_skips_removed_and_unknown_kinds() -> None:
    state = [
        state_event("family_guard.allowed_server", "gone.org", {}),
        state_event("family_guard.bogus", "x", {"entity": "x"}),
        state_event("family_guard.effective_rules", "", {"static": {}}),
    ]
    assert entries_from_state(state) == []


def test_published_payload_found_and_absent() -> None:
    payload = {"static": {"allowed_servers": ["vibb.me"]}, "effective": {}}
    assert published_payload([state_event("family_guard.effective_rules", "", payload)]) == payload
    assert published_payload([state_event("m.room.name", "", {"name": "x"})]) is None
    assert published_payload([]) is None


def test_static_extra_lines_lists_only_what_the_room_does_not_show() -> None:
    payload = {
        "static": {
            "protected_users": ["@kid:vibb.me"],
            "allowed_servers": ["vibb.me", "friends.org"],
        }
    }
    lines = static_extra_lines(payload, {("allowed_server", "friends.org")})
    assert "**protected_user** (homeserver.yaml)" in lines
    assert "- `@kid:vibb.me`" in lines
    assert "- `vibb.me`" in lines
    assert "- `friends.org`" not in lines  # already listed from the room


def test_static_extra_lines_tolerates_junk() -> None:
    assert static_extra_lines(None, set()) == []
    assert static_extra_lines({}, set()) == []
    assert static_extra_lines({"static": "nope"}, set()) == []
    assert static_extra_lines({"static": {"allowed_servers": [1, None]}}, set()) == []
