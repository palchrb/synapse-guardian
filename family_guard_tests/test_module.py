"""End-to-end tests against a real (in-memory) Synapse 1.161 via HomeserverTestCase.

Run with:  PYTHONPATH=.synapse-tests python -m twisted.trial family_guard_tests.test_module
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, Mock

from twisted.internet.testing import MemoryReactor

from synapse.api.constants import EventTypes, JoinRules
from synapse.api.errors import SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.module_api import NOT_SPAM
from synapse.rest import admin
from synapse.rest.client import directory, knock, login, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util.clock import Clock

from tests import unittest
from tests.test_utils.event_builders import make_test_event, make_test_pdu_event

from family_guard.config import ConfigError
from family_guard.module import FamilyGuard

SERVER = "test"
KID = "@kid:test"
PLACEHOLDER_ROOM = "!placeholder:test"


class FamilyGuardTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        knock.register_servlets,
        directory.register_servlets,
    ]

    CONFIG_OVERRIDES: dict[str, Any] = {}

    def module_config(self) -> dict[str, Any]:
        cfg: dict[str, Any] = {
            "control_room": PLACEHOLDER_ROOM,
            "protected_users": [KID],
            "allowed_servers": [SERVER, "friends.org", "*.skole.no"],
            "allowed_users": ["@granny:other.org"],
            "blocked_users": ["@troll:friends.org"],
            "blocked_servers": ["evil.skole.no"],
            "notify_user": "@bot:test",
        }
        cfg.update(self.CONFIG_OVERRIDES)
        return cfg

    def default_config(self) -> JsonDict:
        config = super().default_config()
        config["modules"] = [
            {"module": "family_guard.FamilyGuard", "config": self.module_config()}
        ]
        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.module = self._find_module(hs)

        self.parent = self.register_user("parent", "pw", admin=True)
        self.parent_tok = self.login("parent", "pw")
        self.kid = self.register_user("kid", "pw")
        assert self.kid == KID
        self.kid_tok = self.login("kid", "pw")
        self.sibling = self.register_user("sibling", "pw")
        self.sibling_tok = self.login("sibling", "pw")
        self.bot = self.register_user("bot", "pw")
        self.bot_tok = self.login("bot", "pw")

        # Control room: parent creates it, bot joins. Point the module at it.
        self.control_room = self.helper.create_room_as(
            self.parent, is_public=False, tok=self.parent_tok
        )
        self.helper.invite(self.control_room, self.parent, self.bot, tok=self.parent_tok)
        self.helper.join(self.control_room, self.bot, tok=self.bot_tok)
        self.module._store.control_room = self.control_room
        if hasattr(self.module._notifier, "_room_id"):
            self.module._notifier._room_id = self.control_room  # type: ignore[attr-defined]

    @staticmethod
    def _find_module(hs: HomeServer) -> FamilyGuard:
        callbacks = hs.get_module_api_callbacks().spam_checker._user_may_invite_callbacks
        for cb in callbacks:
            if isinstance(getattr(cb, "__self__", None), FamilyGuard):
                return cb.__self__
        raise AssertionError("family_guard module not loaded")

    # --- helpers ------------------------------------------------------------

    def federated_invite(
        self,
        sender: str,
        invitee: str = KID,
        room_id: str = "!remote:friends.org",
        origin: str | None = None,
        membership: str = "invite",
    ) -> Any:
        room_version = RoomVersions.V10
        event = make_test_pdu_event(
            {
                "type": EventTypes.Member,
                "content": {"membership": membership},
                "room_id": room_id,
                "sender": sender,
                "state_key": invitee,
                "depth": 32,
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )
        return self.hs.get_federation_handler().on_invite_request(
            origin or sender.split(":", 1)[1], event, room_version
        )

    def assert_federated_invite_blocked(self, sender: str, **kwargs: Any) -> None:
        failure = self.get_failure(self.federated_invite(sender, **kwargs), SynapseError)
        self.assertEqual(failure.value.code, 403)
        self.assertEqual(failure.value.errcode, "M_FORBIDDEN")

    def remote_user_joins(self, room_id: str, user_id: str) -> None:
        """Have a remote user join a local public room via the federation handlers."""
        server = user_id.split(":", 1)[1]
        handler = self.hs.get_federation_handler()
        join_event = self.get_success(handler.on_make_join_request(server, room_id, user_id))
        join_event.signatures.update({server: {"x": "y"}})
        self.get_success(
            self.hs.get_federation_event_handler().on_send_membership_event(server, join_event)
        )

    def notices(self) -> list[str]:
        channel = self.make_request(
            "GET",
            f"/rooms/{self.control_room}/messages?dir=b&limit=50",
            access_token=self.parent_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)
        return [
            ev["content"]["body"]
            for ev in channel.json_body["chunk"]
            if ev["type"] == "m.room.message" and ev["content"].get("msgtype") == "m.notice"
        ]

    def mock_remote_profiles(self) -> None:
        """Synapse fetches a remote invitee's profile over federation before the spam check."""
        profile = self.hs.get_profile_handler()
        profile.get_displayname = AsyncMock(return_value=None)  # type: ignore[method-assign]
        profile.get_avatar_url = AsyncMock(return_value=None)  # type: ignore[method-assign]

    def mock_3pid(self) -> AsyncMock:
        make_invite_mock = AsyncMock(return_value=(Mock(event_id="abc"), 0))
        self.hs.get_room_member_handler()._make_and_store_3pid_invite = make_invite_mock  # type: ignore[method-assign]
        self.hs.get_identity_handler().lookup_3pid = AsyncMock(return_value=None)  # type: ignore[method-assign]
        return make_invite_mock

    def threepid_invite(self, room_id: str, tok: str) -> int:
        channel = self.make_request(
            "POST",
            f"/rooms/{room_id}/invite",
            content={
                "id_server": "example.com",
                "id_access_token": "sometoken",
                "medium": "email",
                "address": "someone@example.com",
            },
            access_token=tok,
        )
        return channel.code

    def add_rule(self, kind: str, entity: str, tok: str | None = None, content: dict | None = None,
                 expect_code: int = 200) -> None:
        # state keys may not start with "@" (auth rules) -> strip it, entity lives in content
        self.helper.send_state(
            self.control_room,
            f"family_guard.{kind}",
            {"entity": entity, "added_by": self.parent} if content is None else content,
            tok=tok or self.parent_tok,
            state_key=entity[1:] if entity.startswith("@") else entity,
            expect_code=expect_code,
        )
        self.pump()


class InvitesToKidTestCase(FamilyGuardTestCase):
    def test_federated_invite_from_allowed_server_ok(self) -> None:
        event = self.get_success(self.federated_invite("@friend:friends.org"))
        self.assertEqual(event.state_key, KID)

    def test_federated_invite_from_blocked_server_403(self) -> None:
        self.assert_federated_invite_blocked("@stranger:stranger.org")

    def test_federated_invite_from_allowed_user_on_blocked_server_ok(self) -> None:
        self.get_success(self.federated_invite("@granny:other.org"))

    def test_federated_invite_from_blocked_user_on_allowed_server_403(self) -> None:
        self.assert_federated_invite_blocked("@troll:friends.org")

    def test_federated_invite_glob_and_blocked_server_exception(self) -> None:
        self.get_success(self.federated_invite("@a:ok.skole.no", room_id="!r1:ok.skole.no"))
        self.assert_federated_invite_blocked("@a:evil.skole.no", room_id="!r2:evil.skole.no")

    def test_federated_invite_non_invite_event_passthrough(self) -> None:
        # federated_user_may_invite itself passes non-invite events through
        # (Synapse rejects them with 400 later). Note Synapse's dispatcher also
        # runs user_may_invite for federated invites, which does block here.
        event = make_test_pdu_event(
            {
                "type": EventTypes.Member,
                "content": {"membership": "join"},
                "room_id": "!r:stranger.org",
                "sender": "@stranger:stranger.org",
                "state_key": KID,
            },
            RoomVersions.V10,
        )
        self.assertEqual(self.get_success(self.module.federated_user_may_invite(event)), NOT_SPAM)
        failure = self.get_failure(
            self.federated_invite("@stranger:stranger.org", membership="join"), SynapseError
        )
        self.assertIn(failure.value.code, (400, 403))

    def test_federated_invite_foreign_state_key_passthrough(self) -> None:
        failure = self.get_failure(
            self.federated_invite("@stranger:stranger.org", invitee="@someone:elsewhere.org"),
            SynapseError,
        )
        self.assertEqual(failure.value.code, 400)  # "must be for this server", not our 403

    def test_federated_invite_to_unprotected_user_unaffected(self) -> None:
        self.get_success(self.federated_invite("@stranger:stranger.org", invitee=self.sibling))

    def test_local_invite_from_sibling_ok(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.helper.invite(room_id, self.sibling, self.kid, tok=self.sibling_tok)

    def test_local_invite_from_admin_ok(self) -> None:
        room_id = self.helper.create_room_as(self.parent, is_public=False, tok=self.parent_tok)
        self.helper.invite(room_id, self.parent, self.kid, tok=self.parent_tok)

    def test_local_invite_to_unprotected_user_unaffected(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.helper.invite(room_id, self.sibling, self.bot, tok=self.sibling_tok)


class InvitesFromKidTestCase(FamilyGuardTestCase):
    def test_kid_invite_remote_blocked_403(self) -> None:
        self.mock_remote_profiles()
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.invite(
            room_id, self.kid, "@stranger:stranger.org", tok=self.kid_tok, expect_code=403
        )

    def test_kid_invite_remote_allowed_ok(self) -> None:
        # Direct callback: a real REST invite would need outbound federation.
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        res = self.get_success(self.module.user_may_invite(self.kid, "@friend:friends.org", room_id))
        self.assertEqual(res, NOT_SPAM)
        res = self.get_success(self.module.user_may_invite(self.kid, "@troll:friends.org", room_id))
        self.assertNotEqual(res, NOT_SPAM)

    def test_kid_invite_local_sibling_ok(self) -> None:
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.invite(room_id, self.kid, self.sibling, tok=self.kid_tok)

    def test_kid_createroom_with_blocked_invitee_403(self) -> None:
        self.mock_remote_profiles()
        channel = self.make_request(
            "POST",
            "/createRoom",
            content={"invite": ["@stranger:stranger.org"], "preset": "private_chat"},
            access_token=self.kid_tok,
        )
        self.assertEqual(channel.code, 403, channel.json_body)

    def test_kid_3pid_invite_403(self) -> None:
        make_invite = self.mock_3pid()
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.assertEqual(self.threepid_invite(room_id, self.kid_tok), 403)
        make_invite.assert_not_called()

    def test_sibling_3pid_invite_ok(self) -> None:
        make_invite = self.mock_3pid()
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.assertEqual(self.threepid_invite(room_id, self.sibling_tok), 200)
        make_invite.assert_called_once()


class JoinsTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"strict_local_events": True}

    def test_kid_join_with_invite_ok(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.helper.invite(room_id, self.sibling, self.kid, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok)

    def test_kid_join_unknown_remote_room_403(self) -> None:
        self.helper.join("!nope:remote.org", self.kid, tok=self.kid_tok, expect_code=403)

    def test_sibling_join_unknown_remote_room_not_blocked_by_us(self) -> None:
        # Not 403 from us: Synapse fails later trying to reach the remote (404/502-ish).
        channel = self.make_request(
            "POST", "/join/!nope:remote.org", content={}, access_token=self.sibling_tok
        )
        self.assertNotEqual(channel.code, 403, channel.json_body)

    def test_kid_join_local_room_all_members_allowed_ok(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok)

    def test_kid_join_local_room_with_blocked_member_403(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.remote_user_joins(room_id, "@x:bad.org")
        self.helper.join(room_id, self.kid, tok=self.kid_tok, expect_code=403)

    def test_kid_join_local_room_with_allowed_remote_member_ok(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.remote_user_joins(room_id, "@x:friends.org")
        self.helper.join(room_id, self.kid, tok=self.kid_tok)

    def test_kid_join_room_everyone_left_403(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.helper.leave(room_id, self.sibling, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok, expect_code=403)

    def test_kid_create_room_ok(self) -> None:
        self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)

    def test_kid_create_public_room_403(self) -> None:
        # public preset sets join_rules=public, vetoed by check_event_allowed
        self.helper.create_room_as(self.kid, is_public=True, tok=self.kid_tok, expect_code=403)

    def test_kid_cannot_open_join_rules_403(self) -> None:
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.send_state(
            room_id, EventTypes.JoinRules, {"join_rule": JoinRules.PUBLIC}, tok=self.kid_tok, expect_code=403
        )
        self.helper.send_state(
            room_id, EventTypes.JoinRules, {"join_rule": JoinRules.INVITE}, tok=self.kid_tok
        )

    def test_kid_cannot_set_canonical_alias_403(self) -> None:
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.send_state(
            room_id, EventTypes.CanonicalAlias, {"alias": "#x:test"}, tok=self.kid_tok, expect_code=403
        )

    @unittest.override_config({"room_list_publication_rules": [{"action": "allow"}]})
    def test_kid_cannot_publish_room_403(self) -> None:
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        channel = self.make_request(
            "PUT",
            f"/directory/list/room/{room_id}",
            content={"visibility": "public"},
            access_token=self.kid_tok,
        )
        self.assertEqual(channel.code, 403, channel.json_body)
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        channel = self.make_request(
            "PUT",
            f"/directory/list/room/{room_id}",
            content={"visibility": "public"},
            access_token=self.sibling_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)


class KnocksTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"strict_local_events": True}

    def knock_room(self) -> str:
        room_id = self.helper.create_room_as(
            self.sibling, is_public=False, room_version="10", tok=self.sibling_tok
        )
        self.helper.send_state(
            room_id, EventTypes.JoinRules, {"join_rule": JoinRules.KNOCK}, tok=self.sibling_tok
        )
        return room_id

    def test_kid_local_knock_403(self) -> None:
        self.helper.knock(self.knock_room(), self.kid, tok=self.kid_tok, expect_code=403)

    def test_bot_local_knock_ok(self) -> None:
        self.helper.knock(self.knock_room(), self.bot, tok=self.bot_tok)

    def test_incoming_federation_knock_not_vetoed(self) -> None:
        event = make_test_event(
            type=EventTypes.Member,
            sender="@remote:stranger.org",
            state_key="@remote:stranger.org",
            content={"membership": "knock"},
            room_id="!r:test",
        )
        res = self.get_success(self.module.check_event_allowed(event, {}))
        self.assertEqual(res, (True, None))

    def test_kid_knock_event_vetoed_directly(self) -> None:
        event = make_test_event(
            type=EventTypes.Member,
            sender=self.kid,
            state_key=self.kid,
            content={"membership": "knock"},
            room_id="!r:test",
        )
        res = self.get_success(self.module.check_event_allowed(event, {}))
        self.assertEqual(res, (False, None))


class DenyJoinPolicyTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"uninvited_joins": "deny"}

    def test_kid_join_uninvited_deny_policy_403(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok, expect_code=403)

    def test_kid_join_with_invite_still_ok(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.helper.invite(room_id, self.sibling, self.kid, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok)


class ControlRoomTestCase(FamilyGuardTestCase):
    def test_rule_added_via_state_applies_immediately(self) -> None:
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")
        self.add_rule("allowed_server", "new.org")
        self.get_success(self.federated_invite("@a:new.org", room_id="!b:new.org"))

    def test_rule_removed_via_empty_content(self) -> None:
        self.add_rule("allowed_server", "new.org")
        self.get_success(self.federated_invite("@a:new.org", room_id="!a:new.org"))
        self.add_rule("allowed_server", "new.org", content={})
        self.assert_federated_invite_blocked("@a:new.org", room_id="!b:new.org")

    def test_protect_via_state_makes_user_protected(self) -> None:
        self.get_success(self.federated_invite("@stranger:stranger.org", invitee=self.sibling, room_id="!a:stranger.org"))
        self.add_rule("protected_user", self.sibling)
        self.assert_federated_invite_blocked("@stranger:stranger.org", invitee=self.sibling, room_id="!b:stranger.org")

    def test_blocked_user_via_state(self) -> None:
        self.add_rule("blocked_user", "@meanie:friends.org")
        self.assert_federated_invite_blocked("@meanie:friends.org")
        self.get_success(self.federated_invite("@friend:friends.org"))

    def test_rule_from_bot_is_trusted(self) -> None:
        # bot is notify_user -> trusted; needs PL to send state, grant it
        self.helper.send_state(
            self.control_room,
            EventTypes.PowerLevels,
            {"users": {self.parent: 100, self.bot: 50}, "state_default": 50},
            tok=self.parent_tok,
        )
        self.add_rule("allowed_server", "new.org", tok=self.bot_tok)
        self.get_success(self.federated_invite("@a:new.org", room_id="!a:new.org"))

    def test_state_from_low_pl_user_rejected_by_synapse(self) -> None:
        self.helper.invite(self.control_room, self.parent, self.sibling, tok=self.parent_tok)
        self.helper.join(self.control_room, self.sibling, tok=self.sibling_tok)
        self.add_rule("allowed_server", "new.org", tok=self.sibling_tok, expect_code=403)
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")

    def test_state_from_trusted_but_unprivileged_user_ignored_by_module(self) -> None:
        # Give sibling PL to send state but sibling is neither admin nor trusted.
        self.helper.invite(self.control_room, self.parent, self.sibling, tok=self.parent_tok)
        self.helper.join(self.control_room, self.sibling, tok=self.sibling_tok)
        self.helper.send_state(
            self.control_room,
            EventTypes.PowerLevels,
            {"users": {self.parent: 100, self.sibling: 100}, "state_default": 50},
            tok=self.parent_tok,
        )
        self.add_rule("allowed_server", "new.org", tok=self.sibling_tok)
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")

    def test_invalid_state_entries_ignored(self) -> None:
        self.add_rule("allowed_server", "*")  # catch-all: skipped
        self.add_rule("allowed_user", "not-a-user")
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")

    def test_ttl_refresh_picks_up_changes_without_invalidation(self) -> None:
        self.add_rule("allowed_server", "new.org")
        # Simulate a worker that never saw on_new_event: force cache to look fresh & unaware.
        self.module._store._stale = False
        self.module._store._rules = self.module._config.static_rules
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")
        self.module._store._loaded_at -= 31
        self.get_success(self.federated_invite("@a:new.org", room_id="!b:new.org"))


class AdminProtectedTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"protected_users": [KID, "@parent:test"], "notify_room": True}

    def test_admin_protected_user_logged_and_notified(self) -> None:
        self.module._store._warned_admins.clear()  # already warned once during prepare()
        with self.assertLogs("family_guard.store", level="ERROR") as logs:
            self.get_success(self.module._store.refresh())
        self.assertTrue(any("@parent:test" in line and "server admin" in line for line in logs.output))
        self.pump()
        self.assertTrue(any("@parent:test" in n and "WARNING" in n for n in self.notices()))


class DryRunTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"dry_run": True, "notify_room": True, "strict_local_events": True}

    def test_dry_run_allows_and_logs(self) -> None:
        with self.assertLogs("family_guard.module", level="INFO") as logs:
            self.get_success(self.federated_invite("@stranger:stranger.org", room_id="!a:stranger.org"))
        self.assertTrue(any("[dry-run] would block invite" in line for line in logs.output))
        self.pump()
        self.assertTrue(any("[dry-run]" in n for n in self.notices()))

    def test_dry_run_join_allowed(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.remote_user_joins(room_id, "@x:bad.org")
        self.helper.join(room_id, self.kid, tok=self.kid_tok)

    def test_dry_run_knock_allowed(self) -> None:
        room_id = self.helper.create_room_as(self.sibling, is_public=False, tok=self.sibling_tok)
        self.helper.send_state(
            room_id, EventTypes.JoinRules, {"join_rule": JoinRules.KNOCK}, tok=self.sibling_tok
        )
        self.helper.knock(room_id, self.kid, tok=self.kid_tok)


class NotifyTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"notify_room": True, "notify_dedupe_s": 300}

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)
        self.now = [1000.0]
        self.module._notifier._clock = lambda: self.now[0]  # type: ignore[attr-defined]

    def test_notify_posts_notice_on_block(self) -> None:
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!a:stranger.org")
        self.pump()
        notes = self.notices()
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("blocked invite @stranger:stranger.org -> @kid:test", notes[0])
        self.assertIn("default-deny", notes[0])

    def test_notify_deduped_within_window(self) -> None:
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!a:stranger.org")
        self.now[0] += 100
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!b:stranger.org")
        self.pump()
        self.assertEqual(len(self.notices()), 1)

    def test_notify_after_window(self) -> None:
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!a:stranger.org")
        self.now[0] += 301
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!b:stranger.org")
        self.pump()
        self.assertEqual(len(self.notices()), 2)

    def test_notify_different_actors_not_deduped(self) -> None:
        self.assert_federated_invite_blocked("@a:stranger.org", room_id="!a:stranger.org")
        self.assert_federated_invite_blocked("@b:stranger.org", room_id="!a:stranger.org")
        self.pump()
        self.assertEqual(len(self.notices()), 2)

    def test_notify_failure_does_not_change_decision(self) -> None:
        self.helper.leave(self.control_room, self.bot, tok=self.bot_tok)
        with self.assertLogs("family_guard.notify", level="ERROR"):
            self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!a:stranger.org")
            self.pump()
        self.assertEqual(self.notices(), [])

    def test_notice_is_not_encrypted_plain_notice(self) -> None:
        self.assert_federated_invite_blocked("@stranger:stranger.org", room_id="!a:stranger.org")
        self.pump()
        channel = self.make_request(
            "GET", f"/rooms/{self.control_room}/messages?dir=b", access_token=self.parent_tok
        )
        ev = [e for e in channel.json_body["chunk"] if e["type"] == "m.room.message"][0]
        self.assertEqual(ev["sender"], self.bot)


class ConfigTestCase(unittest.TestCase):
    def test_parse_config_rejects_bad_values(self) -> None:
        with self.assertRaises(ConfigError):
            FamilyGuard.parse_config({"uninvited_joins": "sometimes"})
        with self.assertRaises(ConfigError):
            FamilyGuard.parse_config({"allowed_servers": ["*"]})
        with self.assertRaises(ConfigError):
            FamilyGuard.parse_config({"control_room": "#not-an-id:test"})
        with self.assertRaises(ConfigError):
            FamilyGuard.parse_config({"notify_room": True})

    def test_parse_config_ok(self) -> None:
        cfg = FamilyGuard.parse_config({"protected_users": [KID], "allowed_servers": ["test"]})
        self.assertTrue(cfg.static_rules.is_protected(KID))


class StrictLocalEventsTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"strict_local_events": True}

    def test_check_event_allowed_registered_when_enabled(self) -> None:
        callbacks = self.hs.get_module_api_callbacks().third_party_event_rules
        self.assertIn(
            self.module.check_event_allowed, callbacks._check_event_allowed_callbacks
        )


class WatchControlRoomTestCase(FamilyGuardTestCase):
    """`on_new_event` is costly server-wide, so it is only registered when usable."""

    def test_on_new_event_registered_when_watching(self) -> None:
        callbacks = self.hs.get_module_api_callbacks().third_party_event_rules
        self.assertIn(self.module.on_new_event, callbacks._on_new_event_callbacks)
        self.assertTrue(self.module._watching_control_room)


class NoWatchControlRoomTestCase(FamilyGuardTestCase):
    CONFIG_OVERRIDES = {"watch_control_room": False}

    def test_on_new_event_not_registered(self) -> None:
        callbacks = self.hs.get_module_api_callbacks().third_party_event_rules
        self.assertNotIn(self.module.on_new_event, callbacks._on_new_event_callbacks)
        self.assertFalse(self.module._watching_control_room)

    def test_rules_still_propagate_via_ttl(self) -> None:
        self.add_rule("allowed_server", "new.org")
        self.module._store._stale = False
        self.module._store._rules = self.module._config.static_rules
        self.assert_federated_invite_blocked("@a:new.org", room_id="!a:new.org")
        self.module._store._loaded_at -= 31
        self.get_success(self.federated_invite("@a:new.org", room_id="!b:new.org"))

    def test_check_event_allowed_not_registered_by_default(self) -> None:
        """It costs a state load per event server-wide, so it is opt-in."""
        callbacks = self.hs.get_module_api_callbacks().third_party_event_rules
        self.assertNotIn(
            self.module.check_event_allowed, callbacks._check_event_allowed_callbacks
        )
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.send_state(
            room_id, EventTypes.JoinRules, {"join_rule": JoinRules.PUBLIC}, tok=self.kid_tok
        )


class ResilienceTestCase(FamilyGuardTestCase):
    def test_callback_error_fails_closed_for_protected(self) -> None:
        self.module._store.get_rules = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        self.assert_federated_invite_blocked("@friend:friends.org")
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.helper.join(room_id, self.kid, tok=self.kid_tok, expect_code=403)

    def test_callback_error_fails_open_for_unprotected(self) -> None:
        self.module._store.get_rules = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        self.get_success(self.federated_invite("@stranger:stranger.org", invitee=self.sibling))
        room_id = self.helper.create_room_as(self.sibling, is_public=True, tok=self.sibling_tok)
        self.helper.join(room_id, self.bot, tok=self.bot_tok)

    def test_events_from_kid_in_ordinary_rooms_allowed(self) -> None:
        room_id = self.helper.create_room_as(self.kid, is_public=False, tok=self.kid_tok)
        self.helper.send(room_id, body="hi", tok=self.kid_tok)
        self.helper.send_state(room_id, EventTypes.Name, {"name": "mine"}, tok=self.kid_tok)
