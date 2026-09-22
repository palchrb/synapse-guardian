"""FamilyGuard: the Synapse module. Registers the callbacks and applies the rules.

Never raises out of a callback: unexpected errors fail closed for protected
users and open for everyone else.
"""

from __future__ import annotations

import logging
from typing import Any

from synapse.module_api import NOT_SPAM, EventBase, ModuleApi
from synapse.module_api.errors import Codes

from family_guard.config import FamilyGuardConfig
from family_guard.notify import Notifier, NullNotifier, RoomNotifier, format_block
from family_guard.policy import RuleSet
from family_guard.store import PolicyStore

logger = logging.getLogger(__name__)

# kinds used in log lines / notices
INVITE_IN = "invite"
INVITE_OUT = "invite-out"
INVITE_3PID = "3pid-invite"
JOIN = "join"
PUBLISH = "publish"
KNOCK = "knock"
JOIN_RULES = "join_rules"
CANONICAL_ALIAS = "canonical_alias"


class FamilyGuard:
    def __init__(self, config: FamilyGuardConfig, api: ModuleApi) -> None:
        self._api = api
        self._config = config
        self._notifier: Notifier
        if config.notify_room:
            assert config.control_room is not None and config.notify_user is not None
            self._notifier = RoomNotifier(
                api, config.control_room, config.notify_user, config.notify_dedupe_s
            )
        else:
            self._notifier = NullNotifier()
        self._store = PolicyStore(api, config, on_admin_protected=self._on_admin_protected)

        api.register_spam_checker_callbacks(
            user_may_invite=self.user_may_invite,
            federated_user_may_invite=self.federated_user_may_invite,
            user_may_send_3pid_invite=self.user_may_send_3pid_invite,
            user_may_join_room=self.user_may_join_room,
            user_may_publish_room=self.user_may_publish_room,
        )
        api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed,
            on_new_event=self.on_new_event,
        )
        logger.info(
            "family_guard: loaded (control_room=%s, uninvited_joins=%s, dry_run=%s)",
            config.control_room,
            config.uninvited_joins,
            config.dry_run,
        )

    @staticmethod
    def parse_config(config: dict[str, Any] | None) -> FamilyGuardConfig:
        return FamilyGuardConfig.parse(config)

    # --- helpers -----------------------------------------------------------

    async def _rules(self) -> RuleSet:
        return await self._store.get_rules()

    def _block(
        self, kind: str, actor: str, target: str, room_id: str | None, rule: str
    ) -> Any:
        """Log + notify a block; return the spam-checker verdict (honouring dry_run)."""
        dry = self._config.dry_run
        logger.info(format_block(kind, actor, target, room_id, rule, dry))
        self._api.run_as_background_process(
            "family_guard_notify",
            self._notifier.notify,
            kind,
            actor,
            target,
            room_id,
            rule,
            dry,
        )
        return NOT_SPAM if dry else Codes.FORBIDDEN

    async def _on_admin_protected(self, user_id: str) -> None:
        await self._notifier.message(
            f"family_guard: WARNING protected user {user_id} is a server admin; "
            "Synapse skips invite/join checks for admins, so this user is NOT protected"
        )

    # --- spam checker callbacks -------------------------------------------

    async def federated_user_may_invite(self, event: EventBase) -> Any:
        """Inbound invites over federation. Runs before Synapse validates the event."""
        invitee: str | None = None
        try:
            if event.type != "m.room.member" or event.content.get("membership") != "invite":
                return NOT_SPAM
            invitee = event.state_key
            inviter = event.sender
            if not isinstance(invitee, str) or not isinstance(inviter, str):
                return NOT_SPAM
            rules = await self._rules()
            if not rules.is_protected(invitee):
                return NOT_SPAM
            decision = rules.evaluate(inviter)
            if decision.allowed:
                return NOT_SPAM
            return self._block(INVITE_IN, inviter, invitee, event.room_id, decision.reason)
        except Exception:
            logger.exception("family_guard: federated_user_may_invite failed")
            return await self._fail_closed_if_protected(invitee)

    async def user_may_invite(self, inviter: str, invitee: str, room_id: str) -> Any:
        """Local invites, both directions."""
        try:
            rules = await self._rules()
            if rules.is_protected(invitee):
                decision = rules.evaluate(inviter)
                if not decision.allowed:
                    return self._block(INVITE_IN, inviter, invitee, room_id, decision.reason)
            if rules.is_protected(inviter):
                decision = rules.evaluate(invitee)
                if not decision.allowed:
                    return self._block(INVITE_OUT, inviter, invitee, room_id, decision.reason)
            return NOT_SPAM
        except Exception:
            logger.exception("family_guard: user_may_invite failed")
            return await self._fail_closed_if_protected(inviter, invitee)

    async def user_may_send_3pid_invite(
        self, inviter: str, medium: str, address: str, room_id: str
    ) -> Any:
        try:
            rules = await self._rules()
            if rules.is_protected(inviter):
                return self._block(
                    INVITE_3PID, inviter, f"{medium}:{address}", room_id, "3pid-invites-disabled"
                )
            return NOT_SPAM
        except Exception:
            logger.exception("family_guard: user_may_send_3pid_invite failed")
            return await self._fail_closed_if_protected(inviter)

    async def user_may_join_room(self, user_id: str, room_id: str, is_invited: bool) -> Any:
        try:
            rules = await self._rules()
            if not rules.is_protected(user_id):
                return NOT_SPAM
            if is_invited:
                return NOT_SPAM  # the invite itself was vetted
            if self._config.uninvited_joins == "deny":
                return self._block(JOIN, user_id, room_id, room_id, "uninvited-joins-denied")
            reason = await self._known_room_reason(rules, user_id, room_id)
            if reason is None:
                return NOT_SPAM
            return self._block(JOIN, user_id, room_id, room_id, reason)
        except Exception:
            logger.exception("family_guard: user_may_join_room failed")
            return await self._fail_closed_if_protected(user_id)

    async def _known_room_reason(self, rules: RuleSet, user_id: str, room_id: str) -> str | None:
        """None if the room is known locally and everyone in it is allowed, else the reason."""
        state = await self._api.get_room_state(room_id, [("m.room.member", None)])
        local_joined = False
        for (_, member), event in state.items():
            membership = event.content.get("membership")
            if membership == "join" and self._api.is_mine(member):
                local_joined = True
                break
        if not local_joined:
            return "room-not-known"
        for (_, member), event in state.items():
            if event.content.get("membership") not in ("join", "invite"):
                continue
            if member.lower() == user_id.lower():
                continue
            decision = rules.evaluate(member)
            if not decision.allowed:
                return f"member {member} not allowed ({decision.reason})"
        return None

    async def user_may_publish_room(self, user_id: str, room_id: str) -> Any:
        try:
            rules = await self._rules()
            if rules.is_protected(user_id):
                return self._block(PUBLISH, user_id, room_id, room_id, "publishing-disabled")
            return NOT_SPAM
        except Exception:
            logger.exception("family_guard: user_may_publish_room failed")
            return await self._fail_closed_if_protected(user_id)

    async def _fail_closed_if_protected(self, *user_ids: str | None) -> Any:
        """After an unexpected error: deny if any involved user is (statically) protected."""
        static = self._config.static_rules
        cached = self._store._rules
        for user_id in user_ids:
            if user_id is None:
                continue
            if static.is_protected(user_id) or (cached is not None and cached.is_protected(user_id)):
                return Codes.FORBIDDEN
        return NOT_SPAM

    # --- third-party rules callbacks --------------------------------------

    async def check_event_allowed(
        self, event: EventBase, state: dict[Any, EventBase]
    ) -> tuple[bool, dict | None]:
        """Veto local knocks, non-invite join rules and canonical aliases by protected users."""
        sender: str | None = None
        try:
            sender = event.sender
            if not isinstance(sender, str) or not self._api.is_mine(sender):
                return True, None  # never veto federation traffic
            rules = await self._rules()
            if not rules.is_protected(sender):
                return True, None
            kind: str | None = None
            if event.type == "m.room.member" and event.content.get("membership") == "knock":
                kind = KNOCK
            elif event.type == "m.room.join_rules" and event.content.get("join_rule") != "invite":
                kind = JOIN_RULES
            elif event.type == "m.room.canonical_alias":
                kind = CANONICAL_ALIAS
            if kind is None:
                return True, None
            verdict = self._block(kind, sender, event.room_id, event.room_id, f"{kind}-disabled")
            return (verdict == NOT_SPAM), None
        except Exception:
            logger.exception("family_guard: check_event_allowed failed")
            verdict = await self._fail_closed_if_protected(sender)
            return (verdict == NOT_SPAM), None

    async def on_new_event(self, event: EventBase, state: dict[Any, EventBase]) -> None:
        try:
            if event.room_id == self._store.control_room and PolicyStore.is_our_event_type(
                event.type
            ):
                self._store.invalidate()
        except Exception:
            logger.exception("family_guard: on_new_event failed")
