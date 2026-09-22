"""maubot plugin: manage family_guard rules as state events in the control room.

Hardening principle: the bot never grants anyone a right they do not already
have in the room. Every command is silently ignored outside `control_room`,
and mutating commands require that the sender could send that state event
themselves (power levels), plus optionally membership in `admins`.
"""

from __future__ import annotations

import time
from typing import Any

from maubot import MessageEvent, Plugin
from maubot.handlers import command
from mautrix.types import EventType, PowerLevelStateEventContent, RoomID, StateEvent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

# vendored copy of family_guard/policy.py (see `make bot-build`)
from .policy import (
    KIND_ALLOWED_SERVER,
    KIND_ALLOWED_USER,
    KIND_BLOCKED_SERVER,
    KIND_BLOCKED_USER,
    KIND_PROTECTED_USER,
    InvalidPattern,
    RuleSet,
    is_user_id,
    validate_pattern,
)

EVENT_TYPE_PREFIX = "family_guard."
KINDS = (
    KIND_PROTECTED_USER,
    KIND_ALLOWED_SERVER,
    KIND_ALLOWED_USER,
    KIND_BLOCKED_USER,
    KIND_BLOCKED_SERVER,
)
# "<verb> <what>" -> kind
VERB_KINDS = {
    ("allow", "server"): KIND_ALLOWED_SERVER,
    ("allow", "user"): KIND_ALLOWED_USER,
    ("block", "server"): KIND_BLOCKED_SERVER,
    ("block", "user"): KIND_BLOCKED_USER,
}
REMOVE_KINDS = {
    ("remove", "server"): KIND_ALLOWED_SERVER,
    ("remove", "user"): KIND_ALLOWED_USER,
    ("unblock", "server"): KIND_BLOCKED_SERVER,
    ("unblock", "user"): KIND_BLOCKED_USER,
}


def event_type_for(kind: str) -> EventType:
    return EventType.find(EVENT_TYPE_PREFIX + kind, EventType.Class.STATE)


def state_key_for(entity: str) -> str:
    # State keys starting with "@" may only be set by that user (auth rules).
    return entity[1:] if entity.startswith("@") else entity


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("control_room")
        helper.copy("admins")


class FamilyGuardBot(Plugin):
    config: Config

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()
        if not self.config["control_room"]:
            self.log.error("family_guard_bot: control_room is not configured; refusing all commands")

    # --- guards --------------------------------------------------------------

    @property
    def control_room(self) -> RoomID | None:
        room = self.config["control_room"]
        return RoomID(room) if room else None

    @property
    def server_name(self) -> str:
        return str(self.client.mxid).split(":", 1)[1]

    def in_control_room(self, evt: MessageEvent) -> bool:
        room = self.control_room
        return room is not None and evt.room_id == room

    async def may_mutate(self, evt: MessageEvent, kind: str) -> bool:
        """Sender must be able to send this state event type themselves (and be in `admins`)."""
        admins = self.config["admins"] or []
        if admins and evt.sender not in admins:
            await evt.reply("You are not in the bot's admin list.")
            return False
        try:
            pl = await self.client.get_state_event(evt.room_id, EventType.ROOM_POWER_LEVELS)
        except Exception as e:  # noqa: BLE001
            await evt.reply(f"Could not read power levels: {e}")
            return False
        assert isinstance(pl, PowerLevelStateEventContent)
        needed = pl.get_event_level(event_type_for(kind))
        have = pl.get_user_level(evt.sender)
        if have < needed:
            await evt.reply(
                f"You cannot send this state event yourself (need PL {needed}, you have {have}), "
                "so I won't either."
            )
            return False
        return True

    # --- state I/O -----------------------------------------------------------

    async def current_entries(self, room_id: RoomID) -> list[tuple[str, str, dict[str, Any]]]:
        """(kind, entity, content) for every active entry in the room."""
        return [(k, e, c) for k, e, _, c in await self._current_state_entries(room_id)]

    async def _current_state_entries(
        self, room_id: RoomID
    ) -> list[tuple[str, str, str, dict[str, Any]]]:
        """(kind, entity, state_key, content) for every active entry in the room."""
        out: list[tuple[str, str, str, dict[str, Any]]] = []
        state: list[StateEvent] = await self.client.get_state(room_id)
        for ev in state:
            t = str(ev.type)
            if not t.startswith(EVENT_TYPE_PREFIX):
                continue
            kind = t[len(EVENT_TYPE_PREFIX):]
            if kind not in KINDS:
                continue
            content = ev.content.serialize() if hasattr(ev.content, "serialize") else dict(ev.content)
            if not content:
                continue
            entity = content.get("entity", ev.state_key)
            if isinstance(entity, str):
                out.append((kind, entity, str(ev.state_key), content))
        return out

    async def write_entry(self, evt: MessageEvent, kind: str, entity: str, reason: str | None) -> None:
        content: dict[str, Any] = {
            "entity": entity,
            "added_by": str(evt.sender),
            "ts": int(time.time() * 1000),
        }
        if reason:
            content["reason"] = reason
        await self.client.send_state_event(
            evt.room_id, event_type_for(kind), content, state_key=state_key_for(entity)
        )

    async def clear_entry(self, evt: MessageEvent, kind: str, state_key: str) -> None:
        await self.client.send_state_event(evt.room_id, event_type_for(kind), {}, state_key=state_key)

    async def add(self, evt: MessageEvent, kind: str, entity: str, reason: str | None) -> None:
        if not await self.may_mutate(evt, kind):
            return
        try:
            validate_pattern(kind, entity)
        except InvalidPattern as e:
            await evt.reply(f"Refusing `{entity}`: {e}")
            return
        await self.write_entry(evt, kind, entity, reason)
        await evt.reply(f"Added {kind} `{entity}`.")

    async def remove(self, evt: MessageEvent, kind: str, entity: str) -> None:
        if not await self.may_mutate(evt, kind):
            return
        # Clear by the *actual* state key(s) of matching entries: a hand-written
        # event may use a different key than the one the bot would derive.
        keys = [
            sk
            for k, e, sk, _ in await self._current_state_entries(evt.room_id)
            if k == kind and e.lower() == entity.lower()
        ]
        if not keys:
            await evt.reply(f"No active {kind} entry for `{entity}`.")
            return
        for state_key in keys:
            await self.clear_entry(evt, kind, state_key)
        await evt.reply(f"Removed {kind} `{entity}`.")

    # --- commands ------------------------------------------------------------

    @command.new(name="fg", help="family_guard rules", require_subcommand=True)
    async def fg(self, evt: MessageEvent) -> None:
        pass

    @fg.subcommand("protect", help="Protect a local user: !fg protect @kid:server [reason]")
    @command.argument("mxid")
    @command.argument("reason", required=False, pass_raw=True)
    async def protect(self, evt: MessageEvent, mxid: str, reason: str | None) -> None:
        if not self.in_control_room(evt):
            return
        if not is_user_id(mxid) or mxid.split(":", 1)[1] != self.server_name:
            await evt.reply(f"`{mxid}` is not a user on {self.server_name}; only local users can be protected.")
            return
        if evt.sender == mxid:
            await evt.reply("Refusing: you are trying to protect yourself. Admins bypass the module's checks.")
            return
        await self.add(evt, KIND_PROTECTED_USER, mxid, reason)
        await evt.reply(
            "Reminder: a protected user must not be a Synapse server admin "
            "(admins bypass invite/join checks). The module logs an error if it is."
        )

    @fg.subcommand("unprotect", help="Stop protecting a user: !fg unprotect @kid:server")
    @command.argument("mxid")
    async def unprotect(self, evt: MessageEvent, mxid: str) -> None:
        if not self.in_control_room(evt):
            return
        await self.remove(evt, KIND_PROTECTED_USER, mxid)

    @fg.subcommand("allow", help="Allow a server or user: !fg allow server <glob> | !fg allow user <mxid|glob> [reason]")
    @command.argument("what")
    @command.argument("pattern")
    @command.argument("reason", required=False, pass_raw=True)
    async def allow(self, evt: MessageEvent, what: str, pattern: str, reason: str | None) -> None:
        await self._verb(evt, "allow", what, pattern, reason)

    @fg.subcommand("block", help="Block a server or user: !fg block server <glob> | !fg block user <mxid|glob> [reason]")
    @command.argument("what")
    @command.argument("pattern")
    @command.argument("reason", required=False, pass_raw=True)
    async def block(self, evt: MessageEvent, what: str, pattern: str, reason: str | None) -> None:
        await self._verb(evt, "block", what, pattern, reason)

    @fg.subcommand("remove", help="Remove an allow entry: !fg remove server <glob> | !fg remove user <mxid|glob>")
    @command.argument("what")
    @command.argument("pattern")
    async def remove_cmd(self, evt: MessageEvent, what: str, pattern: str) -> None:
        await self._verb(evt, "remove", what, pattern, None)

    @fg.subcommand("unblock", help="Remove a block entry: !fg unblock server <glob> | !fg unblock user <mxid|glob>")
    @command.argument("what")
    @command.argument("pattern")
    async def unblock(self, evt: MessageEvent, what: str, pattern: str) -> None:
        await self._verb(evt, "unblock", what, pattern, None)

    async def _verb(
        self, evt: MessageEvent, verb: str, what: str, pattern: str, reason: str | None
    ) -> None:
        if not self.in_control_room(evt):
            return
        what = what.lower()
        if (verb, what) in VERB_KINDS:
            await self.add(evt, VERB_KINDS[(verb, what)], pattern, reason)
        elif (verb, what) in REMOVE_KINDS:
            await self.remove(evt, REMOVE_KINDS[(verb, what)], pattern)
        else:
            await evt.reply(f"Usage: !fg {verb} server|user <pattern>")

    @fg.subcommand("list", help="List all rules")
    async def list_cmd(self, evt: MessageEvent) -> None:
        if not self.in_control_room(evt):
            return
        entries = await self.current_entries(evt.room_id)
        if not entries:
            await evt.reply("No rules in this room (static homeserver.yaml rules are not shown).")
            return
        lines: list[str] = []
        for kind in KINDS:
            rows = sorted((e, c) for k, e, c in entries if k == kind)
            if not rows:
                continue
            lines.append(f"**{kind}**")
            for entity, content in rows:
                meta = []
                if content.get("added_by"):
                    meta.append(f"by {content['added_by']}")
                if isinstance(content.get("ts"), int):
                    meta.append(time.strftime("%Y-%m-%d", time.gmtime(content["ts"] / 1000)))
                if content.get("reason"):
                    meta.append(str(content["reason"]))
                suffix = f" — {', '.join(meta)}" if meta else ""
                lines.append(f"- `{entity}`{suffix}")
        lines.append("_Static rules from homeserver.yaml also apply and are not listed here._")
        await evt.reply("\n".join(lines))

    @fg.subcommand("check", help="Would this user be allowed to interact with the kids? !fg check @x:server")
    @command.argument("mxid")
    async def check(self, evt: MessageEvent, mxid: str) -> None:
        if not self.in_control_room(evt):
            return
        if not is_user_id(mxid):
            await evt.reply(f"`{mxid}` is not a user ID.")
            return
        entries = await self.current_entries(evt.room_id)
        rules = RuleSet.build([(k, e) for k, e, _ in entries], on_invalid=lambda *a: None)
        decision = rules.evaluate(mxid)
        verdict = "ALLOWED" if decision.allowed else "BLOCKED"
        await evt.reply(
            f"`{mxid}`: **{verdict}** (rule: `{decision.reason}`; room rules only — "
            "static homeserver.yaml rules such as your own server are not included)"
        )
