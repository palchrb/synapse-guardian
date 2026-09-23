"""maubot plugin: manage guardian rules as state events in the control room.

Hardening principle: the bot never grants anyone a right they do not already
have in the room. Every command is silently ignored outside `control_room`,
and mutating commands require that the sender could send that state event
themselves (power levels), plus optionally membership in `admins`.
"""

from __future__ import annotations

import hmac
import html
import json
import re
import time
import urllib.parse
from collections.abc import Mapping
from typing import Any

from aiohttp import web as aiohttp_web
from maubot import MessageEvent, Plugin
from maubot.handlers import command, web
from mautrix.types import EventType, MessageType, RoomID, StateEvent, TextMessageEventContent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

# vendored copy of synapse_guardian/policy.py (see `make bot-build`)
from .policy import (
    KIND_ALLOWED_SERVER,
    KIND_ALLOWED_USER,
    KIND_BLOCKED_SERVER,
    KIND_BLOCKED_USER,
    KIND_PROTECTED_USER,
    InvalidPattern,
    RuleSet,
    event_power_level,
    is_user_id,
    user_power_level,
    validate_pattern,
)

EVENT_TYPE_PREFIX = "guardian."
# Published by the module: the rule set it actually loaded, including the
# homeserver.yaml baseline we cannot see from here.
EFFECTIVE_RULES_TYPE = "guardian.effective_rules"
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
        helper.copy("notify_secret")


# Element sends a pill as a matrix.to link in `formatted_body`, leaving only the
# display name in `body`. Both link forms below appear in the wild.
_LINK_RE = re.compile(
    r'<a\b[^>]*\bhref="(?P<href>[^"]+)"[^>]*>(?P<text>.*?)</a>', re.IGNORECASE | re.DOTALL
)
_MATRIX_TO_RE = re.compile(r"^https?://matrix\.to/#/(?P<id>[^?]+)", re.IGNORECASE)
_MATRIX_URI_RE = re.compile(r"^matrix:u/(?P<id>[^?]+)", re.IGNORECASE)


def _user_id_from_href(href: str) -> str | None:
    """The MXID a link points at, or None if it is not a user link."""
    href = html.unescape(href).strip()
    match = _MATRIX_TO_RE.match(href)
    if match:
        candidate = urllib.parse.unquote(match.group("id"))
    else:
        match = _MATRIX_URI_RE.match(href)
        if not match:
            return None
        # matrix:u/user:server omits the sigil
        candidate = "@" + urllib.parse.unquote(match.group("id"))
    return candidate if is_user_id(candidate) else None


def resolve_user_arg(arg: str, formatted_body: str | None) -> str:
    """Turn a pill's display name back into an MXID, if that is what `arg` is.

    Returns `arg` unchanged when it already is an MXID, when there is nothing
    usable in `formatted_body`, or when the pills are ambiguous -- so the
    caller's "is not a user ID" error still fires.
    """
    if is_user_id(arg):
        return arg  # an explicit MXID always wins over the rendered body
    if not formatted_body or not isinstance(formatted_body, str):
        return arg
    links: list[tuple[str, str]] = []  # (anchor text, mxid)
    for match in _LINK_RE.finditer(formatted_body):
        user_id = _user_id_from_href(match.group("href"))
        if user_id is None:
            continue  # room, alias or event link
        text = html.unescape(re.sub(r"<[^>]+>", "", match.group("text"))).strip()
        links.append((text, user_id))
    if not links:
        return arg
    wanted = arg.strip()
    for text, user_id in links:
        if text == wanted or text.lstrip("@") == wanted.lstrip("@"):
            return user_id
    return links[0][1] if len(links) == 1 else arg


def formatted_body_of(evt: MessageEvent) -> str | None:
    """`formatted_body` if this message has one."""
    body = getattr(evt.content, "formatted_body", None)
    return body if isinstance(body, str) else None


def _content_dict(content: Any) -> dict[str, Any]:
    if hasattr(content, "serialize"):
        return dict(content.serialize())
    try:
        return dict(content)
    except Exception:  # noqa: BLE001
        return {}


def entries_from_state(state: list[StateEvent]) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(kind, entity, state_key, content) for every active rule entry in `state`."""
    out: list[tuple[str, str, str, dict[str, Any]]] = []
    for ev in state:
        t = str(ev.type)
        if not t.startswith(EVENT_TYPE_PREFIX):
            continue
        kind = t[len(EVENT_TYPE_PREFIX):]
        if kind not in KINDS:
            continue
        content = _content_dict(ev.content)
        if not content:
            continue
        entity = content.get("entity", ev.state_key)
        if isinstance(entity, str):
            out.append((kind, entity, str(ev.state_key), content))
    return out


def published_payload(state: list[StateEvent]) -> dict[str, Any] | None:
    """The module's `guardian.effective_rules` content, or None if absent."""
    for ev in state:
        if str(ev.type) == EFFECTIVE_RULES_TYPE and str(ev.state_key) == "":
            content = _content_dict(ev.content)
            return content or None
    return None


def static_extra_lines(payload: dict[str, Any] | None, shown: set[tuple[str, str]]) -> list[str]:
    """Lines describing static rules that the room listing does not already show."""
    if not payload:
        return []
    static = payload.get("static")
    if not isinstance(static, Mapping):
        return []
    lines: list[str] = []
    for kind in KINDS:
        patterns = static.get(kind + "s")
        if not isinstance(patterns, (list, tuple)):
            continue
        extra = [p for p in patterns if isinstance(p, str) and (kind, p) not in shown]
        if not extra:
            continue
        lines.append(f"**{kind}** (homeserver.yaml)")
        lines.extend(f"- `{p}`" for p in sorted(extra))
    return lines


class RoomAuthority:
    """The room's power levels, read the same way the module reads them.

    The arithmetic lives in `policy.py` so the bot and the module can never
    disagree about who may change a rule; this only unwraps mautrix objects
    into the plain dicts that module shares.
    """

    def __init__(self, power_levels: dict[str, Any], create: StateEvent | None) -> None:
        self._power_levels = power_levels
        self._create_sender = str(create.sender) if create is not None else None
        self._create_content = _content_dict(create.content) if create is not None else None

    @classmethod
    def from_state(cls, state: list[StateEvent]) -> "RoomAuthority":
        power_levels: dict[str, Any] = {}
        create: StateEvent | None = None
        for event in state:
            if event.type == EventType.ROOM_POWER_LEVELS:
                power_levels = _content_dict(event.content)
            elif event.type == EventType.ROOM_CREATE:
                create = event
        return cls(power_levels, create)

    def power_of(self, user_id: str) -> int:
        return user_power_level(
            self._power_levels, user_id, self._create_sender, self._create_content
        )

    def needed_for(self, event_type: EventType) -> int:
        return event_power_level(self._power_levels, event_type.t, event_type.is_state)


# --- notice webhook (the module POSTs here when notify_via: bot) -------------

# Mirrors MAX_NOTICES_PER_WINDOW in the module: a leaked secret must not be
# usable to flood the room, even though the module already throttles its own.
NOTIFY_MAX_PER_WINDOW = 20
NOTIFY_WINDOW_S = 300.0
NOTIFY_MAX_BODY = 8192


def parse_notify_request(
    auth_header: str | None, body: bytes, secret: str | None, max_bytes: int = NOTIFY_MAX_BODY
) -> tuple[int, str | None]:
    """Validate a webhook POST. Returns (status, text); text is None on refusal.

    Pure, so it can be tested without maubot's runtime. The endpoint is a sink:
    it accepts a notice or refuses, and reveals nothing either way.
    """
    if not secret:
        return 503, None
    if not auth_header or not auth_header.startswith("Bearer "):
        return 401, None
    if not hmac.compare_digest(auth_header[len("Bearer ") :], secret):
        return 401, None
    if len(body) > max_bytes:
        return 413, None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 400, None
    if not isinstance(payload, dict):
        return 400, None
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        return 400, None
    return 200, text


class GuardianBot(Plugin):
    config: Config

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    _notify_window_started: float = 0.0
    _notify_sent_in_window: int = 0

    async def start(self) -> None:
        self.config.load_and_update()
        if not self.config["control_room"]:
            self.log.error("guardian_bot: control_room is not configured; refusing all commands")

    # --- notice webhook ------------------------------------------------------

    def _notify_allowed(self) -> bool:
        now = time.monotonic()
        if now - self._notify_window_started >= NOTIFY_WINDOW_S:
            self._notify_window_started = now
            self._notify_sent_in_window = 0
        if self._notify_sent_in_window >= NOTIFY_MAX_PER_WINDOW:
            return False
        self._notify_sent_in_window += 1
        return True

    @web.post("/notify")
    async def notify(self, request: aiohttp_web.Request) -> aiohttp_web.Response:
        """Post a notice from the module. Encrypted if the control room is."""
        body = await request.content.read(NOTIFY_MAX_BODY + 1)
        status, text = parse_notify_request(
            request.headers.get("Authorization"), body, self.config["notify_secret"]
        )
        if status != 200 or text is None:
            return aiohttp_web.json_response({}, status=status)
        room = self.control_room
        if room is None:
            return aiohttp_web.json_response({}, status=503)
        if not self._notify_allowed():
            # Drop quietly: answering 200 keeps the module from retrying.
            return aiohttp_web.json_response({})
        try:
            await self.client.send_message(
                room, TextMessageEventContent(msgtype=MessageType.NOTICE, body=text)
            )
        except Exception as e:  # noqa: BLE001
            self.log.warning(f"guardian_bot: could not post notice: {e}")
            return aiohttp_web.json_response({}, status=502)
        return aiohttp_web.json_response({})

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
            state = await self.client.get_state(evt.room_id)
        except Exception as e:  # noqa: BLE001
            await evt.reply(f"Could not read room state: {e}")
            return False
        authority = RoomAuthority.from_state(state)
        needed = authority.needed_for(event_type_for(kind))
        have = authority.power_of(evt.sender)
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
        return entries_from_state(await self.client.get_state(room_id))

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

    @command.new(name="guard", help="guardian rules", require_subcommand=True)
    async def guard(self, evt: MessageEvent) -> None:
        pass

    @guard.subcommand("protect", help="Protect a local user: !guard protect @kid:server [reason]")
    @command.argument("mxid")
    @command.argument("reason", required=False, pass_raw=True)
    async def protect(self, evt: MessageEvent, mxid: str, reason: str | None) -> None:
        if not self.in_control_room(evt):
            return
        mxid = resolve_user_arg(mxid, formatted_body_of(evt))
        if not is_user_id(mxid) or mxid.split(":", 1)[1] != self.server_name:
            await evt.reply(f"`{mxid}` is not a user on {self.server_name}; only local users can be protected.")
            return
        if evt.sender == mxid:
            await evt.reply("Refusing: you are trying to protect yourself. Admins bypass the module's checks.")
            return
        await self.add(evt, KIND_PROTECTED_USER, mxid, reason)

    @guard.subcommand("unprotect", help="Stop protecting a user: !guard unprotect @kid:server")
    @command.argument("mxid")
    async def unprotect(self, evt: MessageEvent, mxid: str) -> None:
        if not self.in_control_room(evt):
            return
        mxid = resolve_user_arg(mxid, formatted_body_of(evt))
        await self.remove(evt, KIND_PROTECTED_USER, mxid)

    @guard.subcommand("allow", help="Allow a server or user: !guard allow server <glob> | !guard allow user <mxid|glob> [reason]")
    @command.argument("what")
    @command.argument("pattern")
    @command.argument("reason", required=False, pass_raw=True)
    async def allow(self, evt: MessageEvent, what: str, pattern: str, reason: str | None) -> None:
        await self._verb(evt, "allow", what, pattern, reason)

    @guard.subcommand("block", help="Block a server or user: !guard block server <glob> | !guard block user <mxid|glob> [reason]")
    @command.argument("what")
    @command.argument("pattern")
    @command.argument("reason", required=False, pass_raw=True)
    async def block(self, evt: MessageEvent, what: str, pattern: str, reason: str | None) -> None:
        await self._verb(evt, "block", what, pattern, reason)

    @guard.subcommand("remove", help="Remove an allow entry: !guard remove server <glob> | !guard remove user <mxid|glob>")
    @command.argument("what")
    @command.argument("pattern")
    async def remove_cmd(self, evt: MessageEvent, what: str, pattern: str) -> None:
        await self._verb(evt, "remove", what, pattern, None)

    @guard.subcommand("unblock", help="Remove a block entry: !guard unblock server <glob> | !guard unblock user <mxid|glob>")
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
        if what == "user":
            pattern = resolve_user_arg(pattern, formatted_body_of(evt))
        if (verb, what) in VERB_KINDS:
            await self.add(evt, VERB_KINDS[(verb, what)], pattern, reason)
        elif (verb, what) in REMOVE_KINDS:
            await self.remove(evt, REMOVE_KINDS[(verb, what)], pattern)
        else:
            await evt.reply(f"Usage: !guard {verb} server|user <pattern>")

    @guard.subcommand("list", help="List all rules")
    async def list_cmd(self, evt: MessageEvent) -> None:
        if not self.in_control_room(evt):
            return
        state: list[StateEvent] = await self.client.get_state(evt.room_id)
        entries = [(k, e, c) for k, e, _, c in entries_from_state(state)]
        payload = published_payload(state)
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
        if not lines:
            lines.append("_No rules set in this room._")
        extra = static_extra_lines(payload, {(k, e) for k, e, _ in entries})
        # Blank line first: Markdown would otherwise fold this into the last bullet.
        if extra:
            lines.append("")
            lines.extend(extra)
        elif payload is None:
            lines.append("")
            lines.append(
                "_Static homeserver.yaml rules also apply but are not shown: the module "
                "has not published `guardian.effective_rules` here (check that "
                "`notify_user` may send that state event)._"
            )
        await evt.reply("\n".join(lines))

    @guard.subcommand("check", help="Would this user be allowed to interact with the kids? !guard check @x:server")
    @command.argument("mxid")
    async def check(self, evt: MessageEvent, mxid: str) -> None:
        if not self.in_control_room(evt):
            return
        mxid = resolve_user_arg(mxid, formatted_body_of(evt))
        if not is_user_id(mxid):
            await evt.reply(f"`{mxid}` is not a user ID.")
            return
        state: list[StateEvent] = await self.client.get_state(evt.room_id)
        payload = published_payload(state)
        if payload is not None:
            # What the module actually enforces, static baseline included.
            rules = RuleSet.from_payload(payload.get("effective"))
            scope = "the rules the module has loaded"
        else:
            entries = entries_from_state(state)
            rules = RuleSet.build([(k, e) for k, e, _, _ in entries], on_invalid=lambda *a: None)
            scope = "room rules only — static homeserver.yaml rules are not included"
        decision = rules.evaluate(mxid)
        verdict = "ALLOWED" if decision.allowed else "BLOCKED"
        await evt.reply(f"`{mxid}`: **{verdict}** (rule: `{decision.reason}`; {scope})")
