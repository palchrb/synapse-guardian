"""PolicyStore: merges static config rules with control-room state, with caching.

The `api` object only needs a small surface, so tests can pass a fake:

    api.server_name: str
    api.is_mine(user_id) -> bool
    async api.is_user_admin(user_id) -> bool
    async api.get_room_state(room_id, event_filter) -> {(type, state_key): event}

Events need `.type`, `.state_key`, `.sender`, `.content`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

from synapse_guardian.config import GuardianConfig
from synapse_guardian.policy import (
    ALL_KINDS,
    RuleSet,
    event_power_level,
    user_power_level,
)

logger = logging.getLogger(__name__)

EVENT_TYPE_PREFIX = "guardian."
EVENT_TYPES: dict[str, str] = {EVENT_TYPE_PREFIX + kind: kind for kind in ALL_KINDS}

POWER_LEVELS_TYPE = "m.room.power_levels"
CREATE_TYPE = "m.room.create"


class StoreApi(Protocol):
    @property
    def server_name(self) -> str: ...

    def is_mine(self, id: str) -> bool: ...

    async def is_user_admin(self, user_id: str) -> bool: ...

    async def get_room_state(
        self, room_id: str, event_filter: Any = None
    ) -> dict[tuple[str, str], Any]: ...


class PolicyStore:
    def __init__(
        self,
        api: StoreApi,
        config: GuardianConfig,
        clock: Callable[[], float] = time.monotonic,
        on_admin_protected: Callable[[str], Awaitable[None]] | None = None,
        on_rules_loaded: Callable[[RuleSet], None] | None = None,
    ) -> None:
        self._api = api
        self._config = config
        self._clock = clock
        self._on_admin_protected = on_admin_protected
        self._on_rules_loaded = on_rules_loaded
        self.control_room: str | None = config.control_room
        self._rules: RuleSet | None = None
        self._loaded_at: float = 0.0
        self._stale = True
        self._warned_admins: set[str] = set()

    @staticmethod
    def is_our_event_type(event_type: str) -> bool:
        return event_type in EVENT_TYPES

    def invalidate(self) -> None:
        self._stale = True

    @property
    def cached(self) -> RuleSet | None:
        """Last loaded rules without triggering a refresh (None before first load)."""
        return self._rules

    async def get_rules(self) -> RuleSet:
        """Return the current rule set, refreshing lazily on staleness or TTL."""
        expired = self._clock() - self._loaded_at >= self._config.refresh_interval_s
        if self._rules is None or self._stale or expired:
            await self.refresh()
        assert self._rules is not None
        return self._rules

    async def refresh(self) -> RuleSet:
        """Re-read the control room. On failure keep the previous rules (or static only)."""
        static = self._config.static_rules
        if self.control_room is None:
            rules = static
        else:
            try:
                room_rules = await self._read_control_room(self.control_room)
                rules = static.merge(room_rules)
            except Exception:
                logger.exception(
                    "guardian: failed to read control room %s; keeping %s rules",
                    self.control_room,
                    "previous" if self._rules is not None else "static-only",
                )
                rules = self._rules if self._rules is not None else static
        self._rules = rules
        self._loaded_at = self._clock()
        self._stale = False
        await self._check_admins(rules)
        if self._on_rules_loaded is not None:
            # Must not block the callback that triggered this refresh.
            try:
                self._on_rules_loaded(rules)
            except Exception:
                logger.exception("guardian: rules-loaded hook failed")
        return rules

    async def _read_control_room(self, room_id: str) -> RuleSet:
        state = await self._api.get_room_state(
            room_id,
            [(event_type, None) for event_type in EVENT_TYPES]
            + [(POWER_LEVELS_TYPE, ""), (CREATE_TYPE, "")],
        )
        authority = _RoomAuthority.from_state(state, room_id)
        entries: list[tuple[str, str]] = []
        trust_cache: dict[str, _SenderPower] = {}
        for (event_type, state_key), event in state.items():
            kind = EVENT_TYPES.get(event_type)
            if kind is None:
                continue
            content = event.content
            if not isinstance(content, Mapping) or not content:
                continue  # empty content = removed (Rust-backed events are Mappings, not dicts)
            sender = event.sender
            if sender not in trust_cache:
                trust_cache[sender] = await self._sender_power(sender, authority)
            refused = trust_cache[sender].refuse(event_type, authority)
            if refused is not None:
                logger.warning(
                    "guardian: ignoring %s %r in %s from %s (%s)",
                    kind,
                    state_key,
                    room_id,
                    sender,
                    refused,
                )
                continue
            # The entity lives in content["entity"]; state keys cannot start with
            # "@" unless the sender is that user (auth rules), so the bot writes
            # user entities without the leading "@" in the state key.
            entity = content.get("entity", state_key)
            if not isinstance(entity, str):
                logger.warning(
                    "guardian: ignoring %s %r in %s: entity is not a string", kind, state_key, room_id
                )
                continue
            entries.append((kind, entity))

        def on_invalid(kind: str, pattern: str, error: str) -> None:
            logger.warning(
                "guardian: ignoring invalid %s %r in %s: %s", kind, pattern, room_id, error
            )

        return RuleSet.build(entries, on_invalid=on_invalid)

    async def _sender_power(self, sender: str, authority: "_RoomAuthority") -> "_SenderPower":
        """How much this sender is allowed to say about the rules.

        The room's power levels are the authority: Synapse already refused to
        persist the event otherwise, so re-deciding it here could only ever
        reject someone the room had allowed. Server admins are honoured on top,
        and are the only route left if the power levels cannot be read.
        """
        if not isinstance(sender, str) or not self._api.is_mine(sender):
            return _SenderPower(local=False)
        try:
            if await self._api.is_user_admin(sender):
                return _SenderPower(local=True, always=True)
        except Exception:
            logger.exception("guardian: could not check admin status of %s", sender)
        return _SenderPower(local=True, power=authority.power_of(sender))

    async def _check_admins(self, rules: RuleSet) -> None:
        """Protected users must not be server admins (admins bypass the checks)."""
        for user_id in sorted(rules.protected_users):
            try:
                is_admin = await self._api.is_user_admin(user_id)
            except Exception:
                logger.exception("guardian: could not check admin status of %s", user_id)
                continue
            if not is_admin:
                self._warned_admins.discard(user_id)
                continue
            if user_id in self._warned_admins:
                continue
            self._warned_admins.add(user_id)
            logger.error(
                "guardian: protected user %s is a server admin; Synapse skips "
                "invite/join checks for admins, so this user is NOT protected",
                user_id,
            )
            if self._on_admin_protected is not None:
                try:
                    await self._on_admin_protected(user_id)
                except Exception:
                    logger.exception("guardian: admin-protected notification failed")


@dataclass(frozen=True)
class _SenderPower:
    """What a control-room sender is allowed to change, decided once per refresh."""

    local: bool
    always: bool = False  # server admin: allowed whatever the room says
    power: int = 0

    def refuse(self, event_type: str, authority: "_RoomAuthority") -> str | None:
        """None if this sender may send `event_type`, else why not."""
        if not self.local:
            return "not a local user"
        if self.always:
            return None
        if not authority.readable:
            return "power levels unreadable, and not a server admin"
        needed = authority.needed_for(event_type)
        if self.power >= needed:
            return None
        return f"power {self.power}, needs {needed} for {event_type}"


@dataclass(frozen=True)
class _RoomAuthority:
    """The control room's power levels, which decide who may manage rules."""

    readable: bool
    power_levels: Mapping[str, Any] | None = None
    create_sender: str | None = None
    create_content: Mapping[str, Any] | None = None

    @classmethod
    def from_state(cls, state: Mapping[tuple[str, str], Any], room_id: str) -> "_RoomAuthority":
        levels = state.get((POWER_LEVELS_TYPE, ""))
        create = state.get((CREATE_TYPE, ""))
        content = getattr(levels, "content", None)
        if not isinstance(content, Mapping):
            logger.warning(
                "guardian: no readable %s in %s; only server admins may manage rules",
                POWER_LEVELS_TYPE,
                room_id,
            )
            return cls(readable=False)
        create_content = getattr(create, "content", None)
        return cls(
            readable=True,
            power_levels=content,
            create_sender=getattr(create, "sender", None),
            create_content=create_content if isinstance(create_content, Mapping) else None,
        )

    def power_of(self, user_id: str) -> int:
        return user_power_level(
            self.power_levels, user_id, self.create_sender, self.create_content
        )

    def needed_for(self, event_type: str) -> int:
        return event_power_level(self.power_levels, event_type)
