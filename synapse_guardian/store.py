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
from typing import Any, Awaitable, Callable, Protocol

from synapse_guardian.config import GuardianConfig
from synapse_guardian.policy import ALL_KINDS, RuleSet

logger = logging.getLogger(__name__)

EVENT_TYPE_PREFIX = "guardian."
EVENT_TYPES: dict[str, str] = {EVENT_TYPE_PREFIX + kind: kind for kind in ALL_KINDS}


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
            room_id, [(event_type, None) for event_type in EVENT_TYPES]
        )
        entries: list[tuple[str, str]] = []
        trust_cache: dict[str, bool] = {}
        for (event_type, state_key), event in state.items():
            kind = EVENT_TYPES.get(event_type)
            if kind is None:
                continue
            content = event.content
            if not isinstance(content, Mapping) or not content:
                continue  # empty content = removed (Rust-backed events are Mappings, not dicts)
            sender = event.sender
            if sender not in trust_cache:
                trust_cache[sender] = await self._is_trusted(sender)
            if not trust_cache[sender]:
                logger.warning(
                    "guardian: ignoring %s %r in %s from untrusted sender %s",
                    kind,
                    state_key,
                    room_id,
                    sender,
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

    async def _is_trusted(self, sender: str) -> bool:
        if not isinstance(sender, str) or not self._api.is_mine(sender):
            return False
        if sender.lower() in self._config.trusted_senders:
            return True
        try:
            return bool(await self._api.is_user_admin(sender))
        except Exception:
            logger.exception("guardian: could not check admin status of %s", sender)
            return False

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
