"""Publishing the rule set the module actually loaded into the control room.

The maubot plugin is an ordinary Matrix client: it can read the rule state
events it wrote itself, but it cannot see `homeserver.yaml`. So `!fg list` and
`!fg check` were blind to the static baseline. The module publishes a single
`family_guard.effective_rules` state event describing what it really has, and
the bot reads that.

Written only when the content changes. `updated_ts` moves on every refresh, so
Synapse's own state-event deduplication would never fire; the comparison here
is what keeps the room quiet.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any, Callable, Protocol

from family_guard.policy import RuleSet

logger = logging.getLogger(__name__)

EFFECTIVE_RULES_TYPE = "family_guard.effective_rules"


class Publisher(Protocol):
    async def publish(
        self, static: RuleSet, effective: RuleSet, dry_run: bool, uninvited_joins: str
    ) -> None: ...


class NullPublisher:
    async def publish(
        self, static: RuleSet, effective: RuleSet, dry_run: bool, uninvited_joins: str
    ) -> None:
        return None


class RoomPublisher:
    """Keeps `family_guard.effective_rules` in the control room up to date.

    Sent as `sender`, who must be a local user joined to the room and able to
    send this state event type. A failure (usually too low a power level) is
    logged once and never affects an enforcement decision.
    """

    def __init__(
        self,
        api: Any,
        room_id: str,
        sender: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._api = api
        self._room_id = room_id
        self._sender = sender
        self._clock = clock
        self._last: dict[str, Any] | None = None
        self._primed = False
        self._warned = False

    async def publish(
        self, static: RuleSet, effective: RuleSet, dry_run: bool, uninvited_joins: str
    ) -> None:
        payload = {
            "static": static.to_payload(),
            "effective": effective.to_payload(),
            "dry_run": dry_run,
            "uninvited_joins": uninvited_joins,
        }
        if not self._primed:
            # A restart must not rewrite an identical event.
            self._last = await self._published()
            self._primed = True
        if self._last == payload:
            return
        try:
            await self._api.create_and_send_event_into_room(
                {
                    "type": EFFECTIVE_RULES_TYPE,
                    "state_key": "",
                    "room_id": self._room_id,
                    "sender": self._sender,
                    "content": {**payload, "updated_ts": int(self._clock() * 1000)},
                }
            )
        except Exception as e:  # noqa: BLE001
            if not self._warned:
                self._warned = True
                logger.warning(
                    "family_guard: cannot publish %s into %s as %s (%s); "
                    "grant that user power to send %s (50 in the room's "
                    "m.room.power_levels 'events' map). The bot will keep "
                    "showing room rules only.",
                    EFFECTIVE_RULES_TYPE,
                    self._room_id,
                    self._sender,
                    e,
                    EFFECTIVE_RULES_TYPE,
                )
            return
        self._warned = False
        self._last = payload

    async def _published(self) -> dict[str, Any] | None:
        """The payload currently in the room, or None if absent/unreadable."""
        try:
            state = await self._api.get_room_state(
                self._room_id, [(EFFECTIVE_RULES_TYPE, "")]
            )
        except Exception:
            logger.exception(
                "family_guard: could not read %s from %s", EFFECTIVE_RULES_TYPE, self._room_id
            )
            return None
        event = state.get((EFFECTIVE_RULES_TYPE, ""))
        if event is None or not isinstance(event.content, Mapping) or not event.content:
            return None
        return {k: v for k, v in event.content.items() if k != "updated_ts"}
