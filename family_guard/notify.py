"""Notification sinks for blocked actions.

`Notifier` is a tiny interface so that other transports (e.g. a webhook to the
maubot plugin, `notify_via: bot`) can be dropped in later without touching the
module logic. v1 ships `RoomNotifier` (server-side m.notice into the control
room) and `NullNotifier`.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Protocol

logger = logging.getLogger(__name__)


class Notifier(Protocol):
    async def notify(
        self,
        kind: str,
        actor: str,
        target: str,
        room_id: str | None,
        rule: str,
        dry_run: bool,
    ) -> None: ...

    async def message(self, text: str) -> None: ...


class NullNotifier:
    async def notify(
        self,
        kind: str,
        actor: str,
        target: str,
        room_id: str | None,
        rule: str,
        dry_run: bool,
    ) -> None:
        return None

    async def message(self, text: str) -> None:
        return None


def format_block(
    kind: str, actor: str, target: str, room_id: str | None, rule: str, dry_run: bool
) -> str:
    prefix = "[dry-run] would block" if dry_run else "blocked"
    where = f" in {room_id}" if room_id else ""
    return f"family_guard: {prefix} {kind} {actor} -> {target}{where} (reason: {rule})"


class RoomNotifier:
    """Posts m.notice events into the control room as `notify_user`.

    `create_and_send_event_into_room` requires the sender to be a local user
    already joined to the room. Notices are deduplicated per
    (kind, actor, target) for `dedupe_s`.
    """

    def __init__(
        self,
        api: Any,
        room_id: str,
        sender: str,
        dedupe_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api = api
        self._room_id = room_id
        self._sender = sender
        self._dedupe_s = dedupe_s
        self._clock = clock
        self._recent: dict[tuple[str, str, str], float] = {}

    def _should_send(self, key: tuple[str, str, str]) -> bool:
        now = self._clock()
        # prune expired entries on insert; the dict stays tiny in practice
        self._recent = {k: t for k, t in self._recent.items() if now - t < self._dedupe_s}
        if key in self._recent:
            return False
        self._recent[key] = now
        return True

    async def notify(
        self,
        kind: str,
        actor: str,
        target: str,
        room_id: str | None,
        rule: str,
        dry_run: bool,
    ) -> None:
        if not self._should_send((kind, actor, target)):
            return
        await self.message(format_block(kind, actor, target, room_id, rule, dry_run))

    async def message(self, text: str) -> None:
        try:
            await self._api.create_and_send_event_into_room(
                {
                    "type": "m.room.message",
                    "room_id": self._room_id,
                    "sender": self._sender,
                    "content": {"msgtype": "m.notice", "body": text},
                }
            )
        except Exception:
            logger.exception(
                "family_guard: could not post notice to %s as %s (is %s joined?)",
                self._room_id,
                self._sender,
                self._sender,
            )
