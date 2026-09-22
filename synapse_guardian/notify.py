"""Posting blocked actions into the control room."""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Identifiers reaching us from federation are unvalidated at the point we log
# them, so strip anything that could forge a log line or notice.
_UNSAFE_CHARS_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]")
_MAX_ID_LEN = 255

# An invite flood from many distinct senders bypasses per-(kind, actor, target)
# dedupe, so bound both the memory and the number of events we persist.
MAX_RECENT = 512
MAX_NOTICES_PER_WINDOW = 20


def sanitise(value: str) -> str:
    """Make an attacker-influenced identifier safe to put in a log line/notice."""
    if not isinstance(value, str):
        value = repr(value)
    if len(value) > _MAX_ID_LEN:
        value = value[:_MAX_ID_LEN] + "...(truncated)"
    return _UNSAFE_CHARS_RE.sub("?", value)


def format_block(
    kind: str, actor: str, target: str, room_id: str | None, rule: str, dry_run: bool
) -> str:
    prefix = "[dry-run] would block" if dry_run else "blocked"
    where = f" in {sanitise(room_id)}" if room_id else ""
    return (
        f"guardian: {prefix} {sanitise(kind)} {sanitise(actor)} -> "
        f"{sanitise(target)}{where} (reason: {sanitise(rule)})"
    )


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
        self._window_started = 0.0
        self._sent_in_window = 0
        self._suppressed = 0

    def _should_send(self, key: tuple[str, str, str]) -> bool:
        now = self._clock()
        # prune expired entries on insert; the dict stays tiny in practice
        self._recent = {k: t for k, t in self._recent.items() if now - t < self._dedupe_s}
        if key in self._recent:
            return False

        if now - self._window_started >= self._dedupe_s:
            if self._suppressed:
                logger.warning(
                    "guardian: suppressed %d notices in the last %.0fs "
                    "(cap %d per window)",
                    self._suppressed,
                    self._dedupe_s,
                    MAX_NOTICES_PER_WINDOW,
                )
            self._window_started = now
            self._sent_in_window = 0
            self._suppressed = 0

        if self._sent_in_window >= MAX_NOTICES_PER_WINDOW:
            # A flood from many distinct senders: keep logging, stop persisting
            # events into the control room.
            self._suppressed += 1
            return False

        if len(self._recent) >= MAX_RECENT:
            oldest = min(self._recent, key=self._recent.__getitem__)
            del self._recent[oldest]

        self._recent[key] = now
        self._sent_in_window += 1
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
                "guardian: could not post notice to %s as %s (is %s joined?)",
                self._room_id,
                self._sender,
                self._sender,
            )
