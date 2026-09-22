"""Module configuration parsing and validation (homeserver.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from synapse_guardian.policy import (
    ALL_KINDS,
    PLURAL,
    InvalidPattern,
    RuleSet,
    is_user_id,
)

UNINVITED_JOIN_POLICIES = ("deny", "known_rooms")


class ConfigError(ValueError):
    """Invalid module config; raised from parse_config so Synapse refuses to start."""


def _str_list(cfg: dict[str, Any], key: str) -> list[str]:
    value = cfg.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be a list of strings")
    return value


def _opt_str(cfg: dict[str, Any], key: str) -> str | None:
    value = cfg.get(key)
    if value is not None and not isinstance(value, str):
        raise ConfigError(f"{key} must be a string")
    return value


def _bool(cfg: dict[str, Any], key: str, default: bool) -> bool:
    value = cfg.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be a boolean")
    return value


def _number(cfg: dict[str, Any], key: str, default: float) -> float:
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ConfigError(f"{key} must be a non-negative number")
    return float(value)


@dataclass(frozen=True)
class GuardianConfig:
    static_rules: RuleSet
    control_room: str | None = None
    uninvited_joins: str = "known_rooms"
    notify_room: bool = False
    notify_user: str | None = None
    notify_dedupe_s: float = 300.0
    trusted_senders: frozenset[str] = field(default_factory=frozenset)
    refresh_interval_s: float = 15.0
    watch_control_room: bool = False
    strict_local_events: bool = False
    dry_run: bool = False

    @classmethod
    def parse(cls, cfg: dict[str, Any] | None) -> "GuardianConfig":
        cfg = cfg or {}
        if not isinstance(cfg, dict):
            raise ConfigError("module config must be a mapping")

        known = set(PLURAL.values()) | {
            "control_room",
            "uninvited_joins",
            "notify_room",
            "notify_user",
            "notify_dedupe_s",
            "trusted_senders",
            "refresh_interval_s",
            "watch_control_room",
            "strict_local_events",
            "dry_run",
        }
        unknown = set(cfg) - known
        if unknown:
            raise ConfigError(f"unknown config keys: {sorted(unknown)}")

        entries = [
            (kind, pattern) for kind in ALL_KINDS for pattern in _str_list(cfg, PLURAL[kind])
        ]
        try:
            static_rules = RuleSet.build(entries)
        except InvalidPattern as e:
            raise ConfigError(str(e)) from e

        control_room = _opt_str(cfg, "control_room")
        if control_room is not None and not control_room.startswith("!"):
            raise ConfigError("control_room must be a room ID (starting with '!')")

        uninvited_joins = cfg.get("uninvited_joins", "known_rooms")
        if uninvited_joins not in UNINVITED_JOIN_POLICIES:
            raise ConfigError(
                f"uninvited_joins must be one of {UNINVITED_JOIN_POLICIES}, got {uninvited_joins!r}"
            )

        notify_room = _bool(cfg, "notify_room", False)
        notify_user = _opt_str(cfg, "notify_user")
        if notify_user is not None and not is_user_id(notify_user):
            raise ConfigError("notify_user must be a user ID")
        if notify_room:
            if control_room is None:
                raise ConfigError("notify_room requires control_room")
            if notify_user is None:
                raise ConfigError("notify_room requires notify_user")

        trusted = _str_list(cfg, "trusted_senders")
        for sender in trusted:
            if not is_user_id(sender):
                raise ConfigError(f"trusted_senders entry is not a user ID: {sender!r}")
        if notify_user is not None:
            trusted.append(notify_user)

        return cls(
            static_rules=static_rules,
            control_room=control_room,
            uninvited_joins=uninvited_joins,
            notify_room=notify_room,
            notify_user=notify_user,
            notify_dedupe_s=_number(cfg, "notify_dedupe_s", 300),
            trusted_senders=frozenset(s.lower() for s in trusted),
            refresh_interval_s=_number(cfg, "refresh_interval_s", 15),
            watch_control_room=_bool(cfg, "watch_control_room", False),
            strict_local_events=_bool(cfg, "strict_local_events", False),
            dry_run=_bool(cfg, "dry_run", False),
        )
