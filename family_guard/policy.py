"""Pure rule logic for family_guard.

No Synapse imports: this file is shared verbatim with the maubot plugin so
that `!fg check` and the module agree bit for bit.

Evaluation principle: the more specific rule wins; on a tie, block wins.

    1. blocked_users    (glob on full MXID)    -> deny
    2. allowed_users    (glob on full MXID)    -> allow
    3. blocked_servers  (glob on server name)  -> deny
    4. allowed_servers  (glob on server name)  -> allow
    5. default                                 -> deny
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Iterable, Pattern

MAX_PATTERN_LEN = 255

_WILDCARD_RUN = re.compile(r"([\?\*]+)")


def glob_to_regex(glob: str) -> Pattern[str]:
    """Compile a Matrix glob (`*`, `?`) into an anchored, case-insensitive regex.

    Behaviour is identical to `matrix_common.regex.glob_to_regex(glob)`, which
    Synapse itself uses (asserted by `test_glob_matches_matrix_common`). It is
    reimplemented here so this file has no dependency beyond the standard
    library: it is vendored into the maubot plugin, whose runtime has neither
    Synapse nor matrix-common installed.

    Runs of wildcards are collapsed into a single counted repetition
    (`?**?` -> `.{2,}`), which is what keeps matching free of the backtracking
    cliffs a naive `.*.*.*` translation would have.
    """
    chunks: list[str] = []
    for chunk in _WILDCARD_RUN.split(glob):
        if not _WILDCARD_RUN.match(chunk):
            chunks.append(re.escape(chunk))
            continue
        question_marks = chunk.count("?")
        if "*" in chunk:
            chunks.append(".{%d,}" % (question_marks,))
        else:
            chunks.append(".{%d}" % (question_marks,))
    # `\Z` (not `$`) so a trailing newline cannot sneak past the anchor.
    return re.compile(rf"\A({''.join(chunks)})\Z", re.IGNORECASE)

# Matrix caps user IDs at 255 bytes; anything longer cannot be a real MXID.
# Federation hands us unvalidated senders, so bound what we run regexes over.
MAX_SUBJECT_LEN = 255

# `glob_to_regex` turns each wildcard run into `.{n,}`. Several of those in one
# pattern (`*a*a*a*a*b`) backtrack catastrophically against a long non-matching
# subject, which would hang the (single-threaded) Synapse reactor. Real rules
# need one or two wildcards, so cap it.
MAX_WILDCARD_RUNS = 4

KIND_PROTECTED_USER = "protected_user"
KIND_ALLOWED_SERVER = "allowed_server"
KIND_ALLOWED_USER = "allowed_user"
KIND_BLOCKED_USER = "blocked_user"
KIND_BLOCKED_SERVER = "blocked_server"

USER_KINDS = frozenset({KIND_ALLOWED_USER, KIND_BLOCKED_USER})
SERVER_KINDS = frozenset({KIND_ALLOWED_SERVER, KIND_BLOCKED_SERVER})
ALLOW_KINDS = frozenset({KIND_ALLOWED_USER, KIND_ALLOWED_SERVER})
RULE_KINDS = (
    KIND_BLOCKED_USER,
    KIND_ALLOWED_USER,
    KIND_BLOCKED_SERVER,
    KIND_ALLOWED_SERVER,
)
ALL_KINDS = (KIND_PROTECTED_USER,) + RULE_KINDS

# Config keys / room event-type suffixes are the plural of the kind.
PLURAL = {kind: kind + "s" for kind in ALL_KINDS}

# Matrix server names: hostname or IP literal, optional port. Globs allowed.
_SERVER_PATTERN_RE = re.compile(r"^[A-Za-z0-9.\-_*?:\[\]]+$")
_WILDCARDS_RE = re.compile(r"[*?]")
_WILDCARD_RUN_RE = re.compile(r"[*?]+")


class InvalidPattern(ValueError):
    """A user/server pattern that must not be used."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str | None  # "<kind>:<pattern>" of the deciding rule, None = default deny

    @property
    def reason(self) -> str:
        return self.rule or "default-deny"


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: str
    regex: Pattern[str]

    def matches(self, subject: str) -> bool:
        return self.regex.match(subject) is not None

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.pattern}"


# Two unrelated, well-formed subjects per kind. A glob that matches both of
# them matches (practically) every MXID / server name, e.g. `@*:*` or `*.*`.
_CATCH_ALL_PROBES = {
    "user": ("@q:q.q", "@z:z.z"),
    "server": ("q.q", "z.z"),
}


def is_catch_all(pattern: str, kind: str | None = None) -> bool:
    """True if the glob matches every string (`*`, `?*`, `**`), or — when
    `kind` is a user/server kind — every well-formed subject of that kind."""
    if _WILDCARDS_RE.sub("", pattern) == "":
        return True
    probes = _CATCH_ALL_PROBES.get(
        "user" if kind in USER_KINDS else "server" if kind in SERVER_KINDS else ""
    )
    if probes is None:
        return False
    regex = glob_to_regex(pattern)
    return all(regex.match(probe) for probe in probes)


def server_of(user_id: str) -> str:
    """Server part of an MXID. Raises ValueError for malformed IDs."""
    if not user_id.startswith("@") or ":" not in user_id:
        raise ValueError(f"not a user ID: {user_id!r}")
    return user_id.split(":", 1)[1]


def is_user_id(value: str) -> bool:
    """Loose MXID check: `@localpart:server`, no wildcards, no whitespace."""
    return (
        isinstance(value, str)
        and value.startswith("@")
        and ":" in value
        and len(value) <= MAX_PATTERN_LEN
        and value.split() == [value]
        and not _WILDCARDS_RE.search(value)
    )


def validate_pattern(kind: str, pattern: str) -> None:
    """Raise InvalidPattern if `pattern` is not acceptable for `kind`."""
    if not isinstance(pattern, str) or not pattern:
        raise InvalidPattern("empty pattern")
    if len(pattern) > MAX_PATTERN_LEN:
        raise InvalidPattern("pattern longer than 255 characters")
    if pattern.split() != [pattern]:
        raise InvalidPattern("pattern contains whitespace")
    if len(_WILDCARD_RUN_RE.findall(pattern)) > MAX_WILDCARD_RUNS:
        raise InvalidPattern(
            f"pattern has more than {MAX_WILDCARD_RUNS} wildcard groups "
            "(risks catastrophic regex backtracking)"
        )
    if kind in ALLOW_KINDS and is_catch_all(pattern, kind):
        raise InvalidPattern("catch-all pattern is not allowed in an allow list")
    if kind == KIND_PROTECTED_USER:
        if not is_user_id(pattern):
            raise InvalidPattern("protected user must be an exact user ID")
    elif kind in USER_KINDS:
        if not pattern.startswith("@") or ":" not in pattern:
            raise InvalidPattern("user pattern must look like @user:server")
    elif kind in SERVER_KINDS:
        if pattern.startswith("@") or not _SERVER_PATTERN_RE.match(pattern):
            raise InvalidPattern("server pattern must be a server name glob")
    else:
        raise InvalidPattern(f"unknown rule kind {kind!r}")


def compile_rule(kind: str, pattern: str) -> Rule:
    validate_pattern(kind, pattern)
    return Rule(kind=kind, pattern=pattern, regex=glob_to_regex(pattern))


OnInvalid = Callable[[str, str, str], None]  # (kind, pattern, error)


@dataclass(frozen=True)
class RuleSet:
    protected_users: frozenset[str]
    blocked_users: tuple[Rule, ...] = ()
    allowed_users: tuple[Rule, ...] = ()
    blocked_servers: tuple[Rule, ...] = ()
    allowed_servers: tuple[Rule, ...] = ()

    @classmethod
    def build(
        cls,
        entries: Iterable[tuple[str, str]],
        on_invalid: OnInvalid | None = None,
    ) -> "RuleSet":
        """Build from (kind, pattern) pairs.

        Invalid entries are reported through `on_invalid` and skipped; if
        `on_invalid` is None they raise InvalidPattern instead.
        """
        protected: set[str] = set()
        rules: dict[str, list[Rule]] = {kind: [] for kind in RULE_KINDS}
        for kind, pattern in entries:
            try:
                if kind == KIND_PROTECTED_USER:
                    validate_pattern(kind, pattern)
                    protected.add(pattern.lower())
                else:
                    rules[kind].append(compile_rule(kind, pattern))
            except (InvalidPattern, KeyError) as e:
                if on_invalid is None:
                    raise InvalidPattern(f"{kind} {pattern!r}: {e}") from e
                on_invalid(kind, str(pattern), str(e))
        return cls(
            protected_users=frozenset(protected),
            blocked_users=tuple(rules[KIND_BLOCKED_USER]),
            allowed_users=tuple(rules[KIND_ALLOWED_USER]),
            blocked_servers=tuple(rules[KIND_BLOCKED_SERVER]),
            allowed_servers=tuple(rules[KIND_ALLOWED_SERVER]),
        )

    def merge(self, other: "RuleSet") -> "RuleSet":
        return RuleSet(
            protected_users=self.protected_users | other.protected_users,
            blocked_users=self.blocked_users + other.blocked_users,
            allowed_users=self.allowed_users + other.allowed_users,
            blocked_servers=self.blocked_servers + other.blocked_servers,
            allowed_servers=self.allowed_servers + other.allowed_servers,
        )

    def is_protected(self, user_id: str) -> bool:
        """Exact (case-insensitive) match; protected users are never globs."""
        return user_id.lower() in self.protected_users

    def evaluate(self, other_user_id: str) -> Decision:
        """May `other_user_id` interact with a protected user?"""
        if len(other_user_id) > MAX_SUBJECT_LEN:
            # Not a valid MXID; deny without running any regex over it.
            return Decision(False, None)
        try:
            server = server_of(other_user_id)
        except ValueError:
            return Decision(False, None)
        for rule in self.blocked_users:
            if rule.matches(other_user_id):
                return Decision(False, rule.label)
        for rule in self.allowed_users:
            if rule.matches(other_user_id):
                return Decision(True, rule.label)
        for rule in self.blocked_servers:
            if rule.matches(server):
                return Decision(False, rule.label)
        for rule in self.allowed_servers:
            if rule.matches(server):
                return Decision(True, rule.label)
        return Decision(False, None)

    def to_payload(self) -> dict[str, list[str]]:
        """Plain JSON shape, keyed by the plural config/room names."""
        payload = {PLURAL[KIND_PROTECTED_USER]: sorted(self.protected_users)}
        for kind in RULE_KINDS:
            payload[PLURAL[kind]] = [rule.pattern for rule in getattr(self, PLURAL[kind])]
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> "RuleSet":
        """Rebuild from `to_payload`. Anything unparseable is skipped, never fatal."""
        if not isinstance(payload, Mapping):
            return EMPTY
        entries: list[tuple[str, str]] = []
        for kind in ALL_KINDS:
            patterns = payload.get(PLURAL[kind])
            if not isinstance(patterns, (list, tuple)):
                continue
            entries.extend((kind, p) for p in patterns if isinstance(p, str))
        return cls.build(entries, on_invalid=lambda *_: None)

    def entries(self) -> list[tuple[str, str]]:
        """All (kind, pattern) pairs, for listing."""
        out = [(KIND_PROTECTED_USER, u) for u in sorted(self.protected_users)]
        for kind in RULE_KINDS:
            out.extend((kind, r.pattern) for r in getattr(self, PLURAL[kind]))
        return out


EMPTY = RuleSet(protected_users=frozenset())
