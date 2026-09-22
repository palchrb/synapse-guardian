import time

import pytest

from synapse_guardian.policy import (
    MAX_SUBJECT_LEN,
    KIND_ALLOWED_SERVER,
    KIND_ALLOWED_USER,
    KIND_BLOCKED_SERVER,
    KIND_BLOCKED_USER,
    KIND_PROTECTED_USER,
    Decision,
    glob_to_regex,
    InvalidPattern,
    RuleSet,
    is_catch_all,
    validate_pattern,
)


def build(**lists: list[str]) -> RuleSet:
    entries = [(kind, p) for kind, patterns in lists.items() for p in patterns]
    return RuleSet.build(entries)


def test_default_deny() -> None:
    assert build().evaluate("@x:anywhere.org") == Decision(False, None)
    assert build().evaluate("@x:anywhere.org").reason == "default-deny"


def test_allowed_server_exact() -> None:
    rs = build(allowed_server=["friends.org"])
    assert rs.evaluate("@a:friends.org") == Decision(True, "allowed_server:friends.org")
    assert rs.evaluate("@a:notfriends.org").allowed is False


def test_allowed_server_glob() -> None:
    rs = build(allowed_server=["*.skole.no"])
    assert rs.evaluate("@a:a.skole.no").allowed
    assert not rs.evaluate("@a:skole.no").allowed


def test_allowed_user_beats_blocked_server() -> None:
    rs = build(allowed_user=["@granny:bad.org"], blocked_server=["bad.org"])
    assert rs.evaluate("@granny:bad.org") == Decision(True, "allowed_user:@granny:bad.org")
    assert rs.evaluate("@other:bad.org") == Decision(False, "blocked_server:bad.org")


def test_blocked_user_beats_allowed_server() -> None:
    rs = build(allowed_server=["friends.org"], blocked_user=["@troll:friends.org"])
    assert rs.evaluate("@troll:friends.org") == Decision(False, "blocked_user:@troll:friends.org")
    assert rs.evaluate("@nice:friends.org").allowed


def test_blocked_server_is_exception_to_allowed_glob() -> None:
    rs = build(allowed_server=["*.skole.no"], blocked_server=["evil.skole.no"])
    assert rs.evaluate("@a:evil.skole.no") == Decision(False, "blocked_server:evil.skole.no")
    assert rs.evaluate("@a:ok.skole.no").allowed


def test_blocked_user_beats_allowed_user_on_tie() -> None:
    rs = build(allowed_user=["@x:a.org"], blocked_user=["@x:a.org"])
    assert not rs.evaluate("@x:a.org").allowed


def test_case_insensitive_server() -> None:
    rs = build(allowed_server=["Friends.ORG"])
    assert rs.evaluate("@a:friends.org").allowed
    assert rs.evaluate("@a:FRIENDS.org").allowed


def test_case_insensitive_user() -> None:
    rs = build(allowed_user=["@Bob:x.org"])
    assert rs.evaluate("@bob:x.org").allowed


def test_server_with_port_not_matched_by_bare_glob() -> None:
    rs = build(allowed_server=["ex.org"])
    assert not rs.evaluate("@a:ex.org:8448").allowed
    assert build(allowed_server=["ex.org:8448"]).evaluate("@a:ex.org:8448").allowed


def test_star_matches_everything_in_block_list() -> None:
    rs = build(blocked_server=["*"], allowed_user=["@granny:x.org"])
    assert not rs.evaluate("@a:anything.org").allowed
    assert rs.evaluate("@granny:x.org").allowed


@pytest.mark.parametrize("pattern", ["*", "?*", "**", "???"])
def test_is_catch_all_glob(pattern: str) -> None:
    assert is_catch_all(pattern)


@pytest.mark.parametrize("pattern", ["*.org", "@*:x.org", "a?b"])
def test_is_not_catch_all_glob(pattern: str) -> None:
    assert not is_catch_all(pattern)


@pytest.mark.parametrize("kind", [KIND_ALLOWED_SERVER, KIND_ALLOWED_USER])
def test_catch_all_rejected_in_allow_lists(kind: str) -> None:
    with pytest.raises(InvalidPattern):
        validate_pattern(kind, "*")


def test_catch_all_accepted_in_block_lists() -> None:
    validate_pattern(KIND_BLOCKED_SERVER, "*")
    validate_pattern(KIND_BLOCKED_USER, "@*:*")


@pytest.mark.parametrize("pattern", ["@*", "*:*", "@*:*", "*.*", "@?*:*"])
def test_effective_catch_all_user_glob_rejected_in_allow_list(pattern: str) -> None:
    # Not literally "*", but matches every well-formed MXID.
    with pytest.raises(InvalidPattern):
        validate_pattern(KIND_ALLOWED_USER, pattern)


@pytest.mark.parametrize("pattern", ["*.*", "*?.*", "?*"])
def test_effective_catch_all_server_glob_rejected_in_allow_list(pattern: str) -> None:
    with pytest.raises(InvalidPattern):
        validate_pattern(KIND_ALLOWED_SERVER, pattern)


@pytest.mark.parametrize(
    "kind, pattern",
    [
        (KIND_ALLOWED_USER, "@*:friends.org"),
        (KIND_ALLOWED_USER, "@*e*:*"),
        (KIND_ALLOWED_SERVER, "*.skole.no"),
        (KIND_ALLOWED_SERVER, "*e*"),
        (KIND_BLOCKED_USER, "@*:*"),
        (KIND_BLOCKED_SERVER, "*.*"),
    ],
)
def test_narrow_globs_and_block_lists_accepted(kind: str, pattern: str) -> None:
    validate_pattern(kind, pattern)


def test_pattern_over_255_ignored() -> None:
    long = "a" * 256 + ".org"
    seen: list[tuple[str, str, str]] = []
    rs = RuleSet.build([(KIND_ALLOWED_SERVER, long)], on_invalid=lambda k, p, e: seen.append((k, p, e)))
    assert rs.allowed_servers == ()
    assert seen and seen[0][0] == KIND_ALLOWED_SERVER


@pytest.mark.parametrize(
    "kind,pattern",
    [
        (KIND_ALLOWED_SERVER, "friends org"),
        (KIND_ALLOWED_SERVER, "@friends.org"),
        (KIND_ALLOWED_SERVER, ""),
        (KIND_ALLOWED_USER, "@x"),
        (KIND_ALLOWED_USER, "not-a-user"),
        (KIND_BLOCKED_USER, "friends.org"),
        (KIND_PROTECTED_USER, "@kid*:x.org"),
        (KIND_PROTECTED_USER, "x.org"),
        ("bogus_kind", "x.org"),
    ],
)
def test_invalid_entries_skipped(kind: str, pattern: str) -> None:
    seen: list[str] = []
    rs = RuleSet.build([(kind, pattern)], on_invalid=lambda k, p, e: seen.append(e))
    assert rs.entries() == []
    assert len(seen) == 1


def test_invalid_entries_raise_without_handler() -> None:
    with pytest.raises(InvalidPattern):
        RuleSet.build([(KIND_ALLOWED_USER, "nope")])


def test_is_protected_exact_only() -> None:
    rs = build(protected_user=["@kid:x.org"])
    assert rs.is_protected("@kid:x.org")
    assert rs.is_protected("@KID:x.org")
    assert not rs.is_protected("@kid2:x.org")
    assert not rs.is_protected("@kid:x.org.evil")


def test_malformed_subject_is_denied() -> None:
    rs = build(allowed_server=["x.org"], blocked_server=["*"])
    assert rs.evaluate("garbage") == Decision(False, None)


def test_merge_is_union() -> None:
    a = build(protected_user=["@a:x.org"], allowed_server=["x.org"])
    b = build(protected_user=["@b:x.org"], blocked_user=["@t:x.org"])
    m = a.merge(b)
    assert m.is_protected("@a:x.org") and m.is_protected("@b:x.org")
    assert not m.evaluate("@t:x.org").allowed
    assert m.evaluate("@ok:x.org").allowed


def test_entries_lists_everything() -> None:
    rs = build(protected_user=["@a:x.org"], allowed_server=["x.org"], blocked_user=["@t:x.org"])
    assert rs.entries() == [
        (KIND_PROTECTED_USER, "@a:x.org"),
        (KIND_BLOCKED_USER, "@t:x.org"),
        (KIND_ALLOWED_SERVER, "x.org"),
    ]


def test_glob_matches_matrix_common() -> None:
    """Our stdlib glob_to_regex must behave exactly like the one Synapse uses.

    `policy.py` is vendored into the maubot plugin, whose runtime has no
    matrix-common, so we reimplement it -- and pin that to the original here.
    """
    from matrix_common.regex import glob_to_regex as reference

    globs = [
        "", "a", "*", "?", "??", "?*", "*?", "**", "*?*", "?**?**?",
        "a*b", "*.x.no", "x.no", "@a:b", "@*:*", "*.*", "[*]", "\\*",
        "EXAMPLE.ORG", "ex.org:8448", "a?c", "*-*",
    ]
    subjects = [
        "", "a", "ab", "abc", "a.x.no", "x.no", "@a:b", "@bob:x.no",
        "A.X.NO", "example.org", "ex.org:8448", "[q]", "*", "\\x",
        "a\nb", "a\n", "\n", "a-b", "..", "?",
    ]
    for glob in globs:
        ours = glob_to_regex(glob)
        theirs = reference(glob)
        for subject in subjects:
            assert bool(ours.match(subject)) == bool(theirs.match(subject)), (
                f"{glob!r} vs {subject!r}"
            )


# --- ReDoS guards: a pattern must never be able to hang the reactor ---------


def test_pattern_with_many_wildcard_groups_rejected() -> None:
    with pytest.raises(InvalidPattern, match="wildcard groups"):
        validate_pattern(KIND_ALLOWED_SERVER, "*a*a*a*a*b")
    with pytest.raises(InvalidPattern, match="wildcard groups"):
        validate_pattern(KIND_BLOCKED_USER, "@*a*a*a*a*b:x.org")


def test_ordinary_patterns_still_accepted() -> None:
    validate_pattern(KIND_ALLOWED_SERVER, "*.skole.no")
    validate_pattern(KIND_ALLOWED_SERVER, "venner.no")
    validate_pattern(KIND_BLOCKED_SERVER, "*.*.*.*")
    validate_pattern(KIND_ALLOWED_USER, "@granny*:other.org")


def test_oversized_subject_denied_without_matching() -> None:
    rs = build(allowed_server=["*.venner.no"])
    started = time.perf_counter()
    decision = rs.evaluate("@" + "a" * 300 + ":sub.venner.no")
    assert decision == Decision(False, None)
    assert time.perf_counter() - started < 1.0


def test_subject_at_length_limit_still_evaluated() -> None:
    rs = build(allowed_server=["venner.no"])
    user = "@" + "a" * (MAX_SUBJECT_LEN - len("@:venner.no")) + ":venner.no"
    assert len(user) == MAX_SUBJECT_LEN
    assert rs.evaluate(user).allowed
