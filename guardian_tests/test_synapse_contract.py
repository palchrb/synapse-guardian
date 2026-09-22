"""Pins the assumptions `docs/callbacks.md` records about Synapse's module API.

These tests do not exercise our logic; they fail when a Synapse upgrade moves
the ground underneath it. Every failure message names the assumption and points
back at the doc, because the fix is always "re-read the source, then update both
the doc and the code".
"""

from __future__ import annotations

import inspect
from typing import Any, Callable

import synapse
from synapse.module_api import NOT_SPAM, ModuleApi
from synapse.module_api.callbacks import spamchecker_callbacks
from synapse.module_api.errors import Codes

from synapse_guardian.module import Guardian

DOC = "docs/callbacks.md"

VERIFIED_AGAINST = "1.161.0"

# Callback -> number of positional arguments the dispatcher passes.
# Sources are cited per row in docs/callbacks.md.
SPAM_CHECKER_ARITY = {
    "user_may_invite": 3,
    "federated_user_may_invite": 1,
    "user_may_send_3pid_invite": 4,
    "user_may_join_room": 3,
    "user_may_publish_room": 2,
    "user_may_create_room_alias": 2,
    "user_may_send_state_event": 5,
}

THIRD_PARTY_ARITY = {
    "check_event_allowed": 2,
    "on_new_event": 2,
}


def _positional_arity(func: Callable[..., Any]) -> int:
    """Positional parameters of a bound method, excluding self."""
    params = inspect.signature(func).parameters.values()
    return sum(
        1
        for p in params
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    )


def test_synapse_version_matches_the_doc() -> None:
    """Not a failure in itself -- it tells you the doc's citations are stale."""
    version = synapse.__version__.split(" ")[0]
    assert version == VERIFIED_AGAINST, (
        f"Synapse is {version}, but {DOC} was verified against {VERIFIED_AGAINST}. "
        f"Re-verify the file:line citations in {DOC}, then update VERIFIED_AGAINST. "
        "The other tests in this file cover the mechanical assumptions; parameter "
        "*order* is not machine-checkable and needs a human read."
    )


def test_registered_callback_names_are_accepted_by_synapse() -> None:
    """A name Synapse dropped or renamed is a TypeError at module load.

    This is how maunium's synapse-http-antispam breaks on upstream Synapse when
    `enabled_callbacks` is unset: it passes `accept_make_join`, which only
    exists in a fork.
    """
    for register, expected in (
        (ModuleApi.register_spam_checker_callbacks, SPAM_CHECKER_ARITY),
        (ModuleApi.register_third_party_rules_callbacks, THIRD_PARTY_ARITY),
    ):
        accepted = set(inspect.signature(register).parameters)
        missing = set(expected) - accepted
        assert not missing, (
            f"Synapse's {register.__name__} no longer accepts {sorted(missing)}. "
            f"Registering them raises TypeError and the module will not load. "
            f"See {DOC}."
        )


def test_our_callbacks_accept_the_arity_synapse_passes() -> None:
    """Dispatchers call positionally, so arity is load-bearing.

    Parameter *order* cannot be checked mechanically -- see the open questions
    in the doc.
    """
    for name, arity in {**SPAM_CHECKER_ARITY, **THIRD_PARTY_ARITY}.items():
        method = getattr(Guardian, name, None)
        assert method is not None, (
            f"Guardian.{name} is gone but {DOC} still lists it as used."
        )
        # Unbound here, so self counts as one positional parameter.
        actual = _positional_arity(method) - 1
        assert actual == arity, (
            f"Guardian.{name} takes {actual} positional args but Synapse "
            f"passes {arity}. See the signature table in {DOC}."
        )


def test_synapse_type_aliases_still_declare_that_arity() -> None:
    """Cross-check our arity table against Synapse's own type aliases.

    Catches the case where Synapse changes a signature and we update our method
    to match without noticing the doc is now wrong.
    """
    for name, arity in SPAM_CHECKER_ARITY.items():
        alias = getattr(spamchecker_callbacks, f"{name.upper()}_CALLBACK", None)
        if alias is None or not hasattr(alias, "__args__"):
            continue  # union alias (e.g. back-compat variants); not machine-checkable
        declared = len(alias.__args__[:-1])
        assert declared == arity, (
            f"Synapse declares {name} with {declared} args, our table says "
            f"{arity}. Re-read the dispatcher and update {DOC}."
        )


def test_dispatchers_do_not_catch_callback_exceptions() -> None:
    """Our callbacks must never raise; this is why.

    If Synapse ever starts catching, the `try/except` in every Guardian
    callback becomes belt-and-braces rather than load-bearing -- worth knowing,
    but do not remove them on the strength of this test alone.
    """
    source = inspect.getsource(spamchecker_callbacks)
    assert "except Exception" not in source, (
        "Synapse's spam-checker dispatchers now catch exceptions. "
        f"{DOC} states they do not; update it."
    )


def test_not_spam_and_forbidden_behave_as_our_code_assumes() -> None:
    """`_block` returns one of these two and compares NOT_SPAM by identity."""
    assert NOT_SPAM == "NOT_SPAM", (
        f"NOT_SPAM is no longer the string 'NOT_SPAM'; see {DOC}."
    )
    assert NOT_SPAM is spamchecker_callbacks.SpamCheckerModuleApiCallbacks.NOT_SPAM, (
        "The exported NOT_SPAM is not the sentinel the dispatcher compares "
        f"against; our callbacks' return values would stop being recognised. See {DOC}."
    )
    assert isinstance(Codes.FORBIDDEN, Codes)
    assert Codes.FORBIDDEN.value == "M_FORBIDDEN", (
        f"Codes.FORBIDDEN changed value; clients will see a different errcode. See {DOC}."
    )


def test_bare_codes_return_is_still_normalised_by_the_dispatcher() -> None:
    """We return a bare `Codes`, not `(Codes, {})`; the dispatcher must accept it."""
    source = inspect.getsource(spamchecker_callbacks.SpamCheckerModuleApiCallbacks.user_may_invite)
    assert "isinstance(res, synapse.api.errors.Codes)" in source, (
        "The dispatcher no longer normalises a bare Codes return value. "
        f"Guardian._block returns one. See {DOC}."
    )
