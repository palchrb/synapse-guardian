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


# --- assumptions recorded in docs/workers.md --------------------------------

WORKERS_DOC = "docs/workers.md"


def test_replication_client_still_retries_connect_errors_then_gives_up() -> None:
    """Our start-up retry ladder is layered on top of this one.

    A worker's write reaches the event persister over the replication HTTP API,
    which is not listening in the first seconds after start-up.
    """
    from synapse.replication.http._base import ReplicationEndpoint

    assert ReplicationEndpoint.RETRY_ON_CONNECT_ERROR is True, (
        "The replication client no longer retries connection errors; the "
        f"start-up publish would fail on the first attempt. See {WORKERS_DOC}."
    )
    assert ReplicationEndpoint.RETRY_ON_CONNECT_ERROR_ATTEMPTS == 5, (
        "The replication connect-error retry count changed, so the ~63s a "
        "single publish attempt can take before failing is no longer accurate. "
        f"See {WORKERS_DOC}."
    )


def test_state_events_are_still_deduplicated_by_whole_content() -> None:
    """This is what stops a duplicate `guardian.effective_rules` being persisted.

    It compares the entire content, which is why the payload must not carry a
    moving timestamp.
    """
    from synapse.handlers.message import EventCreationHandler

    source = inspect.getsource(EventCreationHandler.deduplicate_state_event)
    assert "encode_canonical_json" in source, (
        "Synapse no longer compares state-event content to deduplicate. Our "
        f"published rule set could be written twice. See {WORKERS_DOC}."
    )
    caller = inspect.getsource(EventCreationHandler.handle_new_client_event)
    assert "deduplicate_state_event" in caller, (
        "handle_new_client_event no longer deduplicates state events. "
        f"See {WORKERS_DOC}."
    )


def test_delayed_background_call_is_still_ungated_across_processes() -> None:
    """Unlike `looping_background_call`, it fires wherever it was scheduled.

    That is why the warm-up has to be gated on being the main process instead
    of relying on Synapse to do it for us.
    """
    delayed = inspect.signature(ModuleApi.delayed_background_call)
    looping = inspect.signature(ModuleApi.looping_background_call)
    assert "run_on_all_instances" not in delayed.parameters, (
        "delayed_background_call grew instance gating; the warm-up's manual "
        f"worker_app check may now be redundant or wrong. See {WORKERS_DOC}."
    )
    assert "run_on_all_instances" in looping.parameters, (
        "looping_background_call lost its instance gating; the contrast "
        f"{WORKERS_DOC} draws between the two no longer holds."
    )


def test_module_api_still_exposes_worker_app() -> None:
    """The publisher is gated on this being None (the main process)."""
    assert isinstance(ModuleApi.worker_app, property), (
        "ModuleApi.worker_app is no longer a property; the publisher's "
        f"main-process gate in module.py would silently stop working. See {WORKERS_DOC}."
    )


def test_module_sent_events_are_still_created_without_ratelimiting() -> None:
    """Notices and the published rule set must not be rate limited."""
    source = inspect.getsource(ModuleApi.create_and_send_event_into_room)
    assert "ratelimit=False" in source, (
        "create_and_send_event_into_room now rate limits; a burst of blocks "
        f"could start dropping notices. See {WORKERS_DOC}."
    )


def test_inviter_lookup_is_still_available_on_the_datastore() -> None:
    """Guardian re-checks who sent a pending invite before allowing a join.

    `module_api.get_room_state` returns `{}` for a room this server is not in,
    which is exactly the case that matters, so the public API cannot answer it.
    We reach into `api._store.get_invite_for_local_user_in_room`, contained in
    `Guardian._inviter`. Failure there is handled (invited joins fall open), so
    this test is the early warning, not a safety net.
    """
    from synapse.storage.databases.main.roommember import RoomMemberWorkerStore

    lookup = getattr(RoomMemberWorkerStore, "get_invite_for_local_user_in_room", None)
    assert lookup is not None, (
        "Synapse dropped store.get_invite_for_local_user_in_room. Guardian._inviter "
        "can no longer tell who sent a pending invite, so stale invites from a "
        "now-blocked sender stop being re-checked (it falls open, it does not break). "
        f"Find the replacement and update Guardian._inviter and {DOC}."
    )
    params = inspect.signature(lookup).parameters
    for name in ("user_id", "room_id"):
        assert name in params, (
            f"store.get_invite_for_local_user_in_room no longer takes {name!r}; "
            "Guardian._inviter calls it by keyword. See Guardian._inviter."
        )

    from synapse.storage.roommember import RoomsForUser

    assert "sender" in getattr(RoomsForUser, "__annotations__", {}), (
        "RoomsForUser no longer exposes `.sender`; Guardian._inviter reads the "
        "inviter from it. See Guardian._inviter."
    )
