# Synapse module callbacks — verified inventory

Why this file exists: the [upstream callback
docs](https://element-hq.github.io/synapse/latest/modules/spam_checker_callbacks.html)
give each callback a signature and a one-line description, and say **nothing
about cost**. Cost is what bit this module twice — `check_event_allowed` and
`on_new_event` each make Synapse load room state from the database for *every*
event, server-wide, merely because a callback is registered. Nothing in the
upstream docs hints at that. The upstream docs are also silent on which
callbacks are bypassed for server admins, and on the fact that
`check_event_for_spam` *redacts and soft-fails* inbound federated events.

So: every claim below is read from the Synapse source, cited `file:line`.

**Verified against Synapse 1.161.0.** Line numbers refer to that version, as
installed in `.venv/lib/python3.11/site-packages/synapse/`. After a Synapse
upgrade, run `make test-unit` — `family_guard_tests/test_synapse_contract.py`
fails loudly if any assumption here stopped holding, and its failure messages
point back at this file.

Upstream marks `user_may_send_state_event` **experimental**: "The method
signature or behaviour may change without notice." We use it, and the contract
test is what protects us.

## Three things that are true of every callback

**Dispatchers call callbacks positionally**, never by keyword
(`spamchecker_callbacks.py:458,501,544,591,700,731,768`). Our parameter *names*
are therefore irrelevant, but the *order and arity* are load-bearing. An upstream
reordering of same-typed parameters would silently pass the wrong values with no
error — the contract test pins arity; only review pins order.

**Spam-checker dispatchers do not catch exceptions.** There is not one
`except Exception` in `spamchecker_callbacks.py` (0 matches). An exception from
our callback propagates into the request handler: a 500 to the client, or a
failed inbound federated invite. This is why every callback in `module.py` has a
`try/except` around its whole body.

Third-party-rules dispatchers *do* catch, but inconsistently:
`on_new_event` logs and continues (`third_party_event_rules_callbacks.py:429-433`),
while `check_event_allowed` converts any exception into a `ModuleFailedException`
that fails the event send (`:303-305`).

**"Dispatcher cost" below means work Synapse does before any callback runs,**
paid by every registered module, whether or not the callback ends up caring.

## Spam-checker callbacks

Registered via `ModuleApi.register_spam_checker_callbacks`
(`module_api/__init__.py:402-419`). All return
`"NOT_SPAM" | Codes | tuple[Codes, JsonDict] | bool`.

| Callback | Signature | Called from | Local / federated | Dispatcher cost | Admin bypass | Our verdict |
|---|---|---|---|---|---|---|
| `user_may_invite` | `(inviter, invitee, room_id)` | `handlers/room_member.py:914` | Local invites; also runs for federated invites after `federated_user_may_invite` | none | **Yes** — inside `if not is_requester_admin` (`room_member.py:906`); also bypassed for the server-notices user (`:898-902`) | **Used** — core: invites in and out |
| `federated_user_may_invite` | `(event)` | `handlers/federation.py:1134` | Inbound federated invites only | none | No | **Used** — core: the only hook for inbound federated invites |
| `user_may_join_room` | `(user_id, room_id, is_invited)` | `handlers/room_member.py:1075` | Both (runs before the local/remote join decision) | none | **Yes** — `bypass_spam_checker` (`:1065`), and skipped when `new_room` (the creator's own join, `:1073`) | **Used** — core: joins |
| `user_may_send_3pid_invite` | `(inviter, medium, address, room_id)` | `handlers/room_member.py:1747` | Local | none | No (but only reached when the 3PID is *unbound*; a bound 3PID goes via `update_membership` → `user_may_invite`, `:1738-1743`) | **Used** — protected users may not send 3PID invites |
| `user_may_send_state_event` | `(user_id, room_id, event_type, state_key, content)` | `rest/client/room.py:322` | Local, client API only (`PUT /rooms/{id}/state/...`) | none (content is `deepcopy`d, `spamchecker_callbacks.py:701`) | **Yes** — `if not is_requester_admin` (`rest/client/room.py:319`) | **Used** — cheap way to stop protected users opening join rules / setting a canonical alias. Experimental upstream |
| `user_may_create_room_alias` | `(user_id, room_alias: RoomAlias)` | `handlers/directory.py:160` | Local | none | **No** — admins are checked (the `is_admin` at `:150` only relaxes the membership requirement) | **Used** — no published aliases for protected users |
| `user_may_publish_room` | `(user_id, room_id)` | `handlers/directory.py:453` | Local | none | No | **Used** — no directory listings for protected users |
| `user_may_create_room` | `(user_id, config)` *or* `(user_id)` | `handlers/room.py:1233` (createRoom), `:707` (room upgrade) | Local | none | **Yes** — `if not is_requester_admin` (`room.py:1232`) | **Not used** — see open questions; `config` carries `visibility`/`preset`/`initial_state`/`invite` |
| `check_event_for_spam` | `(event)` | `handlers/message.py:1197`, `federation/federation_base.py:184` | Both — but **never for membership events**, so it cannot see invites, joins or knocks | none | n/a | **Not used** — on the federation path a non-`NOT_SPAM` return **prunes the event and marks it soft-failed** (`federation_base.py:186-201`). All risk, no benefit for us |
| `should_drop_federated_event` | `(event)` | `federation/federation_server.py:831,1339,1384` | Federated | none | n/a | **Not used** — drops events silently before auth; far too blunt |
| `check_username_for_spam` | `(user_profile[, requester_id])` | `handlers/user_directory.py:177` | Local | none | n/a | **Not used** — user-directory search filtering, unrelated |
| `check_registration_for_spam` | `(email_threepid, username, request_info, auth_provider_id)` | `handlers/register.py:281` | Local | none | n/a | **Not used** — we do not gate registration |
| `check_media_file_for_spam` | `(file_wrapper, file_info)` | `media/media_storage.py:249` | Both | none | n/a | **Not used** — out of scope |
| `check_login_for_spam` | `(user_id, device_id, initial_display_name, request_info, auth_provider_id)` | `rest/client/login.py:456` | Local | none | n/a | **Not used** — out of scope |

Note on `user_may_create_room`: the dispatcher sniffs the callback's arity with
`inspect.signature` and passes the room config only to two-parameter callbacks
(`spamchecker_callbacks.py:631-655`). Adding or removing a parameter therefore
changes *what Synapse sends you*, silently.

## Third-party-rules callbacks

Registered via `ModuleApi.register_third_party_rules_callbacks`
(`module_api/__init__.py:498-518`).

| Callback | Signature | Called from | Local / federated | Dispatcher cost | Our verdict |
|---|---|---|---|---|---|
| `check_event_allowed` | `(event, state) -> (bool, dict \| None)` | `handlers/message.py:1437`, `handlers/federation_event.py:455` | Both | **Heavy.** `context.get_prev_state_ids()` then `store.get_events(...)` — the room's entire previous state, loaded before every locally created event and every inbound federated event (`third_party_event_rules_callbacks.py:280-284`). Guarded only by "no callbacks registered" (`:277`) | **Opt-in** (`strict_local_events`, default off). Its useful coverage is replicated for free by `user_may_send_state_event` + `user_may_create_room_alias`; what remains is local knocks and `createRoom` initial state |
| `on_new_event` | `(event, state) -> None` | `notifier.py:413`; also on every worker consuming the events replication stream (`replication/tcp/client.py:222`) | Both | **Heavy.** `store.get_event(...)` plus the room's full current state, per persisted event (`third_party_event_rules_callbacks.py:415-426`) | **Conditional** (`watch_control_room`, default on, registered only when `control_room` is set) — the only push-based way to notice control-room edits |
| `on_create_room` | `(requester, config, is_requester_admin)` | `handlers/room.py` | Local | none | **Not used** — `user_may_create_room` covers the same ground and can *refuse* |
| `check_threepid_can_be_invited` | `(medium, address, state_events)` | — | Local | room state fetch | **Not used** — `user_may_send_3pid_invite` is the enforcing hook |
| `check_visibility_can_be_modified` | `(room_id, state_events, new_visibility)` | — | Local | room state fetch | **Not used** — `user_may_publish_room` covers it more cheaply |
| `check_can_shutdown_room`, `check_can_deactivate_user`, `on_profile_update`, `on_user_deactivation_status_changed`, `on_threepid_bind`, `on_add_user_third_party_identifier`, `on_remove_user_third_party_identifier` | — | admin / profile paths | Local | none | **Not used** — unrelated to federation guarding |

## Observability — and what it cannot see

Synapse wraps **every spam-checker callback** in a `Measure` block named after
the callback itself:

```python
with Measure(
    self.clock,
    name=f"{callback.__module__}.{callback.__qualname__}",
    server_name=self.server_name,
):
```

(`spamchecker_callbacks.py:453-457`, and 13 more occurrences — 14 in total.)
Our callbacks therefore appear as `block_name` values like
`family_guard.module.FamilyGuard.user_may_invite`, feeding the counters defined
in `util/metrics.py:55-105`: `synapse_util_metrics_block_count`,
`_block_time_seconds`, `_block_db_txn_count`,
`_block_db_txn_duration_seconds`, `_block_ru_utime_seconds`. All are labelled
`block_name` and `server_name`.

Ready-to-paste PromQL:

```promql
# calls/sec per callback
sum by (block_name) (
  rate(synapse_util_metrics_block_count{block_name=~"family_guard.*"}[5m])
)

# seconds spent per call (latency we add to an invite/join)
sum by (block_name) (rate(synapse_util_metrics_block_time_seconds{block_name=~"family_guard.*"}[5m]))
  /
sum by (block_name) (rate(synapse_util_metrics_block_count{block_name=~"family_guard.*"}[5m]))

# database transactions per call -- should sit at 0 in steady state
sum by (block_name) (rate(synapse_util_metrics_block_db_txn_count{block_name=~"family_guard.*"}[5m]))
  /
sum by (block_name) (rate(synapse_util_metrics_block_count{block_name=~"family_guard.*"}[5m]))

# user CPU seconds per second attributable to the module
sum(rate(synapse_util_metrics_block_ru_utime_seconds{block_name=~"family_guard.*"}[5m]))
```

### Two blind spots

**(a) Third-party-rules callbacks are not measured at all.** `Measure(` appears
**0 times** in `third_party_event_rules_callbacks.py`. So `check_event_allowed`
and `on_new_event` — the two most expensive things a module can register —
produce no `block_name` series whatsoever. Turning on `strict_local_events`
will not show up in any `family_guard.*` metric.

**(b) The expensive part happens before the measurement.** For
`check_event_allowed`, Synapse loads the room's previous state
(`context.get_prev_state_ids()` then `store.get_events(...)`,
`third_party_event_rules_callbacks.py:280-284`) *before* entering the callback
loop at `:286`. `on_new_event` does the same at `:415-426` before its loop at
`:428`. That work is attributed to the calling handler, never to us. The cost
of merely **registering** a callback is therefore invisible under our
`block_name` by construction — it would show up, if at all, as a diffuse
slowdown of `synapse_http_server_response_time_seconds` across every endpoint
that sends events.

**Conclusion: Grafana confirms assumptions; it does not detect this class of
problem.** Reading the dispatcher does. Both regressions this module has had
were found by reading `third_party_event_rules_callbacks.py`, and neither would
have appeared on a dashboard. The machine-checkable half of the claim is pinned
by `CallbackCostTestCase` in `family_guard_tests/test_module.py`, which asserts
a per-callback database-transaction budget of zero and that no
third-party-rules callback is registered under default config.

### Error semantics differ between the two families

Worth knowing when reading metrics, because failures surface differently:

- **Spam-checker dispatchers do not catch exceptions at all** (0 occurrences of
  `except Exception` in `spamchecker_callbacks.py`). An exception propagates to
  the request handler — a 500 to the client, or a failed inbound federated
  invite.
- **`check_event_allowed` converts any exception into `ModuleFailedException`**
  and re-raises `SynapseError` specially so modules can throw it deliberately
  (`third_party_event_rules_callbacks.py:292-305`); the event send fails either
  way.
- **`on_new_event` logs and continues** (`:429-433`), so a failure there is
  silent apart from the log line.

## Open questions

**`user_may_create_room` should probably be used.** It receives the full
createRoom config — `visibility`, `preset`, `initial_state`, `invite`
(`handlers/room.py:1233`, dispatcher `spamchecker_callbacks.py:631-655`) — at
zero dispatcher cost. That closes the residual gap left by preferring
`user_may_send_state_event` over `check_event_allowed`: a protected user can
currently create a room that is public *from birth*, because
`user_may_send_state_event` only sees state sent afterwards through
`PUT /rooms/{id}/state/...`. The same callback also fires on room upgrades
(`handlers/room.py:707`), where the config is reconstructed from the old room's
state. Deliberately left unimplemented here — flagged for a decision.

**Parameter order is unpinnable.** Because dispatchers call positionally, the
contract test can only assert arity. A future Synapse that swapped, say,
`room_id` and `event_type` in `user_may_send_state_event` would be silently
wrong. Re-read this file's citations after a major upgrade.
