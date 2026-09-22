# Running under workers — what N processes each do

Why this file exists: this module has been bitten twice by not reasoning about
process semantics before writing code. Registering `on_new_event` made Synapse
load full room state for every persisted event, server-wide. The start-up
warm-up fired 100 ms in, before the replication endpoints were listening, and
died with `ConnectionRefusedError`. Neither was visible in a dashboard; both
were found by reading Synapse's source afterwards.

So this is the standing answer to "what happens when every worker runs this
module at once", written down so the next change is reasoned about rather than
discovered in production.

**Verified against Synapse 1.161.0**, as installed in
`.venv/lib/python3.11/site-packages/synapse/`. Every claim is cited
`file:line`. For *which callback fires on which process*, see
[`callbacks.md`](callbacks.md) — this file does not repeat it.

## The one fact everything follows from

**Every process loads the module.** `app/_base.py:713-717` instantiates every
entry in `modules:` and is reached from both `app/homeserver.py:450` (main) and
`app/generic_worker.py:446` (workers). There is no "only main" for module
loading, and there must not be: an invite is checked on whichever worker served
the request, so every worker needs the callbacks registered.

Everything below is a consequence of that, plus the fact that only one process
persists events for a given room.

## What we do, and what N processes do to it

| # | Our action | Which processes | R/W | What Synapse does underneath | With N at once | Bounded? | How we handle it |
|---|---|---|---|---|---|---|---|
| 1 | Instantiate `Guardian`, register callbacks | **All** | — | `app/_base.py:713-717` | N independent instances, each with its own cache and its own counters | Yes — registration is process-local | Intended; `module.py:72-81` registers the spam-checker callbacks unconditionally so every worker can enforce |
| 2 | Lazy rule load + TTL refresh (`get_room_state`) | **All** (whichever serves a callback) | R | `module_api/__init__.py:1677-1684` → `get_current_state_ids` with a filter → `get_partial_filtered_current_state_ids`, which is **not cached** (`storage/databases/main/state.py:539` says so in a `FIXME`) | N processes each query the DB, at most once per `refresh_interval_s` each, and only when a callback actually fires | Yes — one filtered query on one small room, ≤ N per interval | `store.py:83-89` gates on staleness/TTL; `store.py:91-117` keeps the previous rules if the read fails |
| 3 | Cache invalidation via `on_new_event` | **All**, when `watch_control_room` is on | R | Dispatched on the persister (`notifier.py:413`) *and* on every worker consuming the events stream (`replication/tcp/client.py:222`) | Every process invalidates its own cache — which is exactly right, each needs it | Yes, but see the cost | Off by default. Registering it costs a full current-state load per persisted event, server-wide (`third_party_event_rules_callbacks.py:415-426`); `module.py:103-106` only registers it when asked |
| 4 | Start-up warm-up | **Main only** | R+W | `delayed_background_call` has **no instance gating** (`module_api/__init__.py:1445-1452`) — unlike `looping_background_call`, which respects `run_background_tasks` (`:1420`). It fires wherever it was scheduled | Would be N warm-ups, N publishes, all racing | Yes, now | `module.py:113-116` schedules it only when `self._publisher is not None`, which is main-only (see 5) |
| 5 | Publish `guardian.effective_rules` | **Main only** | W | See "How a write reaches the persister" below | Would be a flap: two processes with briefly different views take turns overwriting | Yes | `module.py:58-64` gates the publisher on `worker_app is None`. Two further layers below |
| 6 | Post a block notice (`m.room.message`) | **All** — whichever process handled the blocked request | W | Same write path; `m.room.message` is **not** a state event, so Synapse's dedup does not apply (`handlers/message.py:1581`) | Each process notices only its own blocks, so no double-reporting of one block. But the dedupe window and the 20-per-window cap are **per process** | Bounded at ~20·N per window, not 20 | `notify.py:69-101`; accepted, see Open questions |
| 7 | Admin-protected ERROR + notice | **All** | W | Same | Up to N identical ERROR lines and N identical notices | Once per process per user | `store.py:184-197` guards with a per-process `_warned_admins`; see Open questions |
| 8 | Reject a stale invite (`update_room_membership` → leave) | **All** — whichever process refused the join | W | `handlers/room_member.py:2038-2073`: tries the federated rejection, then falls back to `_generate_local_out_of_band_leave`, catching "everything from DNS failures upwards" | Only the process that refused the join acts, and only when a protected user actually attempts the join, so there is nothing to race | Yes — one leave per refused join | `module.py` `_reject_invite_in_background` dispatches it via `run_as_background_process`; failures are logged and ignored, and `dry_run` skips it |
| 9 | The callbacks themselves | **All** | R | See [`callbacks.md`](callbacks.md) | Each request is served by exactly one process, so exactly one decision | Yes | Nothing to do — this is the design |

## How a write reaches the persister

`module_api.create_and_send_event_into_room` (`module_api/__init__.py:1268-1303`)
builds a `Requester` and calls `create_and_send_nonmember_event(..., ratelimit=False,
ignore_shadow_ban=True)` (`:1296-1300`). That lands in
`_create_and_send_nonmember_event_locked` → `handle_new_client_event`
(`handlers/message.py:1531`).

There, `handlers/message.py:1779-1802`:

```python
if writer_instance != self._instance_name:
    ...
    result = await self.send_events(instance_name=writer_instance, ...)
```

So a non-persisting process hands the event to the persister over the
replication HTTP API. **This is the line that produced the
`ConnectionRefusedError` the user saw** — the persister was not listening yet.

### Does the replication client retry? Yes, then it raises.

`replication/http/_base.py:322-337`: on `ConnectError`/`DNSLookupError` it
retries while `attempts <= RETRY_ON_CONNECT_ERROR_ATTEMPTS`, which is **5**
(`:121`), sleeping `2**attempts` seconds — 1, 2, 4, 8, 16, 32 — so roughly
**63 seconds** in total before it gives up and raises.

Two consequences worth holding on to:

- Our own warm-up retry (`module.py:154-165`, 5 attempts, 10 s apart) sits *on
  top* of that. A single warm-up attempt can take a minute to fail, so the full
  ladder is minutes, not seconds. That is fine — it is a background process —
  but do not read "retrying in 10s" as "10s until the next real attempt".
- Any future start-up write must assume replication may not be up.

### Is `ratelimit=False` honoured?

Yes. `create_and_send_event_into_room` passes `ratelimit=False`
(`module_api/__init__.py:1298`), and the replication branch only rate-limits
`if ratelimit:` (`handlers/message.py:1786`). So neither notices nor the
published rule set can be rate limited, however many blocks fire at once. The
cap in `notify.py` is ours, and it is the only thing bounding notice volume.

### One aside, because this server runs Meowlnir

Our own outgoing notices pass through `check_event_for_spam`
(`handlers/message.py:1195`). We do not register it, but
`synapse-http-antispam` does — so every notice guardian posts is an HTTP round
trip to Meowlnir before it is persisted. Harmless, but it is not free, and it
is another reason the per-window cap matters.

## Can Synapse's state-event dedup be raced?

`handlers/message.py:1581-1589` calls `deduplicate_state_event` for any state
event, and `:886-919` returns the previous event when the sender matches and
`encode_canonical_json(prev_event.content) == encode_canonical_json(event.content)`.
It compares the **whole content**. That is precisely why we stopped putting a
moving `updated_ts` in the payload: a changing field made every publish
byte-different, so this dedup could never fire for us.

**It can be raced.** The check reads `context.get_prev_state_ids()`
(`:904-906`) — the state as of the event being created. Two processes creating
the same state event concurrently, both before either has persisted, both see
no prior event and both persist. The room then has two events with the same
`(type, state_key)` and different `prev_events`, and state resolution picks one
— both are valid, so the winner is decided by the resolution algorithm, not by
us. No corruption, but a redundant event in the timeline and a brief period
where readers could see either.

**This no longer applies to us**: only the main process publishes
(`module.py:58-64`), so there is no second writer to race with. The dedup is
now a safety net for the sequential case (a restart, or a refresh that
recomputes the same payload), not the primary defence. Our in-process
`_last`/`_primed` check (`publish.py:62-67`) avoids even attempting the write
in the common case, and `guardian_tests/test_module.py` pins both: a restarted
publisher does not rewrite, and a second publisher that believes nothing is
published still cannot create a duplicate.

## Staleness after a rule change

Because `get_room_state` with a filter is uncached
(`storage/databases/main/state.py:539`), every refresh reads the database — so
there is no per-process cache to go stale beyond our own `refresh_interval_s`
(default 15 s) and whatever lag the database itself has.

With `watch_control_room` off (the default), the worst case for a `!guard`
command taking effect on a given worker is therefore `refresh_interval_s`. With
it on, every process invalidates immediately off the events stream — at the
cost documented in row 3 and in [`callbacks.md`](callbacks.md).

The published `guardian.effective_rules` reflects **main's** view, which may be
up to `refresh_interval_s` ahead of a worker that has not refreshed yet. The
bot reads what main published, so `!guard check` can briefly disagree with what
a specific worker would enforce. Bounded by the same interval.

## Open questions

**Notices are duplicated N ways for the admin warning.** `_check_admins`
(`store.py:184-197`) guards with a per-process `_warned_admins` set, and
`RoomNotifier.message` (`notify.py:116-125`) does no dedupe of its own — only
`notify()` does (`:112`). So a protected user who *is* a server admin produces
up to one ERROR line and one notice **per process**, not one per server. Same
class of problem for the per-window notice cap in row 6: a flood spread across
workers can post roughly 20·N notices per window rather than 20. Neither is
dangerous — the cap still bounds each process, and the enforcement decision is
untouched — but the numbers in `notify.py` do not mean what they look like on a
worker deployment. Fixing it properly needs cross-process state, which is a
bigger change than the problem warrants today.

## Rules of thumb for changing this module

1. **Every write must answer: should all N processes do this?** If the answer is
   no, gate it on `worker_app is None` like the publisher
   (`module.py:59-64`). If the answer is yes, ask what happens when N of them
   land at once — and remember Synapse's dedup only saves you for *state* events
   with byte-identical content.
2. **Never register a third-party-rules callback without reading its
   dispatcher first.** Both `check_event_allowed` and `on_new_event` load room
   state for every event, on every process, merely because a callback exists
   (`third_party_event_rules_callbacks.py:280-284` and `:415-426`). Spam-checker
   callbacks cost nothing until they are called. This is the trap that cost us
   twice.
3. **Anything at start-up must tolerate replication being down.** The persister
   may not be listening for the first seconds. Retry, log at INFO, and never let
   it block or fail enforcement.
4. **Do not put changing values in a state event's content.** It defeats
   `deduplicate_state_event` and turns every refresh into a persisted event.
