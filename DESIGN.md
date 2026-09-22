# guardian — design

Synapse module + maubot plugin that restricts which homeservers/users a set of
"protected" local accounts (children) can federate with. Target: Synapse 1.161,
Python 3.11.

## Goals (v1)

For every protected user P, using one shared rule set:

1. P cannot be invited by anyone who is not allowed.
2. P cannot invite anyone who is not allowed (incl. 3PID invites: always denied).
3. P cannot join rooms outside the allowed set (see join policy).
4. Rules live as state events in a control room and can be changed at runtime
   by a maubot plugin (or any client able to send state). No Synapse restart.
5. Non-protected users are completely unaffected.

Non-goals (v1): per-child rule overrides; enforcement *after* P is in a room
(strangers joining a room P is already in) — documented as a known gap, with
"auto-leave" and server-ACL sketched as phase 2.

## Rule evaluation

`is_allowed(other_user_id) -> Decision(allowed: bool, rule: str | None)`

Principle: **the more specific rule wins; on a tie, block wins.** Order, first
match wins:

1. `blocked_users`   (glob on full MXID)          → deny
2. `allowed_users`   (glob on full MXID)          → allow   (beats a blocked server)
3. `blocked_servers` (glob on server name)        → deny    (exception to an allowed glob)
4. `allowed_servers` (glob on server name)        → allow
5. default                                        → deny

(This deliberately differs from MSC4155, where allow is evaluated first: there,
`allowed_servers: ["*.skole.no"], blocked_servers: ["evil.skole.no"]` would
still allow `evil.skole.no`. We promise the opposite.)

Globs via `matrix_common.regex.glob_to_regex` (anchored, case-insensitive by
default — pin with tests). Patterns longer than 255 chars are ignored. A
catch-all pattern (`*`, `?*`, anything whose regex matches every string) is
**rejected** in `allowed_users`/`allowed_servers` (config → startup error;
room state → skipped + logged; bot → refuses). Server names with a port
(`ex.org:8448`) do not match the bare glob `ex.org` (README).

Server admins bypass `user_may_invite`/`user_may_join_room` inside Synapse; the
module adds no bypass of its own. A protected user must never be a server
admin: at rule load, each protected user is checked with
`module_api.is_user_admin`; admins are logged at ERROR (and notified if
`notify_room`) and the bot refuses `!guard protect <admin>`.

## Sources of rules

Two sources, merged as a union:

- **Static** (homeserver.yaml module config): `protected_users`,
  `allowed_servers`, `allowed_users`, `blocked_users`, `blocked_servers`.
  Baseline that can never be removed at runtime (e.g. own server name).
- **Control room** (optional, `control_room: "!id:server"`): state events, one
  per entry. Must be a local room. Read via `module_api.get_room_state`.

Control-room state events, one per entry, empty `content` = removed. The
entity lives in `content.entity` (fallback: the state key). State keys may not
start with `@` unless the sender is that user (auth rules), so user entities
are written with the `@` stripped from the state key:

| type                          | state_key                | content                                              |
|-------------------------------|--------------------------|------------------------------------------------------|
| `guardian.protected_user` | `kid:example.org`        | `{entity: "@kid:example.org", added_by, ts, reason?}` |
| `guardian.allowed_server` | `friends.org` / `*.x.no` | `{entity: "friends.org", ...}`                       |
| `guardian.allowed_user`   | `granny:other.org`       | `{entity: "@granny:other.org", ...}`                 |
| `guardian.blocked_user`   | `troll:friends.org`      | `{entity: "@troll:friends.org", ...}`                |
| `guardian.blocked_server` | `bad.x.no`               | `{entity: "bad.x.no", ...}`                          |

Only state events whose `sender` is a *local* user are honoured (defence in
depth beyond power levels). Entries are validated (MXID / server name / glob);
invalid ones are logged and skipped, never fatal.

Trust: a control-room state event is honoured if its `sender` is a local user
AND (is a server admin per `module_api.is_user_admin`, OR currently holds
enough power in the control room to send that event type).

The room's power levels are the authority, because Synapse already refused to
persist the event otherwise — a second, independent notion of trust could only
ever reject someone the room had allowed. It did exactly that in production:
the control room's creator, who under room version 12 has implicit infinite
power and is *forbidden* from appearing in `m.room.power_levels.users`, was
read as `users_default` (0) and had their hand-written rule silently dropped.

Required level for a type is `content.events[<type>]`, else `state_default`,
else 50, matched by the raw type **string** exactly as Synapse matches it.
Sender level is `users[<sender>]`, else `users_default`, else 0 — except that
with MSC4289 creator power (room version 12+) the create event's `sender` and
everyone in `content.additional_creators` count as infinite. The arithmetic
lives in `policy.py` over plain dicts so the module and the maubot plugin
cannot drift apart. If the power levels cannot be read, only server admins are
honoured, and that is logged.

`trusted_senders` was removed in 0.5.0: the power-level check subsumes it.
`notify_user` is still who we post notices and `guardian.effective_rules` as —
it no longer confers any trust, and does not need to, since the README already
has you grant it power in the room.

## Cache & invalidation

`PolicyStore` holds the merged rule set in memory. There is no async init hook
in the module API (`__init__` is sync), so loading is lazy:

- Rules are loaded on the first callback (per process) from static config +
  `module_api.get_room_state(control_room)`, and cached.
- `on_new_event` (third-party-rules callback, fires after persist on the
  persisting process): if `event.room_id == control_room` and `event.type` is
  one of ours, mark the cache stale so the next check re-reads via
  `get_room_state` (cheap; Synapse caches state). On a monolith this makes
  changes effective before the next callback.
- `on_new_event` is registered only when a `control_room` is set and
  `watch_control_room` (default true) is on: Synapse loads the event *and the
  room's full current state* for every persisted event on every process that
  dispatches the callback, so registering it unusable would tax the whole
  server. Verified dispatched on workers too, via the events replication
  stream (`replication/tcp/client.py:222`).
- TTL refresh (`refresh_interval_s`, default 30): on the next check after
  expiry, re-read room state. Safety net for worker deployments where
  `on_new_event` fires on a different process than the spam-checker callbacks.
  Refresh never blocks longer than one `get_room_state` call and keeps the old
  rule set if the refresh fails.
- Optionally `module_api.delayed_background_call(0, warm_up)` to pre-warm.
- If the control room cannot be read, log an error and run with static rules
  only (fail-safe toward *more* restriction: static protected users stay
  protected; a missing room can never *unprotect*).

## Callbacks (spam checker) and semantics

Verified against Synapse 1.161 source (`synapse/handlers/room_member.py`,
`synapse/handlers/federation.py`). [`docs/callbacks.md`](docs/callbacks.md)
holds the full inventory — every callback, its dispatcher cost, admin bypasses,
and the reasoning for using or avoiding it — pinned by
`guardian_tests/test_synapse_contract.py`, and
[`docs/workers.md`](docs/workers.md) covers what each of our actions does when
every worker runs the module at once:

| callback                       | logic                                                                                                   |
|--------------------------------|---------------------------------------------------------------------------------------------------------|
| `federated_user_may_invite(ev)`| Inbound federated invites (the ONLY hook for those in 1.161). invitee=`ev.state_key`. If protected and `ev.sender` not allowed → FORBIDDEN. |
| `user_may_invite(i, t, room)`  | Local invites (skipped for server admins) — and, via Synapse's spam-checker dispatcher, also run for federated invites right after `federated_user_may_invite` (verified in `spamchecker_callbacks.py`). If `t` protected and `i` not allowed → FORBIDDEN. If `i` protected and `t` not allowed → FORBIDDEN. |
| `user_may_send_3pid_invite`    | If inviter protected → FORBIDDEN.                                                                       |
| `user_may_join_room(u, r, inv)`| Called for local *and* remote joins (alias / `via`), skipped for server admins and room creation. If `u` protected: `inv` → re-check the inviter (below). Else apply `uninvited_joins` policy (below). |
| `user_may_publish_room(u, room)`| If `u` protected → FORBIDDEN (no publishing rooms to the directory).                                    |

Third-party-rules callbacks:

| callback                          | logic                                                                                                  |
|-----------------------------------|--------------------------------------------------------------------------------------------------------|
| `check_event_allowed(ev, state)`  | Only when `module_api.is_mine(ev.sender)` (it is also called for incoming federation events — never veto those). If sender protected: veto `m.room.member` with `membership: knock`; veto `m.room.join_rules` with `join_rule != "invite"`; veto `m.room.canonical_alias`. Return `(False, None)`; else `(True, None)`. |
| `on_new_event(ev, state)`         | If `ev.room_id == control_room` and `ev.type` is ours → mark rules stale (next check re-reads via `get_room_state`; do not trust the passed state map to include the triggering event). |

Not registered: `check_event_for_spam` (never sees local membership events;
on incoming federation PDUs a non-NOT_SPAM return *soft-fails and redacts*
the event — a bug there would destroy traffic. Pure risk, no benefit).

Remote knocks by a protected user cannot be intercepted by any hook in 1.161
(`do_knock` has no spam check). Harmless for access (the resulting invite is
blocked) but leaks displayname/avatar to the target room → README gap.

`federated_user_may_invite` runs *before* Synapse validates the event (type,
sender domain vs origin, local `state_key`), so it must be defensive: return
NOT_SPAM for anything that is not an `m.room.member` invite with a `state_key`
we can parse, and let Synapse reject it.

Invited joins (`inv` true) are **not** trusted on the strength of the invite
alone: an invite that arrived before the module was installed, or while
`dry_run` was on, was never vetted. `Guardian._inviter` looks up who sent the
pending invite and the rules are applied to them; a disallowed inviter means the
join is refused and the stale invite is rejected in the background
(`update_room_membership` → leave; Synapse's `remote_reject_invite`
(`handlers/room_member.py:2038-2073`) falls back to a local out-of-band leave
when the inviting server is unreachable, so the local membership is cleaned up
either way). `dry_run` logs and notifies without rejecting.

The lookup uses `api._store.get_invite_for_local_user_in_room`, which is private
API: `module_api.get_room_state` returns `{}` for a room this server is not in,
which is exactly the out-of-band remote invite case that matters. It is
contained in one helper, guarded with `getattr`, pinned by
`guardian_tests/test_synapse_contract.py`, and **fails open** with a
once-per-process warning — every invite arriving while we enforce has already
been vetted on the way in, so refusing all invited joins after a Synapse
upgrade would be worse than the gap it closes.

`uninvited_joins`:
- `deny`: always forbidden.
- `known_rooms` (default): read `get_room_state(room, [("m.room.member", None)])`.
  Allowed iff at least one *local* user has `membership: join` (an unknown room
  returns `{}`; a room everyone local has left still has stale state — both
  must be denied) **and** every member with membership `join` or `invite` is
  allowed for the protected user. Rooms we are not in → forbidden (we cannot
  see who is there; room v12 IDs carry no domain to fall back on).

Return values use `synapse.module_api.errors.Codes.FORBIDDEN` (bare; Synapse
normalises it to `(Codes, {})`); the module never raises out of a callback.
`dry_run: true` logs what *would* be blocked (and still notifies, prefixed
`[dry-run]`, so the parent can calibrate rules before enforcing) and returns
NOT_SPAM / `(True, None)`.

Caveat for README: server admins bypass `user_may_invite` and
`user_may_join_room`. A protected account must never be a server admin.

Every block is logged at INFO: `guardian: blocked <action> <who> -> <whom>
room=<id> reason=<rule|default-deny>`.

## Notifications

Notices go through a small `Notifier` interface (`synapse_guardian/notify.py`:
`notify(kind, actor, target, room_id, rule, dry_run)` + `message(text)`) so a
webhook transport to the bot (`notify_via: bot`, phase 2) can be dropped in.
v1 implements `RoomNotifier` and `NullNotifier`.

`notify_room: true` posts an `m.notice` into `control_room` for each block via
`module_api.create_and_send_event_into_room` as `notify_user`. That API
requires the sender to be a local user already *joined* to the room, so
`notify_user` is required when `notify_room` is on and is documented as "a local
user joined to `control_room`, normally the maubot account". No user creation,
no auto-join. Deduplicated per (action, actor, target) for `notify_dedupe_s`
(default 300 s) using a plain dict pruned on insert. Failures to notify are
logged and never affect the block decision.

Encryption: state events are never encrypted in Matrix, so rules work in an
encrypted control room. Server-side notices are sent unencrypted, so an
encrypted room will show them with an "unencrypted" warning; recommend an
unencrypted control room (its state is server-visible anyway).

## Module config (homeserver.yaml)

```yaml
modules:
  - module: synapse_guardian.Guardian
    config:
      control_room: "!abc:example.org"     # optional
      protected_users: []                  # static baseline
      allowed_servers: ["example.org"]
      allowed_users: []
      blocked_users: []
      blocked_servers: []
      uninvited_joins: known_rooms         # deny | known_rooms
      notify_room: false
      notify_user: "@guardianbot:example.org"   # required if notify_room; must be joined to control_room
      notify_dedupe_s: 300
      refresh_interval_s: 30
      dry_run: false
```

Config errors → raise in `parse_config` (Synapse refuses to start).

## maubot plugin (`guardian-bot`)

Commands, only honoured in `control_room` from users with PL ≥ `state_default`
(bot checks power levels itself, in addition to the server enforcing them):

```
!guard protect <mxid>            !guard unprotect <mxid>
!guard allow server <glob>       !guard remove server <glob>
!guard allow user <mxid|glob>    !guard remove user <mxid|glob>
!guard block user <mxid|glob>    !guard unblock user <mxid|glob>
!guard block server <glob>       !guard unblock server <glob>
!guard list                      # grouped, with reason / added_by / date
!guard check <mxid>              # evaluate with the shared policy code; show deciding rule
```

The bot writes/clears state events in the control room. It shares `policy.py`
with the module (vendored copy via `make bot-build`) so `!guard check` matches
the module bit for bit.

Hardening (the bot never grants a right the sender lacks in the room):
`control_room` required, commands elsewhere ignored silently; before any
mutation the bot reads `m.room.power_levels` and requires the sender's PL ≥
the level needed for that state event type; optional `admins` list; every
entry records `added_by` and `ts`; only local users can be protected and the
sender cannot protect themselves; catch-all globs refused. Maubot autojoin must
be off (README).

## Repository layout

```
synapse-module/
├── DESIGN.md
├── README.md
├── pyproject.toml                 # package synapse_guardian (module); extras: [bot]
├── synapse_guardian/
│   ├── __init__.py
│   ├── config.py                  # parse/validate module config
│   ├── policy.py                  # pure rule logic, no Synapse imports
│   ├── store.py                   # PolicyStore: static + room state, cache, refresh
│   └── module.py                  # Guardian: registers callbacks
├── bot/
│   ├── maubot.yaml
│   └── guardian_bot/__init__.py
├── scripts/
│   └── reject_pending_invites.py  # one-off: reject pending invites for protected users
└── tests/
    ├── test_policy.py             # pure unit tests
    ├── test_store.py              # parsing of room state, invalid entries, TTL
    └── test_module.py             # synapse HomeserverTestCase: real invites/joins, local + federated
```

## Publishing the effective rules

The maubot plugin is a plain Matrix client: it can read the rule state events
it wrote, but not `homeserver.yaml`, so `!guard list` and `!guard check` were blind
to the static baseline.

When `control_room` and `notify_user` are both set, `RoomPublisher`
(`synapse_guardian/publish.py`) keeps one `guardian.effective_rules` state
event (state key `""`) in the control room, sent as `notify_user`, with
`static`, `effective`, `dry_run` and `uninvited_joins`. No timestamp: the
event carries `origin_server_ts`, and a moving field would defeat Synapse's own
identical-state-event dedup (`handlers/message.py:886`), which is what stops
several workers writing duplicates.
`RuleSet.to_payload()`/`from_payload()` are the shared serialisation, so the
bot rebuilds exactly the rule set the module enforces.

- Driven by `PolicyStore`'s `on_rules_loaded` hook at the end of `refresh()`,
  dispatched through `run_as_background_process` so it never blocks a callback.
- Written only when the payload changes, so
  Synapse's own state-event dedup would never fire; the in-memory comparison is
  what keeps the room quiet. On the first publish after start-up the current
  event is read back first, so a restart does not rewrite identical content.
- `guardian.effective_rules` is not one of the five rule kinds, so
  `PolicyStore` ignores it and `on_new_event` cannot turn it into a refresh
  loop (pinned by `test_publishing_does_not_invalidate_the_rule_cache`).
- A failure (normally `notify_user` lacking power to send the type) is logged
  once and never affects a decision.

## Testing

The `matrix-synapse` wheel does not ship the `tests/` package. `test_module.py`
uses `tests.unittest.HomeserverTestCase`; `make synapse-tests` does a sparse
checkout of only `tests/` from tag `v1.161.0` into `.synapse-tests/` (never the
`synapse/` tree, which would shadow the installed wheel; already gitignored).
`make test` runs `pytest guardian_tests/test_policy.py test_store.py` and
`PYTHONPATH=.synapse-tests python -m twisted.trial guardian_tests.test_module`.

Harness notes (verified for 1.161): load the module via `default_config()`
`"modules": [...]` (pattern `tests/handlers/test_password_providers.py`);
servlets `synapse.rest.admin`, `synapse.rest.client.login/room/knock`; federated
invites via `tests.test_utils.event_builders` + `hs.get_federation_handler()
.on_invite_request(origin, event, room_version)` (pattern
`tests/handlers/test_federation.py`); the allowed "kid invites remote user"
case needs `federation_client.send_invite` mocked. Unknown remote room join:
`helper.join("!nope:remote.org", kid, tok, expect_code=403)`.

The QA test plan (see git history / PR description) enumerates the concrete
test cases; all of them are the v1 acceptance bar.

## Known gaps (document in README)

- Strangers can be invited into a room a protected user is already in.
- Existing pending invites (pre-install or during `dry_run`) are not
  re-evaluated; `is_invited` joins are trusted (script provided).
- Remote knocks by a protected user are not intercepted (leaks name/avatar;
  the resulting invite is still blocked). Local knocks are.
- 3PID invites *to* a protected user's e-mail, exchanged via an identity
  server, bypass `user_may_invite`; keep kids' 3PIDs unbound and set
  `enable_3pid_lookup: false`.
- If the own server is in `allowed_servers`, every local user may invite the
  kids; keep registration closed or list local users instead.
- Server names with a port do not match bare globs.
- Control room should be unencrypted and invite-only; if it is upgraded
  (tombstoned) the module keeps the configured room id.
- Server admins bypass `user_may_invite`/`user_may_join_room`; never make a
  protected account admin.
- Workers: rule changes propagate within `refresh_interval_s` on other workers.
