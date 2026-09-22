# family_guard — design

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
`notify_room`) and the bot refuses `!fg protect <admin>`.

## Sources of rules

Two sources, merged as a union:

- **Static** (homeserver.yaml module config): `protected_users`,
  `allowed_servers`, `allowed_users`, `blocked_users`, `blocked_servers`.
  Baseline that can never be removed at runtime (e.g. own server name).
- **Control room** (optional, `control_room: "!id:server"`): state events, one
  per entry. Must be a local room. Read via `module_api.get_room_state`.

Control-room state events (`state_key` = entity, empty `content` = removed):

| type                          | state_key                | content                       |
|-------------------------------|--------------------------|-------------------------------|
| `family_guard.protected_user` | `@kid:example.org`       | `{reason?, added_by?, ts?}`   |
| `family_guard.allowed_server` | `friends.org` / `*.x.no` | same                          |
| `family_guard.allowed_user`   | `@granny:other.org`      | same                          |
| `family_guard.blocked_user`   | `@troll:friends.org`     | same                          |
| `family_guard.blocked_server` | `bad.x.no`               | same                          |

Only state events whose `sender` is a *local* user are honoured (defence in
depth beyond power levels). Entries are validated (MXID / server name / glob);
invalid ones are logged and skipped, never fatal.

Trust: a control-room state event is honoured only if its `sender` is a local
user AND (is a server admin per `module_api.is_user_admin`, or is listed in
`trusted_senders`, which defaults to `[notify_user]`). Power levels are the
real gate; this is a cheap second layer.

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
`synapse/handlers/federation.py`):

| callback                       | logic                                                                                                   |
|--------------------------------|---------------------------------------------------------------------------------------------------------|
| `federated_user_may_invite(ev)`| Inbound federated invites (the ONLY hook for those in 1.161). invitee=`ev.state_key`. If protected and `ev.sender` not allowed → FORBIDDEN. |
| `user_may_invite(i, t, room)`  | Local invites only (skipped for server admins). If `t` protected and `i` not allowed → FORBIDDEN. If `i` protected and `t` not allowed → FORBIDDEN. |
| `user_may_send_3pid_invite`    | If inviter protected → FORBIDDEN.                                                                       |
| `user_may_join_room(u, r, inv)`| Called for local *and* remote joins (alias / `via`), skipped for server admins and room creation. If `u` protected: `inv` → allow. Else apply `uninvited_joins` policy (below). |
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

Every block is logged at INFO: `family_guard: blocked <action> <who> -> <whom>
room=<id> reason=<rule|default-deny>`.

## Notifications

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
  - module: family_guard.FamilyGuard
    config:
      control_room: "!abc:example.org"     # optional
      protected_users: []                  # static baseline
      allowed_servers: ["example.org"]
      allowed_users: []
      blocked_users: []
      blocked_servers: []
      uninvited_joins: known_rooms         # deny | known_rooms
      notify_room: false
      notify_user: "@family-guard-bot:example.org"   # required if notify_room; must be joined to control_room
      notify_dedupe_s: 300
      trusted_senders: []                  # extra local senders trusted in control_room (admins + notify_user always)
      refresh_interval_s: 30
      dry_run: false
```

Config errors → raise in `parse_config` (Synapse refuses to start).

## maubot plugin (`family-guard-bot`)

Commands, only honoured in `control_room` from users with PL ≥ `state_default`
(bot checks power levels itself, in addition to the server enforcing them):

```
!fg protect <mxid>            !fg unprotect <mxid>
!fg allow server <glob>       !fg remove server <glob>
!fg allow user <mxid|glob>    !fg remove user <mxid|glob>
!fg block user <mxid|glob>    !fg unblock user <mxid|glob>
!fg block server <glob>       !fg unblock server <glob>
!fg list                      # grouped, with reason / added_by / date
!fg check <mxid>              # evaluate with the shared policy code; show deciding rule
```

The bot writes/clears state events in the control room. It shares `policy.py`
with the module (vendored copy or same package) so `!fg check` matches the
module bit for bit.

## Repository layout

```
synapse-module/
├── DESIGN.md
├── README.md
├── pyproject.toml                 # package family_guard (module); extras: [bot]
├── family_guard/
│   ├── __init__.py
│   ├── config.py                  # parse/validate module config
│   ├── policy.py                  # pure rule logic, no Synapse imports
│   ├── store.py                   # PolicyStore: static + room state, cache, refresh
│   └── module.py                  # FamilyGuard: registers callbacks
├── bot/
│   ├── maubot.yaml
│   └── family_guard_bot/__init__.py
├── scripts/
│   └── reject_pending_invites.py  # one-off: reject pending invites for protected users
└── tests/
    ├── test_policy.py             # pure unit tests
    ├── test_store.py              # parsing of room state, invalid entries, TTL
    └── test_module.py             # synapse HomeserverTestCase: real invites/joins, local + federated
```

## Testing

The `matrix-synapse` wheel does not ship the `tests/` package. `test_module.py`
uses `tests.unittest.HomeserverTestCase`; `make synapse-tests` does a sparse
checkout of only `tests/` from tag `v1.161.0` into `.synapse-tests/` (never the
`synapse/` tree, which would shadow the installed wheel; already gitignored).
`make test` runs `pytest family_guard_tests/test_policy.py test_store.py` and
`PYTHONPATH=.synapse-tests python -m twisted.trial family_guard_tests.test_module`.

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
