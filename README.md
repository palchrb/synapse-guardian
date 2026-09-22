# guardian

A [Synapse](https://github.com/element-hq/synapse) module that restricts which
homeservers and users a set of *protected* local accounts (typically your
children) can federate with, plus a [maubot](https://github.com/maubot/maubot)
plugin to manage the rules from a Matrix room.

For every protected user, with one shared rule set:

1. they cannot be **invited** by anyone who is not allowed (local or federated);
2. they cannot **invite** anyone who is not allowed (3PID/e-mail invites are
   always refused);
3. they cannot **join** rooms outside the allowed set;
4. they cannot open their own rooms to strangers (no `join_rules` other than
   `invite`, no canonical alias, no room-directory publishing, no knocking).

Everyone else on the server is unaffected. Requires Synapse ≥ 1.133 (tested
against 1.161) and Python ≥ 3.11. See `DESIGN.md` for the full rationale.

## How rules are evaluated

The more specific rule wins; on a tie, block wins. First match:

| order | list              | matches           | result |
|-------|-------------------|-------------------|--------|
| 1     | `blocked_users`   | glob on full MXID | deny   |
| 2     | `allowed_users`   | glob on full MXID | allow  |
| 3     | `blocked_servers` | glob on server    | deny   |
| 4     | `allowed_servers` | glob on server    | allow  |
| 5     | *(nothing)*       |                   | deny   |

So `allowed_servers: ["*.skole.no"]` + `blocked_servers: ["evil.skole.no"]`
allows every `*.skole.no` server except `evil.skole.no`, and
`allowed_users: ["@granny:bigserver.org"]` lets granny through even though
`bigserver.org` is not allowed. Globs use `*` and `?` and are
case-insensitive. Catch-all patterns are refused in allow lists — not just
`*`, but anything that matches every user or server (`@*:*`, `*.*`, `?*`).

## Upgrading from 0.4.x

`trusted_senders` was removed. The control room's power levels now decide who
may manage rules, which is what the room was already enforcing — and which
fixes a room-version-12 control room silently ignoring its own creator.

1. **Delete the `trusted_senders:` line** from the module config. Synapse
   refuses to start while it is there, with a message saying so.
2. **Check the power levels** of anyone who wrote rules by hand: they now need
   enough power in the control room for the `guardian.*` event types (the
   `m.room.power_levels` example below grants the bot 50). Server admins are
   still honoured regardless, and a room-version-12 creator always is.
3. `notify_user` no longer confers trust. It is still the account notices and
   `guardian.effective_rules` are sent as, and still needs power to send that
   state event.

## Upgrading from family_guard 0.3.x

Everything was renamed in 0.4.0: the pip package, the Python module, the state
event types, the maubot plugin and the bot's command prefix. Nothing migrates
itself, so do all of the following in one sitting.

1. **Remove the old package first**, or both will sit in the virtualenv:

   ```sh
   /opt/venvs/matrix-synapse/bin/pip uninstall -y family-guard
   /opt/venvs/matrix-synapse/bin/pip install --force-reinstall --no-deps \
     "git+https://github.com/<you>/synapse-guardian.git"
   ```

2. **Point `homeserver.yaml` at the new class** — `family_guard.FamilyGuard`
   becomes `synapse_guardian.Guardian`. Every config key is unchanged.

3. **Rename the entries in the control room's `m.room.power_levels`**, under
   `events`: `family_guard.protected_user` → `guardian.protected_user`, and the
   same for `allowed_server`, `allowed_user`, `blocked_user`, `blocked_server`
   and `effective_rules`. Miss this and the bot refuses to write rules and the
   module logs one warning about `guardian.effective_rules`.

4. **Replace the maubot plugin.** The id changed from `no.vibb.family_guard` to
   `no.vibb.guardian`, so maubot treats it as a new plugin: delete the old
   instance and plugin, `make bot-build`, upload the new `.mbp` and re-create
   the instance with the same config.

5. **Re-create any rules that live in the control room.** The new version only
   reads `guardian.*` state events, so old `family_guard.*` ones are ignored —
   run `!guard list` (note the new prefix), and add each rule again with
   `!guard protect` / `!guard allow` / `!guard block`. Rules that live in
   `homeserver.yaml` need no action. The stale `family_guard.*` state events are
   inert and can be left alone, or blanked out by sending `{}` as their content
   if you want the room tidy.

6. **Restart Synapse** and check the log says `guardian: loaded (...)`.

Prometheus series change too: the `block_name` label is now
`synapse_guardian.module.Guardian.*`.

## Installation

Into the Python environment Synapse runs in:

```sh
pip install git+https://github.com/<you>/synapse-guardian.git   # or: pip install .
```

Debian packages from packages.matrix.org: use `/opt/venvs/matrix-synapse/bin/pip`. Docker: build an overlay
image:

```Dockerfile
FROM matrixdotorg/synapse
RUN pip install git+https://github.com/<you>/synapse-guardian.git
```

## Configuration (`homeserver.yaml`)

```yaml
modules:
  - module: synapse_guardian.Guardian
    config:
      control_room: "!abc123:example.org"    # optional; rules managed in this room
      # Static baseline. Always applies; cannot be removed from the room.
      protected_users: []                    # e.g. ["@kid:example.org"]
      allowed_servers: ["example.org"]       # your own server, so family can talk
      allowed_users: []
      blocked_users: []
      blocked_servers: []
      uninvited_joins: known_rooms           # deny | known_rooms (default)
      notify_room: false                     # post a notice on every block
      notify_user: "@guardianbot:example.org"  # required with notify_room
      notify_dedupe_s: 300
      refresh_interval_s: 15                 # max seconds before a rule change is picked up
      watch_control_room: false            # true = instant rule updates, but costs a state load per event
      strict_local_events: false             # costs a DB state load per event; see below
      dry_run: false                         # log/notify only, never block
```

- `uninvited_joins`: what happens when a protected user tries to join a room
  without an invite. `deny` always refuses. `known_rooms` allows it only if at
  least one local user is already joined **and** every joined/invited member is
  allowed by the rules (rooms the server is not in are refused, because we
  cannot see who is there).
- `notify_user` must be a local user that is already **joined** to the control
  room — normally the maubot account. The module does not create or join users.
- **Who may write rules** is decided by the control room's own power levels: a
  local user is honoured if they are a Synapse server admin, or if they
  currently hold enough power there to send that `guardian.*` state event.
  Under room version 12 the room's creator counts as having infinite power even
  though Matrix forbids listing them in `users`. Anyone you grant that level to
  can manage the rules — that is the point of granting it. If the power levels
  cannot be read, only server admins are honoured, and the module says so in
  the log. (`trusted_senders` was removed in 0.5.0; see Upgrading.)
- `dry_run` still logs and notifies (prefixed `[dry-run]`) so you can calibrate
  before enforcing. Remember to run `scripts/reject_pending_invites.py`
  afterwards (see gaps).
- `watch_control_room` (**default `false`** — leave it): makes rule edits apply
  instantly instead of within `refresh_interval_s`. It registers Synapse's
  `on_new_event`, and merely registering that makes Synapse load every persisted
  event **and that room's full current state** on every process that dispatches
  it (`third_party_event_rules_callbacks.py:419-425`) — a server-wide cost, paid
  on every worker, to watch one small room. With it off the module's only
  recurring work is one `get_room_state` of the control room per
  `refresh_interval_s` per worker, which is negligible. Turn it on only on a
  quiet server where a 15-second delay on `!guard` commands would actually bother
  you. It is never registered when `control_room` is unset.
- `strict_local_events` (default `false`): the only thing left that this adds
  is stopping a protected user **knocking** on a local room. Opening up a room
  is already blocked for free: `user_may_create_room` refuses a public room at
  creation, and `user_may_send_state_event` / `user_may_create_room_alias`
  refuse join-rule, canonical-alias and alias changes afterwards. It registers
  Synapse's `check_event_allowed`, and merely
  registering it makes Synapse load the room's previous state from the database
  before **every** locally created event and **every** inbound federated event,
  server-wide (`handlers/message.py:1437`,
  `handlers/federation_event.py:455`). The three main protections — who may
  invite the kids, who the kids may invite, and which rooms they may join — are
  enforced by spam-checker callbacks that carry no such cost and are always on.
  A knock can only lead to an invite, and that invite is blocked anyway, so
  you almost certainly do not need this.

Config errors make Synapse refuse to start.

## Workers

Verified against Synapse 1.161. Short version: **no invite or join can slip past
the module in a worker deployment.**

- **Every process loads the module.** `synapse/app/_base.py:713-717` instantiates
  the `modules:` list, and both `app/homeserver.py:450` and
  `app/generic_worker.py:446` run that function. Workers share `homeserver.yaml`,
  so there is nothing extra to configure — but the module must be importable in
  every worker's Python environment (trivially true unless workers run in
  separate containers, in which case install it in each image).
- **The checks run on the worker handling the request.**
  `update_membership_locked` — which contains the `user_may_invite`
  (`handlers/room_member.py:914`) and `user_may_join_room`
  (`handlers/room_member.py:1075`) calls — lives on the shared
  `RoomMemberHandler` base class. `RoomMemberWorkerHandler` only overrides
  `_remote_join`/`remote_knock`/`remote_reject_invite`, which run *after* the
  checks and merely hand the federation work to the event persister over
  replication. Inbound federated invites are handled in-process by whichever
  worker serves the federation listener (`handlers/federation.py:1134`), with no
  replication hop.
- **Each worker keeps its own rule cache**, refreshed independently.
- **Rule changes propagate fast.** `on_new_event` is dispatched both by the
  persister (`notifier.py:413` via `handlers/message.py:2211`) *and* by every
  worker that receives the events replication stream
  (`replication/tcp/client.py:222`), so with `watch_control_room: true` a `!guard`
  command takes effect on all workers within replication latency. With it off
  (the default), worst case is `refresh_interval_s` (default 15 s) per worker.
- **`notify_room` works on any worker.** `create_and_send_event_into_room` goes
  through `create_and_send_nonmember_event`, which forwards to the room's event
  writer over replication when the local instance is not it
  (`handlers/message.py:1779-1802`).
- Everything else the module calls (`get_room_state`, `is_user_admin`,
  `is_mine`, `run_as_background_process`) is a worker-store read or local
  helper, available everywhere.

## Control room setup

1. As an admin, create a **private, unencrypted** room. Do not set an alias,
   do not publish it, and never invite the protected users.
   (Encryption is unnecessary — state events are never encrypted — and would
   make the module's server-side notices show as "unencrypted".)
2. Set power levels so only you (and the bot) can write rules. Keep
   `state_default: 100` and grant the six types the bot needs at 50, in the
   `events` map of `m.room.power_levels`:

   ```json
   "events": {
     "guardian.protected_user": 50,
     "guardian.allowed_server": 50,
     "guardian.allowed_user": 50,
     "guardian.blocked_user": 50,
     "guardian.blocked_server": 50,
     "guardian.effective_rules": 50
   }
   ```

   `guardian.effective_rules` is written by the **module** as `notify_user`
   (see below), not by you; without it the bot cannot show static rules.

   These levels are also what the module trusts: from 0.5.0 a local user's
   rules are honoured exactly when they could send that state event themselves.
   Granting someone 50 here makes them a rule administrator — deliberately, and
   visibly, in the room's own state. Server admins are honoured regardless, and
   so is the room's creator under room version 12, where Matrix forbids listing
   them in `users` at all.
3. Invite the bot account and have it join. Disable auto-join on the maubot
   client (Manage clients → Autojoin off) so it can never be lured elsewhere.
   Use a strong maubot admin password; the maubot UI can send anything as the
   bot.
4. Put the room ID in `control_room` (module) and in the plugin config.

Rules are state events, one per entry. Empty content means "removed":

| type                          | state_key                      | content                                           |
|-------------------------------|--------------------------------|---------------------------------------------------|
| `guardian.protected_user` | `kid:example.org` (no `@`)     | `{"entity": "@kid:example.org", "added_by", "ts", "reason"?}` |
| `guardian.allowed_server` | `friends.org` / `*.skole.no`   | `{"entity": "friends.org", ...}`                  |
| `guardian.allowed_user`   | `granny:other.org`             | `{"entity": "@granny:other.org", ...}`            |
| `guardian.blocked_user`   | `troll:friends.org`            | `{"entity": "@troll:friends.org", ...}`           |
| `guardian.blocked_server` | `evil.skole.no`                | `{"entity": "evil.skole.no", ...}`                |

### What the module publishes back

When `control_room` and `notify_user` are both set, the module keeps one extra
state event in the room, `guardian.effective_rules` (state key `""`), sent
as `notify_user`:

```json
{
  "static":    {"protected_users": [...], "allowed_servers": [...], "...": []},
  "effective": {"...": "static merged with the room rules the module accepted"},
  "dry_run": false,
  "uninvited_joins": "known_rooms"
}
```

The bot is an ordinary Matrix client and cannot read `homeserver.yaml`, so this
is how `!guard list` shows the static baseline and how `!guard check` answers with
the rules actually in force. It is rewritten only when the content changes, and
a restart re-reads it first rather than rewriting an identical event. If
`notify_user` lacks power to send it, the module logs one warning and carries
on — enforcement is unaffected, and the bot falls back to room rules only.

The entity is read from `content.entity` (falling back to the state key,
which only works for server entries since user IDs need the `@`). State keys
cannot start with `@` unless the sender *is* that user, hence the stripped
form. `!guard remove`/`unblock`/`unprotect` clear every entry whose entity
matches, whatever its state key. Changes take effect immediately on a monolith (the module
listens for new events) and within `refresh_interval_s` on other workers.
If the room becomes unreadable, the module keeps the last known rules.

## The bot

```
!guard protect @kid:example.org [reason]     !guard unprotect @kid:example.org
!guard allow server <glob> [reason]          !guard remove server <glob>
!guard allow user <mxid|glob> [reason]       !guard remove user <mxid|glob>
!guard block user <mxid|glob> [reason]       !guard unblock user <mxid|glob>
!guard block server <glob> [reason]          !guard unblock server <glob>
!guard list                                  # grouped, with who/when/why, plus static rules
!guard check @someone:server.org             # evaluate with the same rule code
```

Hardening, so the bot can never be abused to grant rights:

- `control_room` is required in the plugin config; commands anywhere else are
  ignored without a reply. (maubot itself still answers a bare `!guard` with
  usage text in any room the bot is in — another reason to keep autojoin off.)
- Before any change the bot reads `m.room.power_levels` and refuses unless
  the sender could send that state event type themselves.
- Optional `admins: [...]` in the plugin config restricts further.
- Only local users can be protected; the bot refuses to protect the sender
  themselves and reminds you that Synapse admins bypass the checks.
- Every entry records `added_by` and `ts`; `!guard list` shows them.
- Catch-all globs in allow lists are refused (same validation as the module).

Build: `make bot-build` copies `synapse_guardian/policy.py` into the plugin
(maubot plugins are self-contained zips) and runs `mbc build` if available;
otherwise run `mbc build` in `bot/` yourself and upload the `.mbp`.

## Cleaning up pending invites

Invites that arrived before the module was enabled, or while `dry_run` was on,
are not re-evaluated (accepting an existing invite is trusted). Run:

```sh
scripts/reject_pending_invites.py --homeserver https://matrix.example.org \
    --admin-token <admin token> --users @kid:example.org [--dry-run]
```

It uses the admin "login as user" API, reads pending invites via `/sync` and
leaves them, then logs the temporary token out.

## Known gaps

- **Strangers joining later.** Once a protected user is in a room, other
  members can invite anyone into that room. Mitigations: keep kids in rooms
  you control (set `m.room.server_acl`), or phase 2 (below).
- **Remote knocks.** A protected user knocking on a room on another server
  cannot be intercepted in Synapse 1.161; it leaks their display name/avatar,
  but the resulting invite is still blocked. Local knocks are blocked.
- **3PID invites to the child's e-mail** exchanged via an identity server bypass
  `user_may_invite`. Do not bind the kids' e-mail/phone to an identity server
  and set `enable_3pid_lookup: false`.
- **Local users.** If your own server is in `allowed_servers`, every local
  account may invite the kids. Keep registration closed, or list the local
  users individually instead of the server.
- **Server admins bypass everything.** Synapse never calls `user_may_invite`
  or `user_may_join_room` for admins. A protected account must not be an
  admin; the module logs an error (and notifies) if it is.
- Server names with a port (`ex.org:8448`) do not match the bare glob `ex.org`.
- Room upgrades of the control room are not followed; update `control_room`.
- Workers: enforcement is complete on every worker (see [Workers](#workers)).
  Rule *changes* propagate within replication latency, or within
  `refresh_interval_s` if `watch_control_room` is off.

## Phase 2 ideas

- Auto-leave: when a non-allowed user joins a room a protected user is in,
  make the protected user leave (`on_new_event`).
- Set `m.room.server_acl` on rooms protected users create.
- `notify_via: bot` — deliver notices through a webhook to the maubot plugin so
  they can be encrypted/richer. The module already routes notices through a
  small `Notifier` interface (`synapse_guardian/notify.py`) for this.
- Per-child rule overrides.

## Development

```sh
make venv            # .venv with matrix-synapse 1.161 + test deps
make synapse-tests   # sparse checkout of Synapse's tests/ package (not shipped in the wheel)
make test            # pytest (policy, store) + trial (end-to-end HomeserverTestCase)
make lint
```

[`docs/callbacks.md`](docs/callbacks.md) is a verified inventory of every
Synapse module callback relevant here: what each one costs, whether it fires for
local or federated events, which ones server admins bypass, and why we use or
avoid each. The upstream docs cover none of that. It is pinned by
`guardian_tests/test_synapse_contract.py` — **after upgrading Synapse, run
`make test-unit`**, which fails with an actionable message if an assumption in
that document stopped holding.
