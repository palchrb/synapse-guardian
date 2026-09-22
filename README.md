# family_guard

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

## Installation

Into the Python environment Synapse runs in:

```sh
pip install git+https://github.com/<you>/family-guard.git   # or: pip install .
```

Debian packages from packages.matrix.org: use `/opt/venvs/matrix-synapse/bin/pip`. Docker: build an overlay
image:

```Dockerfile
FROM matrixdotorg/synapse
RUN pip install git+https://github.com/<you>/family-guard.git
```

## Configuration (`homeserver.yaml`)

```yaml
modules:
  - module: family_guard.FamilyGuard
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
      notify_user: "@family-guard-bot:example.org"  # required with notify_room
      notify_dedupe_s: 300
      trusted_senders: []                    # extra local users whose room entries count
      refresh_interval_s: 30
      dry_run: false                         # log/notify only, never block
```

- `uninvited_joins`: what happens when a protected user tries to join a room
  without an invite. `deny` always refuses. `known_rooms` allows it only if at
  least one local user is already joined **and** every joined/invited member is
  allowed by the rules (rooms the server is not in are refused, because we
  cannot see who is there).
- `notify_user` must be a local user that is already **joined** to the control
  room — normally the maubot account. The module does not create or join users.
- `trusted_senders`: room entries count only if their sender is a local server
  admin, `notify_user`, or listed here. Power levels are the real gate; this is
  a second layer.
- `dry_run` still logs and notifies (prefixed `[dry-run]`) so you can calibrate
  before enforcing. Remember to run `scripts/reject_pending_invites.py`
  afterwards (see gaps).

Config errors make Synapse refuse to start.

## Control room setup

1. As an admin, create a **private, unencrypted** room. Do not set an alias,
   do not publish it, and never invite the protected users.
   (Encryption is unnecessary — state events are never encrypted — and would
   make the module's server-side notices show as "unencrypted".)
2. Set power levels so only you (and the bot) can write rules:
   `state_default: 100`, or per type in `events`:
   `family_guard.protected_user`, `family_guard.allowed_server`,
   `family_guard.allowed_user`, `family_guard.blocked_user`,
   `family_guard.blocked_server`. Give the bot exactly that level.
3. Invite the bot account and have it join. Disable auto-join on the maubot
   client (Manage clients → Autojoin off) so it can never be lured elsewhere.
   Use a strong maubot admin password; the maubot UI can send anything as the
   bot.
4. Put the room ID in `control_room` (module) and in the plugin config.

Rules are state events, one per entry. Empty content means "removed":

| type                          | state_key                      | content                                           |
|-------------------------------|--------------------------------|---------------------------------------------------|
| `family_guard.protected_user` | `kid:example.org` (no `@`)     | `{"entity": "@kid:example.org", "added_by", "ts", "reason"?}` |
| `family_guard.allowed_server` | `friends.org` / `*.skole.no`   | `{"entity": "friends.org", ...}`                  |
| `family_guard.allowed_user`   | `granny:other.org`             | `{"entity": "@granny:other.org", ...}`            |
| `family_guard.blocked_user`   | `troll:friends.org`            | `{"entity": "@troll:friends.org", ...}`           |
| `family_guard.blocked_server` | `evil.skole.no`                | `{"entity": "evil.skole.no", ...}`                |

The entity is read from `content.entity` (falling back to the state key,
which only works for server entries since user IDs need the `@`). State keys
cannot start with `@` unless the sender *is* that user, hence the stripped
form. `!fg remove`/`unblock`/`unprotect` clear every entry whose entity
matches, whatever its state key. Changes take effect immediately on a monolith (the module
listens for new events) and within `refresh_interval_s` on other workers.
If the room becomes unreadable, the module keeps the last known rules.

## The bot

```
!fg protect @kid:example.org [reason]     !fg unprotect @kid:example.org
!fg allow server <glob> [reason]          !fg remove server <glob>
!fg allow user <mxid|glob> [reason]       !fg remove user <mxid|glob>
!fg block user <mxid|glob> [reason]       !fg unblock user <mxid|glob>
!fg block server <glob> [reason]          !fg unblock server <glob>
!fg list                                  # grouped, with who/when/why
!fg check @someone:server.org             # evaluate with the same rule code
```

Hardening, so the bot can never be abused to grant rights:

- `control_room` is required in the plugin config; commands anywhere else are
  ignored without a reply. (maubot itself still answers a bare `!fg` with
  usage text in any room the bot is in — another reason to keep autojoin off.)
- Before any change the bot reads `m.room.power_levels` and refuses unless
  the sender could send that state event type themselves.
- Optional `admins: [...]` in the plugin config restricts further.
- Only local users can be protected; the bot refuses to protect the sender
  themselves and reminds you that Synapse admins bypass the checks.
- Every entry records `added_by` and `ts`; `!fg list` shows them.
- Catch-all globs in allow lists are refused (same validation as the module).

Build: `make bot-build` copies `family_guard/policy.py` into the plugin
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
- Workers: rule changes propagate within `refresh_interval_s`.

## Phase 2 ideas

- Auto-leave: when a non-allowed user joins a room a protected user is in,
  make the protected user leave (`on_new_event`).
- Set `m.room.server_acl` on rooms protected users create.
- `notify_via: bot` — deliver notices through a webhook to the maubot plugin so
  they can be encrypted/richer. The module already routes notices through a
  small `Notifier` interface (`family_guard/notify.py`) for this.
- Per-child rule overrides.

## Development

```sh
make venv            # .venv with matrix-synapse 1.161 + test deps
make synapse-tests   # sparse checkout of Synapse's tests/ package (not shipped in the wheel)
make test            # pytest (policy, store) + trial (end-to-end HomeserverTestCase)
make lint
```
