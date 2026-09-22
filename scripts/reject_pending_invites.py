#!/usr/bin/env python3
"""Reject pending invites for protected users.

family_guard trusts `is_invited` joins, so invites that arrived before the
module was enabled (or while `dry_run: true`) would still be joinable. Run this
once after enabling the module to clean them up.

For each protected user it obtains a short-lived access token via the Synapse
admin "login as user" API, reads pending invites from /sync, and leaves them.

Usage:
  reject_pending_invites.py --homeserver https://matrix.example.org \
      --admin-token <token> --users @kid1:example.org @kid2:example.org [--dry-run]
  reject_pending_invites.py --homeserver ... --admin-token ... --config homeserver.yaml

Only the standard library (plus PyYAML when --config is used) is required.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

SYNC_FILTER = json.dumps(
    {"room": {"timeline": {"limit": 0}, "state": {"lazy_load_members": True}}}
)


def request(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {url} failed: {e.code} {e.read().decode(errors='replace')}")


def users_from_config(path: str) -> list[str]:
    try:
        import yaml
    except ImportError:
        raise SystemExit("--config needs PyYAML (pip install pyyaml)")
    with open(path) as f:
        cfg = yaml.safe_load(f)
    for module in cfg.get("modules", []):
        if str(module.get("module", "")).startswith("family_guard"):
            return list((module.get("config") or {}).get("protected_users") or [])
    raise SystemExit("no family_guard module found in config")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--homeserver", required=True, help="base URL, e.g. https://matrix.example.org")
    ap.add_argument("--admin-token", required=True)
    ap.add_argument("--users", nargs="*", default=[], help="protected user IDs")
    ap.add_argument("--config", help="homeserver.yaml to read protected_users from")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    users = list(args.users)
    if args.config:
        users += users_from_config(args.config)
    if not users:
        ap.error("no users given (use --users or --config)")

    hs = args.homeserver.rstrip("/")
    for user_id in users:
        quoted = urllib.parse.quote(user_id)
        login = request("POST", f"{hs}/_synapse/admin/v1/users/{quoted}/login", args.admin_token, {})
        token = login["access_token"]
        sync = request(
            "GET",
            f"{hs}/_matrix/client/v3/sync?timeout=0&filter={urllib.parse.quote(SYNC_FILTER)}",
            token,
        )
        invites = sync.get("rooms", {}).get("invite", {})
        if not invites:
            print(f"{user_id}: no pending invites")
        for room_id, data in invites.items():
            inviter = next(
                (
                    ev.get("sender")
                    for ev in data.get("invite_state", {}).get("events", [])
                    if ev.get("type") == "m.room.member" and ev.get("state_key") == user_id
                ),
                "?",
            )
            if args.dry_run:
                print(f"{user_id}: would reject invite to {room_id} from {inviter}")
                continue
            request("POST", f"{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room_id)}/leave", token, {})
            print(f"{user_id}: rejected invite to {room_id} from {inviter}")
        # revoke the temporary token
        request("POST", f"{hs}/_matrix/client/v3/logout", token, {})
    return 0


if __name__ == "__main__":
    sys.exit(main())
