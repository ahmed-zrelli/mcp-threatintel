"""threatintel-approve: the analyst's approval CLI (admin channel, outside the LLM).

    threatintel-approve list [--status pending|all|...]
    threatintel-approve show <id>
    threatintel-approve approve <id>
    threatintel-approve reject <id> [--reason TEXT]
    threatintel-approve audit [--id N] [--limit N]

Needs read access to the admin token file, i.e. an elevated terminal.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .config import ResponderConfig
from .protocol import ProtocolError, request_sync


def _token(config: ResponderConfig) -> str:
    try:
        return config.admin_token_file.read_text(encoding="utf-8").strip()
    except PermissionError:
        sys.exit(f"cannot read {config.admin_token_file}: run this from an elevated (Administrator/root) terminal")
    except FileNotFoundError:
        sys.exit(f"{config.admin_token_file} not found: start threatintel-responder first")


def _call(config: ResponderConfig, op: str, **params):
    try:
        resp = request_sync(config.admin_addr, op, params, _token(config))
    except ProtocolError as e:
        sys.exit(str(e))
    if not resp.get("ok"):
        sys.exit(f"error: {resp.get('error')}")
    return resp["data"]


def _row(a: dict) -> str:
    flags = " [dry-run]" if a["dry_run"] else ""
    return f"{a['id']:>4}  {a['status']:<11} {a['type']:<16} {a['target'][:48]:<48}{flags}"


def _print_action(a: dict) -> None:
    print(_row(a))
    print(f"      reason      : {a['reason'] or '-'}")
    print(f"      requested by: {a['requested_by']} at {a['created_at']}")
    if a.get("approved_by"):
        print(f"      approved by : {a['approved_by']}")
    if a.get("executed_at"):
        print(f"      executed at : {a['executed_at']}")
    if a.get("expires_at"):
        print(f"      expires at  : {a['expires_at']}")
    if a.get("rollback_of"):
        print(f"      rollback of : action {a['rollback_of']}")
    print(f"      params      : {json.dumps(a['params'])}")
    if a.get("commands"):
        print("      commands    :")
        for c in a["commands"]:
            print(f"        {c}")
    if a.get("error"):
        print(f"      error       : {a['error']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="threatintel-approve", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list", help="list actions (default: pending)")
    p.add_argument("--status", default="pending", help="pending, approved, executed, failed, rejected, "
                                                         "rolled_back, expired, or 'all'")
    p.add_argument("--limit", type=int, default=30)
    sub.add_parser("show", help="show one action and its audit trail").add_argument("id", type=int)
    sub.add_parser("approve", help="approve a pending action").add_argument("id", type=int)
    p = sub.add_parser("reject", help="reject a pending action")
    p.add_argument("id", type=int)
    p.add_argument("--reason", default="")
    p = sub.add_parser("alerts", help="show alerts from the always-on detection")
    p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("audit", help="show the audit log")
    p.add_argument("--id", type=int)
    p.add_argument("--limit", type=int, default=30)
    args = parser.parse_args(argv)

    config = ResponderConfig.from_env()
    actor = getpass.getuser()

    if args.cmd == "list":
        status = "" if args.status == "all" else args.status
        actions = _call(config, "list_actions", status=status, limit=args.limit)
        if not actions:
            print(f"no {args.status} actions")
        for a in actions:
            print(_row(a))
    elif args.cmd == "show":
        a = _call(config, "get_action", id=args.id)
        _print_action(a)
        print("      audit trail :")
        for e in a.get("audit", []):
            print(f"        {e['ts']}  {e['actor']:<22} {e['event']:<20} {json.dumps(e['details'])[:80]}")
    elif args.cmd == "approve":
        a = _call(config, "get_action", id=args.id)
        _print_action(a)
        a = _call(config, "approve", id=args.id, actor=actor)
        if a["status"] == "approved":
            print(f"\naction {args.id} approved; the host agent executes it within a second.")
        else:
            print(f"\naction {args.id} was NOT approved: {a['status']} ({a.get('error')})")
    elif args.cmd == "reject":
        _call(config, "reject", id=args.id, actor=actor, reason=args.reason)
        print(f"action {args.id} rejected")
    elif args.cmd == "alerts":
        alerts = _call(config, "list_alerts", limit=args.limit)
        if not alerts:
            print("no alerts")
        for a in alerts:
            print(f"#{a['id']:<4} {a['ts']}  {a['severity'].upper():<8} {a['title']}")
            for x in a.get("actions", []):
                print(f"        action {x['id']}: {x['type']} {x['target'][:40]} -> {x['status']}")
    elif args.cmd == "audit":
        for e in _call(config, "audit", id=args.id, limit=args.limit):
            print(f"{e['ts']}  #{e['action_id'] or '-':<5} {e['actor']:<22} {e['event']:<20} "
                  f"{json.dumps(e['details'])[:90]}")


if __name__ == "__main__":
    main()
