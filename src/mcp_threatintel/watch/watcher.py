"""threatintel-watch: the always-on loop.

    threatintel-watch --mcp-url http://192.168.21.129:3707/mcp

Every --interval seconds: scan_host on the protected server. For each NEW
finding (C2 connection, malicious file, SSH brute force):
  1. create the rule-based response actions as PENDING (the agent refuses
     duplicates and anything allowlisted);
  2. show a Windows notification with the approve commands;
  3. let the local model investigate (lookup_ioc, maybe more actions) and
     notify its short analysis.
Nothing is ever approved here: approval stays `threatintel-approve` on the server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from fastmcp import Client

from .findings import Finding, SeenStore, extract_findings
from .llm import investigate
from .notify import notify


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _text(result) -> dict:
    try:
        return json.loads(result.content[0].text)
    except (ValueError, IndexError, AttributeError):
        return {"error": "unreadable tool result"}


def describe(action: dict) -> str:
    status = action.get("status", "?")
    if action.get("error") and status != "pending":
        return f"{action.get('type')} {action.get('target')}: {status} ({action['error']})"
    dup = " (already existed)" if action.get("duplicate") else ""
    return f"#{action.get('id')} {action.get('type')} {action.get('target')}: {status}{dup}"


def approve_hint(actions: list[dict]) -> str:
    ids = [str(a["id"]) for a in actions if a.get("status") == "pending" and a.get("id")]
    if not ids:
        return "No action to approve."
    return "Approve on the server: " + " ; ".join(f"threatintel-approve approve {i}" for i in ids)


async def create_planned(mcp, findings: list[Finding]) -> list[dict]:
    actions: list[dict] = []
    for f in findings:
        for tool, args in f.plan:
            try:
                data = _text(await mcp.call_tool(tool, args))
            except Exception as e:
                data = {"type": tool, "target": str(args), "status": "error", "error": str(e)}
            data.setdefault("type", tool)
            actions.append(data)
    return actions


async def handle(mcp, findings: list[Finding], args) -> None:
    actions = await create_planned(mcp, findings)
    top = findings[0].severity.upper()  # findings are sorted, most severe first
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} new threats on the server"
    lines = [f.title for f in findings][:2] if len(findings) > 1 else [findings[0].detail.get("ioc") or ""]
    lines.append(approve_hint(actions))
    shown = notify(f"ThreatIntel {top} - " + title, lines)

    print(f"\n[{_ts()}] ===== ALERT ({top}) =====" + ("" if shown else " (notification not shown)"))
    for f in findings:
        print(f"  ! [{f.severity}] {f.title}")
    for a in actions:
        print(f"    - {describe(a)}")
    print(f"  {approve_hint(actions)}")

    if args.no_ai:
        return
    brief = {
        "new_findings": [{"kind": f.kind, "severity": f.severity, "title": f.title, "detail": f.detail}
                         for f in findings],
        "actions_already_created": [
            {k: a.get(k) for k in ("id", "type", "target", "status", "error")} for a in actions
        ],
    }
    print(f"[{_ts()}] AI investigating (Qwen)...")
    try:
        analysis, more = await investigate(mcp, args.llm_url, json.dumps(brief, default=str), timeout=args.llm_timeout)
    except Exception as e:
        print(f"[{_ts()}] AI unavailable ({e}); the alert above stands on its own.")
        return
    new = [a for a in more if a.get("id") not in {x.get("id") for x in actions}]
    print(f"[{_ts()}] AI analysis:\n  " + analysis.replace("\n", "\n  "))
    for a in new:
        print(f"    + AI added {describe(a)}")
    notify("ThreatIntel - AI analysis", [analysis[:200], approve_hint(actions + new) if new else ""])


async def run(args) -> None:
    store = Path(os.getenv("LOCALAPPDATA") or Path.home()) / "threatintel" / "watch_seen.json"
    seen = SeenStore(store, ttl_s=args.seen_ttl_hours * 3600)
    token = os.getenv("MCP_THREATINTEL_AUTH_TOKEN") or None
    print(f"[{_ts()}] threatintel-watch: server {args.mcp_url}, every {args.interval}s, "
          f"AI {'off' if args.no_ai else args.llm_url}")
    while True:
        try:
            async with Client(args.mcp_url, auth=token) as mcp:
                print(f"[{_ts()}] connected to the MCP server, watching...")
                while True:
                    report = _text(await mcp.call_tool("scan_host", {"minutes": args.window}))
                    if report.get("error"):
                        print(f"[{_ts()}] scan failed: {report['error']}")
                    else:
                        found = extract_findings(report)
                        fresh = seen.new_only(found)
                        if fresh:
                            await handle(mcp, fresh, args)
                        elif args.verbose:
                            print(f"[{_ts()}] scan ok, {len(found)} known finding(s), nothing new")
                    if args.once:
                        return
                    await asyncio.sleep(args.interval)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[{_ts()}] MCP server unreachable ({e}); retrying in {args.interval}s")
            if args.once:
                return
            await asyncio.sleep(args.interval)


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    p = argparse.ArgumentParser(prog="threatintel-watch", description="Always-on alerting for mcp-threatintel")
    p.add_argument("--mcp-url", default=os.getenv("WATCH_MCP_URL", "http://127.0.0.1:3707/mcp"))
    p.add_argument("--llm-url", default=os.getenv("WATCH_LLM_URL", "http://127.0.0.1:8080"))
    p.add_argument("--interval", type=int, default=int(os.getenv("WATCH_INTERVAL", "30")), help="seconds between scans")
    p.add_argument("--window", type=int, default=10, help="minutes of SSH logs checked for brute force")
    p.add_argument("--seen-ttl-hours", type=float, default=6, help="forget an alerted finding after this many hours")
    p.add_argument("--llm-timeout", type=float, default=300)
    p.add_argument("--no-ai", action="store_true", help="alerts and pending actions only, no model investigation")
    p.add_argument("--once", action="store_true", help="one scan, then exit")
    p.add_argument("--verbose", action="store_true", help="print a line after every scan")
    args = p.parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
