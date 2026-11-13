"""threatintel-watch: the AI responder on the analyst PC.

Detection and the first response run on the server, inside the host agent: the rules execute the
clear-cut cases themselves (threat-feed matches, brute force, port scans, reverse shells), even when
this PC is off. What the rules cannot handle is routed to the AI ("ai" route): unusual behavior,
refused or failed actions, attacks that persist.

This program, started with the console (scripts/windows/start-console.ps1), closes the loop:
  1. it long-polls the server for new alerts and logs / notifies them;
  2. it takes every alert routed to the AI (new ones, and the backlog raised while the PC was off),
     lets the local model investigate it in a fresh conversation, and the model DECIDES with
     resolve_alert (execute / dismiss / escalate) — no human approval;
  3. it saves the model's report on the alert (shown on the dashboard).
If llama-server is not running, AI alerts wait and are picked up as soon as it is.
Log: %LOCALAPPDATA%\\threatintel\\watch.log
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastmcp import Client

from .llm import budgets, compact, context_size, investigate
from .notify import notify

STATE_DIR = Path(os.getenv("LOCALAPPDATA") or Path.home()) / "threatintel"
MAX_TOASTS_PER_POLL = 3
MAX_AI_ATTEMPTS = 2          # after that the alert is escalated to the analyst
RETRY_AFTER_S = 60           # wait before retrying an alert (model busy, not running, no decision)
_log_file = None


def out(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    if sys.stdout is not None:
        try:
            print(line, flush=True)
        except (OSError, ValueError):
            pass
    if _log_file:
        try:
            with open(_log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def _text(result) -> object:
    try:
        return json.loads(result.content[0].text)
    except (ValueError, IndexError, AttributeError):
        return {"error": "unreadable tool result"}


def route_of(alert: dict) -> str | None:
    return (alert.get("detail") or {}).get("route")


def needs_ai(alert: dict) -> bool:
    return route_of(alert) == "ai" and not alert.get("resolution")


def approve_hint(actions: list[dict]) -> str:
    """What happened to the alert's actions, in one line."""
    done = [a for a in actions if a.get("status") in ("approved", "executed")]
    waiting = [a for a in actions if a.get("status") == "pending" and a.get("id")]
    parts = []
    if done:
        parts.append("Executed: " + ", ".join(f"#{a['id']} {a.get('type')}" for a in done))
    if waiting:
        parts.append("Waiting for the AI: " + ", ".join(f"#{a['id']} {a.get('type')}" for a in waiting))
    return " | ".join(parts) or "No action."


def describe(action: dict) -> str:
    return f"#{action.get('id')} {action.get('type')} {str(action.get('target'))[:50]}: {action.get('status')}"


class LastSeen:
    """Id of the last alert shown, so restarts do not repeat old notifications."""

    def __init__(self, path: Path):
        self.path = path

    def get(self) -> int | None:
        try:
            return int(self.path.read_text().strip())
        except (OSError, ValueError):
            return None

    def set(self, value: int) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(str(value))
        except OSError:
            pass


async def llm_available(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=3) as http:
            return (await http.get(f"{url.rstrip('/')}/health")).status_code == 200
    except httpx.HTTPError:
        return False


#: Incident events that deserve a notification ("grew" = another finding of an attack already notified).
NOTIFY_EVENTS = {None, "new", "reopened", "escalated", "persisting"}
EVENT_LABEL = {"new": "NEW ATTACK", "reopened": "ATTACK BACK", "escalated": "ESCALATED",
               "persisting": "STILL ACTIVE", "grew": "same attack"}


def announce(alert: dict, toast: bool) -> None:
    """Instant part: log (and notify) the alert as soon as the server raised it."""
    actions = alert.get("actions") or []
    sev = alert.get("severity", "?").upper()
    event = alert.get("incident_event")
    inc = f"incident #{alert['incident_id']} " if alert.get("incident_id") else ""
    label = EVENT_LABEL.get(event, "")
    handler = {"rules": "handled by the rules", "ai": "sent to the AI"}.get(route_of(alert), "")
    if toast and event in NOTIFY_EVENTS:
        notify(f"ThreatIntel {sev} {label} {inc}- {alert['title']}", [handler, approve_hint(actions)])
    out(f"ALERT #{alert['id']} ({sev}) {inc}{label}: {alert['title']}" + (f"  [{handler}]" if handler else ""))
    for a in actions:
        out(f"    - {describe(a)}")


class Responder:
    """Runs the AI on the alerts the rules could not handle, one at a time, with retries."""

    def __init__(self, mcp, args):
        self.mcp = mcp
        self.args = args
        self.attempts: dict[int, int] = {}
        self.next_try: dict[int, float] = {}
        self.busy: set[int] = set()
        self.waiting_logged = False

    def due(self, alert_id: int) -> bool:
        return alert_id not in self.busy and time.time() >= self.next_try.get(alert_id, 0)

    async def queue(self) -> list[dict]:
        data = _text(await self.mcp.call_tool("list_alerts", {"ai_queue": True}))
        if isinstance(data, dict) and isinstance(data.get("ai_queue"), list):
            return data["ai_queue"]
        if not getattr(self, "old_agent_logged", False):   # an older agent answers with plain alerts: never act on those
            out("    the host agent does not support the AI queue yet (update it on the server); AI responder idle")
            self.old_agent_logged = True
        return []

    async def sweep(self, jobs: asyncio.Queue) -> None:
        """Queue every AI-routed alert not decided yet (new ones and the backlog)."""
        for alert in await self.queue():
            if self.due(alert["id"]):
                self.busy.add(alert["id"])
                jobs.put_nowait(alert)

    async def decide(self, alert: dict) -> None:
        try:
            await investigate_alert(self.mcp, alert, self.args, toast=True, responder=self)
        finally:
            self.busy.discard(alert["id"])


async def investigate_alert(mcp, alert: dict, args, toast: bool, responder: Responder | None = None) -> None:
    """The model investigates the alert in a fresh conversation and decides it (resolve_alert)."""
    alert_id = alert["id"]
    full = _text(await mcp.call_tool("list_alerts", {"alert_id": alert_id}))
    if not isinstance(full, dict) or full.get("error"):
        full = alert
    if full.get("resolution"):
        return
    if args.no_ai or not await llm_available(args.llm_url):
        if responder:
            responder.next_try[alert_id] = time.time() + RETRY_AFTER_S
            if not responder.waiting_logged:
                out(f"    Qwen is not running at {args.llm_url}: AI alerts wait until it starts")
                responder.waiting_logged = True
        return
    if responder:
        responder.waiting_logged = False
    actions = full.get("actions") or []
    brief_budget, _ = budgets(getattr(args, "llm_context", None))
    detail = {k: v for k, v in (full.get("detail") or {}).items() if k not in ("evidence", "actions", "route")}
    brief = {"alert": {k: full.get(k) for k in ("id", "ts", "kind", "severity", "title", "incident_event")},
             "why_you": "the rules could not handle this alert alone",
             "incident": full.get("incident"),
             "detail": detail,
             "proposed_actions": [{k: a.get(k) for k in ("id", "type", "target", "status", "error")} for a in actions],
             "evidence": (full.get("detail") or {}).get("evidence")}
    text = json.dumps(compact(brief), default=str, separators=(",", ":"))
    if len(text) > brief_budget:
        text = json.dumps(compact(brief, 5, 150), default=str, separators=(",", ":"))[:brief_budget]
    out(f"    AI investigating alert #{alert_id} (Qwen)...")
    try:
        report, _more = await investigate(mcp, args.llm_url, text, timeout=args.llm_timeout,
                                          ctx=getattr(args, "llm_context", None))
    except Exception as e:
        out(f"    AI failed on alert #{alert_id}: {e}")
        report = None
    if report:
        try:
            await mcp.call_tool("save_alert_report", {"alert_id": alert_id, "report": report})
        except Exception as e:
            out(f"    could not save the report ({e})")
        out("    REPORT (qwen):\n      " + report.replace("\n", "\n      "))
    after = _text(await mcp.call_tool("list_alerts", {"alert_id": alert_id}))
    if isinstance(after, dict) and after.get("resolution"):
        res = after["resolution"]
        done = [a for a in after.get("actions") or [] if a.get("status") in ("approved", "executed")]
        out(f"    DECISION by {after.get('resolution_by')}: {res} - {after.get('resolution_note')}")
        if toast:
            title = {"executed": "AI executed", "partially_executed": "AI partly executed",
                     "dismissed": "AI dismissed (false positive)", "escalated": "AI escalated to you"}.get(res, res)
            lines = [", ".join(f"{a['type']} {str(a['target'])[:30]}" for a in done)
                     or (after.get("resolution_note") or "")[:150], "Undo anytime: Rollback on the dashboard."]
            notify(f"ThreatIntel - {title} alert #{alert_id}", lines)
        return
    # The model did not decide (context full, no tool call...): retry, then escalate.
    if responder:
        n = responder.attempts.get(alert_id, 0) + 1
        responder.attempts[alert_id] = n
        if n < MAX_AI_ATTEMPTS:
            responder.next_try[alert_id] = time.time() + RETRY_AFTER_S
            out(f"    no decision for alert #{alert_id}; retrying in {RETRY_AFTER_S}s (attempt {n}/{MAX_AI_ATTEMPTS})")
            return
    await mcp.call_tool("resolve_alert", {"alert_id": alert_id, "decision": "escalate",
                                          "justification": "The AI responder could not reach a decision "
                                                           "after several attempts; left for the analyst."})
    out(f"    alert #{alert_id} escalated: the AI could not decide")


async def poll(mcp, last: LastSeen, args, jobs: asyncio.Queue | None = None) -> None:
    """One long poll: log / notify new alerts; AI-routed ones go to the responder."""
    since = last.get()
    params = {"since_id": since or 0, "limit": 50}
    if since is not None:
        params["wait_s"] = getattr(args, "wait", 25)
    alerts = _text(await mcp.call_tool("list_alerts", params))
    if isinstance(alerts, dict):
        raise RuntimeError(alerts.get("error", "list_alerts failed"))
    if not alerts:
        if since is None:
            last.set(0)
        return
    if since is None:
        # First run on this PC: summarise what is already there instead of replaying it.
        worst = sorted(alerts, key=lambda a: ["critical", "high", "medium", "low"].index(a.get("severity", "low")))[0]
        notify(f"ThreatIntel - {len(alerts)} alert(s) on the server", [f"Latest: {alerts[-1]['title']}",
                                                                       f"Most severe: {worst['title']}"])
        out(f"{len(alerts)} existing alert(s) on the server; the AI takes the undecided ones")
        last.set(alerts[-1]["id"])
        return
    for i, alert in enumerate(alerts):
        announce(alert, i < MAX_TOASTS_PER_POLL)
        last.set(alert["id"])
        if needs_ai(alert) and jobs is None:
            await investigate_alert(mcp, alert, args, toast=i < MAX_TOASTS_PER_POLL)
    if len(alerts) > MAX_TOASTS_PER_POLL:
        notify(f"ThreatIntel - {len(alerts)} new alerts", ["More alerts than notifications shown.",
                                                          "See the dashboard: http://127.0.0.1:3720"])


async def run(args) -> None:
    last = LastSeen(STATE_DIR / "watch_last_alert.txt")
    token = os.getenv("MCP_THREATINTEL_AUTH_TOKEN") or None
    out(f"AI responder: server {args.mcp_url}, model {'off' if args.no_ai else args.llm_url} "
        f"(context {args.llm_context} tokens). Rules act on the server; the AI decides what they cannot.")
    warned = False
    while True:
        try:
            async with Client(args.mcp_url, auth=token) as mcp:
                out("connected to the MCP server")
                warned = False
                responder = Responder(mcp, args)
                jobs: asyncio.Queue = asyncio.Queue()

                async def worker():
                    while True:
                        alert = await jobs.get()
                        try:
                            await responder.decide(alert)
                        except Exception as e:
                            out(f"    AI handling of alert #{alert.get('id')} failed: {e}")
                            responder.busy.discard(alert.get("id"))

                task = asyncio.create_task(worker())
                try:
                    while True:
                        await poll(mcp, last, args, jobs)
                        await responder.sweep(jobs)
                        if args.once:
                            while not jobs.empty():
                                await responder.decide(jobs.get_nowait())
                            return
                finally:
                    task.cancel()
        except Exception as e:
            if not warned:
                out(f"MCP server unreachable ({e}); retrying every {args.interval}s")
                warned = True
            if args.once:
                return
            await asyncio.sleep(args.interval)


def main(argv: list[str] | None = None) -> None:
    global _log_file
    load_dotenv()
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    p = argparse.ArgumentParser(prog="threatintel-watch", description="AI responder for mcp-threatintel")
    p.add_argument("--mcp-url", default=os.getenv("WATCH_MCP_URL", "http://127.0.0.1:3707/mcp"))
    p.add_argument("--llm-url", default=os.getenv("WATCH_LLM_URL", "http://127.0.0.1:8080"))
    p.add_argument("--llm-context", type=int, default=context_size(),
                   help="llama-server context size (-c), used to size what is sent to the model")
    p.add_argument("--interval", type=int, default=int(os.getenv("WATCH_INTERVAL", "15")),
                   help="seconds between reconnection attempts when the server is unreachable")
    p.add_argument("--wait", type=float, default=25, help="long-poll wait on the server (max 25 s)")
    p.add_argument("--llm-timeout", type=float, default=300)
    p.add_argument("--no-ai", action="store_true", help="log / notify only, no model")
    p.add_argument("--once", action="store_true", help="one poll and one AI sweep, then exit")
    p.add_argument("--log-file", default=str(STATE_DIR / "watch.log"))
    args = p.parse_args(argv)
    _log_file = args.log_file
    Path(_log_file).parent.mkdir(parents=True, exist_ok=True)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        out("stopped")


if __name__ == "__main__":
    main()
