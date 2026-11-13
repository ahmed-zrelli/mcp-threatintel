"""threatintel-console: the analyst's web dashboard (http://127.0.0.1:3720).

Runs on the analyst PC and talks to the host agent ONLY through the admin
channel (ADMIN_ADDR, admin token, TLS with the pinned agent certificate).
It shows alerts, incidents, pending actions (Approve / Reject), active
responses (Rollback), live SSH and port-scan activity, the audit trail and
the Human / AI decision switch, and generates incident reports.

The AI never starts from here: the model runs only when the analyst asks it
in the llama-server WebUI ("investigate alert N").

Browser safety: bound to 127.0.0.1 only; every API call must carry a per-start
random token (custom header, so other web pages cannot forge requests) and a
local Host header (no DNS rebinding); all data is inserted as text, never HTML.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import secrets

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

from ..responder.config import ResponderConfig
from ..responder.protocol import ProtocolError, request
from .page import PAGE

logger = logging.getLogger("threatintel.console")

LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class AdminClient:
    def __init__(self, config: ResponderConfig, actor: str):
        self.config = config
        self.actor = actor

    def _token(self) -> str:
        try:
            return self.config.admin_token_file.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ProtocolError(f"cannot read the admin token {self.config.admin_token_file}: {e}") from e

    async def call(self, op: str, **params):
        params.setdefault("actor", self.actor)
        resp = await request(self.config.admin_addr, op, params, self._token(), timeout=40)
        if not resp.get("ok"):
            raise ProtocolError(resp.get("error") or "agent error")
        return resp["data"]


def create_app(client: AdminClient, session_token: str | None = None) -> Starlette:
    token = session_token or secrets.token_urlsafe(24)

    def guard(req: Request) -> JSONResponse | None:
        host = (req.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in LOCAL_HOSTS:
            return JSONResponse({"error": "bad host"}, status_code=403)
        if not secrets.compare_digest(req.headers.get("x-dashboard-token", ""), token):
            return JSONResponse({"error": "missing or bad dashboard token (reload the page)"}, status_code=403)
        return None

    async def run(req: Request, op: str, **params):
        bad = guard(req)
        if bad:
            return bad
        try:
            return JSONResponse(await client.call(op, **params))
        except ProtocolError as e:
            return JSONResponse({"error": str(e)}, status_code=502)

    async def page(req: Request):
        host = (req.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in LOCAL_HOSTS:
            return PlainTextResponse("forbidden", status_code=403)
        return HTMLResponse(PAGE.replace("__TOKEN__", token), headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                       "img-src data:; connect-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})

    async def body(req: Request) -> dict:
        try:
            data = await req.json()
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    async def overview(req):
        return await run(req, "overview")

    async def alert(req):
        return await run(req, "list_alerts", alert_id=int(req.path_params["id"]))

    async def ssh(req):
        return await run(req, "ssh_activity", minutes=int(req.query_params.get("minutes", 15)))

    async def audit(req):
        return await run(req, "audit", limit=int(req.query_params.get("limit", 100)))

    async def report(req):
        inc = req.query_params.get("incident_id") or None
        return await run(req, "report", incident_id=int(inc) if inc else None,
                         hours=int(req.query_params.get("hours", 24)))

    async def act(req):
        verb, action_id = req.path_params["verb"], int(req.path_params["id"])
        b = await body(req)
        if verb == "approve":
            return await run(req, "approve", id=action_id)
        if verb == "reject":
            return await run(req, "reject", id=action_id, reason=str(b.get("reason") or "rejected on dashboard"))
        if verb == "rollback":
            return await run(req, "rollback", id=action_id, reason=str(b.get("reason") or "rolled back on dashboard"))
        return JSONResponse({"error": "unknown verb"}, status_code=404)

    async def mode(req):
        return await run(req, "set_decision_mode", mode=str((await body(req)).get("mode") or ""))

    return Starlette(routes=[
        Route("/", page),
        Route("/api/overview", overview),
        Route("/api/alerts/{id:int}", alert),
        Route("/api/ssh", ssh),
        Route("/api/audit", audit),
        Route("/api/report", report),
        Route("/api/actions/{id:int}/{verb}", act, methods=["POST"]),
        Route("/api/mode", mode, methods=["POST"]),
    ])


def main() -> None:
    p = argparse.ArgumentParser(description="mcp-threatintel analyst dashboard (local only)")
    p.add_argument("--port", type=int, default=3720)
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")
    config = ResponderConfig.from_env()
    import uvicorn

    app = create_app(AdminClient(config, f"dashboard:{getpass.getuser()}"))
    print(f"Dashboard: http://127.0.0.1:{args.port}   (agent admin channel: {config.admin_addr})")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
