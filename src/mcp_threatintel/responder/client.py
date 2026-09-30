"""HostAgentClient: the MCP server's side of the agent channel."""

from __future__ import annotations

from .protocol import ProtocolError, request


class AgentError(RuntimeError):
    pass


class HostAgentClient:
    def __init__(self, addr: str, token: str, timeout: float = 60):
        self.addr = addr
        self.token = token
        self.timeout = timeout

    async def call(self, op: str, **params):
        if not self.token:
            raise AgentError("AGENT_TOKEN is not configured for the MCP server")
        try:
            resp = await request(self.addr, op, params, self.token, timeout=self.timeout)
        except ProtocolError as e:
            raise AgentError(str(e)) from e
        if not resp.get("ok"):
            raise AgentError(resp.get("error", "unknown agent error"))
        return resp["data"]
