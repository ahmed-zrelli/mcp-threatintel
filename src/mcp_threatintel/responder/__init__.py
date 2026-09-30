"""Host agent (threatintel-responder): the only privileged component.

The MCP server can ask it to scan the host or to *create* an action; only the
analyst, through threatintel-approve on the admin channel, can approve one.
"""
