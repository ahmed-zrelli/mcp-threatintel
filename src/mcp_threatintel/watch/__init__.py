"""threatintel-watch: always-on monitoring from the analyst PC.

Every few seconds it asks the MCP server for a host scan; new findings raise a
Windows notification, get the suggested response actions created as PENDING
(never approved), and are investigated by the local model (Qwen via
llama-server) which explains the alert. Approval stays with the analyst.
"""
