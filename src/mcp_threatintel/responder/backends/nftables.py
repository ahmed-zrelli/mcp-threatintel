"""Linux nftables backend for block_ip / block_feed_c2 (phase 2, VM lab).

Planned design: a dedicated table ``inet threatintel`` with a set
``blocklist { type ipv4_addr; flags timeout; }`` dropped on input and output,
filled with ``nft add element inet threatintel blocklist { <ip> timeout <ttl> }``.
"""

from __future__ import annotations

from .base import BackendError, ResponseBackend


class NftablesBackend(ResponseBackend):
    def apply(self, action: dict) -> dict:
        raise BackendError("nftables backend is not implemented yet (phase 2)")

    def rollback(self, action: dict, state: dict) -> dict:
        raise BackendError("nftables backend is not implemented yet (phase 2)")
