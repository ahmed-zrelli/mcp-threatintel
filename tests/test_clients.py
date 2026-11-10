"""Client parse/format tests. No real network: the HTTP layer is mocked."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel.clients.cisa import CisaClient  # noqa: E402


@pytest.mark.asyncio
async def test_cisa_shapes_kev_catalog(monkeypatch):
    """get_kev_catalog maps the raw CISA payload to the cache row schema."""
    raw = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "shortDescription": "Remote code execution.",
                "dateAdded": "2024-01-02",
                "dueDate": "2024-01-23",
                "knownRansomwareCampaignUse": "Known",
                "notes": "patch now",
            },
            # Entry with no cveID must be dropped.
            {"vendorProject": "NoCve"},
        ]
    }

    client = CisaClient()

    async def fake_get(path, params=None):
        return raw

    monkeypatch.setattr(client, "get", fake_get)

    rows = await client.get_kev_catalog()
    await client.close()

    assert len(rows) == 1
    row = rows[0]
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["vendor"] == "Acme"
    assert row["product"] == "Widget"
    assert row["vulnerability_name"] == "Acme Widget RCE"
    assert row["description"] == "Remote code execution."
    assert row["known_ransomware"] == "Known"
    assert "raw_json" in row


def test_otx_shape_pulse_accepts_strings_and_objects():
    import json

    from mcp_threatintel.clients.otx import OtxClient

    c = OtxClient.__new__(OtxClient)
    as_strings = c.shape_pulse({"id": "1", "name": "n", "attack_ids": ["T1562.001", "T1555"], "malware_families": ["XMRig"]})
    as_objects = c.shape_pulse({"id": "2", "name": "n", "attack_ids": [{"id": "T1059", "name": "x"}],
                                "malware_families": [{"id": "m", "display_name": "Emotet"}]})
    assert json.loads(as_strings["attack_ids"]) == ["T1562.001", "T1555"]
    assert json.loads(as_objects["attack_ids"]) == ["T1059"]
    assert json.loads(as_objects["malware_families"]) == ["Emotet"]
    assert c.shape_indicators("1", ["junk", {"indicator": "evil.example", "type": "domain"}]) == [("1", "evil.example", "domain")]
