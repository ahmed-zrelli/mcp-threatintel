"""Tests for the SQLite layer: schema init, per-call connect() round-trip, WAL."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel import db  # noqa: E402


def test_init_db_creates_schema_and_wal(tmp_path):
    path = str(tmp_path / "t.db")
    conn = db.init_db(path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        # Core tables exist.
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"iocs", "pulses", "vulnerabilities", "feed_sync"} <= names
    finally:
        conn.close()


def test_connect_roundtrips_an_ioc(tmp_path):
    path = str(tmp_path / "t.db")
    db.init_db(path).close()  # schema only

    with db.connect(path) as conn:
        inserted = db.upsert_ioc(
            conn,
            indicator="1.2.3.4",
            type="ip",
            source="urlhaus",
            first_seen=None,
            last_seen=db._now(),
            tags="malware",
            confidence=80,
            malware_family="emotet",
            threat_type="c2",
            raw_json="{}",
        )
        conn.commit()
        assert inserted is True

    # A fresh connection sees the committed row (proves it is a real file, not
    # an in-process handle).
    with db.connect(path) as conn:
        rows = db.lookup_indicator(conn, "1.2.3.4")
        assert len(rows) == 1
        assert rows[0]["source"] == "urlhaus"
        assert rows[0]["malware_family"] == "emotet"


def test_connect_applies_wal_each_time(tmp_path):
    path = str(tmp_path / "t.db")
    db.init_db(path).close()
    with db.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_otx_backfills_after_a_failed_sync(tmp_path, monkeypatch):
    """A previous 'error' row (no key yet) must not turn the first real sync into a near-empty delta."""
    import asyncio
    from datetime import datetime, timezone

    from mcp_threatintel import db as dbmod, poller

    conn = dbmod.init_db(str(tmp_path / "t.db"))
    dbmod.update_feed_sync(conn, "otx", 0, status="error", error="OTX_API_KEY not set")
    asked = {}

    class FakeOtx:
        def __init__(self, key):
            pass

        async def get_subscribed_pulses(self, modified_since=""):
            asked["since"] = modified_since
            return [{"id": "p1", "name": "pulse", "indicators": [{"indicator": "6.6.6.6", "type": "IPv4"}]}]

        shape_pulse = poller.OtxClient.shape_pulse
        shape_indicators = poller.OtxClient.shape_indicators

        async def close(self):
            pass

    monkeypatch.setenv("OTX_API_KEY", "k")
    monkeypatch.setattr(poller, "OtxClient", FakeOtx)
    asyncio.run(poller.poll_otx(conn))
    age = datetime.now(timezone.utc) - datetime.fromisoformat(asked["since"])
    assert age.days >= 29  # backfill window, not "since the failed attempt"
    row = conn.execute("SELECT status, records_total FROM feed_sync WHERE source='otx'").fetchone()
    assert row["status"] == "ok" and row["records_total"] == 1
