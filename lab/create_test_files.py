"""Create the harmless lab files used by the test scenarios.

    python lab/create_test_files.py [target_dir]

Default target: ~/threatintel-lab (put the same folder in SCAN_PATHS).
The content is fixed: its SHA-256 is listed in lab/local_iocs.csv.
EICAR is deliberately not used: Windows Defender would delete it first.
"""

import hashlib
import sys
from pathlib import Path

CONTENT = b"MCP-THREATINTEL-LAB-TEST-FILE: harmless marker for scenario B (quarantine).\n"
EXPECTED = "f8994855ae7bd42bf3490f416413850bc6d385a6af8f50e2685d2514b2e46f48"


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "threatintel-lab"
    target.mkdir(parents=True, exist_ok=True)
    evil = target / "invoice_2026.pdf.exe.txt"
    evil.write_bytes(CONTENT)
    (target / "notes.txt").write_text("A normal, clean file.\n", encoding="utf-8")
    digest = hashlib.sha256(evil.read_bytes()).hexdigest()
    assert digest == EXPECTED, digest
    print(f"created {evil} (sha256 {digest})")
    print(f"created {target / 'notes.txt'} (clean)")
    print(f"SCAN_PATHS should contain: {target}")


if __name__ == "__main__":
    main()
