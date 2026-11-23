#!/usr/bin/env python3
"""Compile and verify SecureScan gettext PO/MO catalogs with Babel."""
from __future__ import annotations
import argparse
import io
import sys
from pathlib import Path
try:
    from babel.messages.mofile import write_mo
    from babel.messages.pofile import read_po
except ImportError as exc:
    print("Babel is required: python -m pip install Babel", file=sys.stderr)
    raise SystemExit(2) from exc
ROOT = Path(__file__).resolve().parents[1]
LOCALES = ROOT / "locales"
def compiled_bytes(po_path: Path) -> bytes:
    with po_path.open("rb") as source: catalog = read_po(source, abort_invalid=True)
    output = io.BytesIO(); write_mo(output, catalog, use_fuzzy=False); return output.getvalue()
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if MO files are missing or stale")
    args = parser.parse_args()
    po_files = sorted(LOCALES.glob("*.po"))
    if not po_files: print("No PO catalogs found.", file=sys.stderr); return 1
    failures = 0
    for po_path in po_files:
        mo_path = po_path.with_suffix(".mo")
        try: expected = compiled_bytes(po_path)
        except Exception as exc:
            print(f"FAIL: {po_path.name}: {exc}", file=sys.stderr); failures += 1; continue
        if args.check:
            try: actual = mo_path.read_bytes()
            except OSError: actual = b""
            if actual != expected: print(f"FAIL: {mo_path.name} is missing or stale.", file=sys.stderr); failures += 1
            else: print(f"PASS: {po_path.name} ↔ {mo_path.name}")
        else:
            mo_path.write_bytes(expected); print(f"OK: compiled {po_path.name} → {mo_path.name}")
    if failures: print(f"{failures} translation catalog validation failure(s).", file=sys.stderr); return 1
    return 0
if __name__ == "__main__": raise SystemExit(main())
