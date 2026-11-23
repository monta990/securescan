#!/usr/bin/env python3
"""Validate SecureScan plugin.xml using Python's standard XML parser."""
from __future__ import annotations
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "plugin.xml"
EXPECTED_VERSION = "2.0.0"
def main() -> int:
    try: root = ET.parse(MANIFEST).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"FAIL: plugin.xml is missing or invalid XML: {exc}", file=sys.stderr); return 1
    checks = {
        "plugin key": root.findtext("key") == "securescan",
        "stable release state": root.findtext("state") == "stable",
        "release version": any((item.findtext("num") or "").strip() == EXPECTED_VERSION for item in root.findall("./versions/version")),
    }
    release = next((item for item in root.findall("./versions/version") if (item.findtext("num") or "").strip() == EXPECTED_VERSION), None)
    compatibility = sorted((item.text or "").strip() for item in release.findall("compatibility")) if release is not None else []
    checks["GLPI compatibility"] = compatibility == ["~11.0.7", "~12.0"]
    checks["release download URL"] = release is not None and (release.findtext("download_url") or "").strip().endswith(f"/releases/download/{EXPECTED_VERSION}/securescan-{EXPECTED_VERSION}.zip")
    failed = False
    for label, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'}: plugin.xml {label}"); failed = failed or not passed
    return 1 if failed else 0
if __name__ == "__main__": raise SystemExit(main())
