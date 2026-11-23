#!/usr/bin/env python3
"""Validate SecureScan plugin.xml against the GLPI plugin catalog structure."""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "plugin.xml"
EXPECTED_VERSION = "2.0.0"
EXPECTED_COMPATIBILITY = ["~11.0.7", "~12.0.0"]
EXPECTED_ROOT_CHILDREN = [
    "name",
    "key",
    "state",
    "logo",
    "description",
    "homepage",
    "download",
    "issues",
    "readme",
    "authors",
    "versions",
    "langs",
    "license",
    "tags",
    "screenshots",
]


def is_https_url(value: str | None) -> bool:
    if not value:
        return False
    parsed = urlparse(value.strip())
    return parsed.scheme == "https" and bool(parsed.netloc)


def has_text(element: ET.Element | None) -> bool:
    return element is not None and bool("".join(element.itertext()).strip())


def main() -> int:
    try:
        root = ET.parse(MANIFEST).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"FAIL: plugin.xml is missing or invalid XML: {exc}", file=sys.stderr)
        return 1

    checks: dict[str, bool] = {
        "root element": root.tag == "root",
        "catalog element order": [child.tag for child in root] == EXPECTED_ROOT_CHILDREN,
        "plugin display name": has_text(root.find("name")),
        "plugin key matches directory": root.findtext("key") == "securescan",
        "stable release state": root.findtext("state") == "stable",
        "logo HTTPS URL": is_https_url(root.findtext("logo")),
        "homepage HTTPS URL": is_https_url(root.findtext("homepage")),
        "download page HTTPS URL": is_https_url(root.findtext("download")),
        "issues HTTPS URL": is_https_url(root.findtext("issues")),
        "README HTTPS URL": is_https_url(root.findtext("readme")),
        "license declaration": root.findtext("license") == "GPLv3+",
    }

    description = root.find("description")
    short = description.find("short") if description is not None else None
    long = description.find("long") if description is not None else None
    for section_name, section in (("short", short), ("long", long)):
        for language in ("en", "es"):
            checks[f"{section_name} {language} description"] = has_text(
                section.find(language) if section is not None else None
            )

    authors = root.findall("./authors/author")
    checks["at least one author"] = bool(authors) and all(has_text(author) for author in authors)

    versions = root.findall("./versions/version")
    release = next(
        (
            item
            for item in versions
            if (item.findtext("num") or "").strip() == EXPECTED_VERSION
        ),
        None,
    )
    checks["single release entry"] = len(versions) == 1
    checks["release version"] = release is not None
    compatibility = (
        sorted((item.text or "").strip() for item in release.findall("compatibility"))
        if release is not None
        else []
    )
    checks["GLPI compatibility constraints"] = compatibility == EXPECTED_COMPATIBILITY
    download_url = release.findtext("download_url") if release is not None else None
    checks["versioned release download URL"] = (
        is_https_url(download_url)
        and download_url.rstrip("/").endswith(
            f"/releases/download/{EXPECTED_VERSION}/securescan-{EXPECTED_VERSION}.zip"
        )
    )

    declared_languages = {
        (item.text or "").strip() for item in root.findall("./langs/lang")
    }
    checks["declared UI languages"] = declared_languages == {"en_GB", "es_MX"}

    tags = root.find("tags")
    for language in ("en", "es"):
        language_tags = tags.findall(f"./{language}/tag") if tags is not None else []
        checks[f"{language} tags"] = bool(language_tags) and all(
            (tag.text or "").strip() for tag in language_tags
        )

    screenshots = root.findall("./screenshots/screenshot")
    checks["at least one screenshot URL"] = bool(screenshots) and all(
        is_https_url((screenshot.text or "").strip()) for screenshot in screenshots
    )

    failed = False
    for label, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'}: plugin.xml {label}")
        failed = failed or not passed

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
