#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT/dist}"
VERSION="$(sed -n "s/.*PLUGIN_SECURESCAN_VERSION', *'\\([^']*\\)'.*/\\1/p" "$ROOT/setup.php" | head -n 1)"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "Invalid release version: $VERSION" >&2; exit 1; fi
mkdir -p "$OUTPUT_DIR"; OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT; mkdir -p "$STAGE/securescan"
for item in setup.php hook.php plugin.xml LICENSE README.md CHANGELOG.md logo.png config.png src templates locales public; do
  test -e "$ROOT/$item" || { echo "Missing required release item: $item" >&2; exit 1; }; cp -a "$ROOT/$item" "$STAGE/securescan/"
done
for required in securescan/setup.php securescan/hook.php securescan/plugin.xml securescan/LICENSE securescan/src/Antivirus.php securescan/src/VirusTotal.php securescan/src/Controller/VirusTotalScanController.php securescan/templates/config.html.twig securescan/public/js/securescan-wait.js securescan/public/css/securescan-wait.css securescan/locales/en_GB.mo securescan/locales/es_MX.mo; do
  test -f "$STAGE/$required" || { echo "Required runtime file missing: $required" >&2; exit 1; }
done
ARCHIVE="$OUTPUT_DIR/securescan-$VERSION.zip"; rm -f "$ARCHIVE" "$ARCHIVE.sha256"; (cd "$STAGE" && zip -qr "$ARCHIVE" securescan); unzip -t "$ARCHIVE" >/dev/null
if unzip -Z1 "$ARCHIVE" | grep -Eq '^securescan/(tests|tools|scripts|.github)(/|$)|^securescan/HANDOFF[.]md$'; then echo "Development-only files leaked into the installer." >&2; exit 1; fi
(cd "$OUTPUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
echo "Created and validated $ARCHIVE"
