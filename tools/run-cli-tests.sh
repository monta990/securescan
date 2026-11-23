#!/usr/bin/env bash
set -euo pipefail
EXPECTED_MINOR="${1:-}"
if [[ ! "$EXPECTED_MINOR" =~ ^8\.(2|3|4|5|6)$ ]]; then
    echo "Usage: bash tools/run-cli-tests.sh <8.2|8.3|8.4|8.5|8.6>" >&2
    exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SECURESCAN_EXPECTED_PHP_MINOR="$EXPECTED_MINOR"
php tests/php/cli_runtime_test.php
while IFS= read -r -d '' file; do php -l "$file"; done < <(find setup.php hook.php src tests tools scripts -type f -name '*.php' -print0 | sort -z)
php tests/check-psr4.php src 'GlpiPlugin\Securescan'
php tests/validate-release.php
python3 tools/validate-plugin-xml.py
python3 tools/compile_locales.py --check
shopt -s nullglob
php_tests=(tests/*Test.php)
if (("${#php_tests[@]}" == 0)); then
    echo "No standalone PHP regression suites were found in tests/*Test.php." >&2
    exit 1
fi
for test_file in "${php_tests[@]}"; do
    printf "\n=== %s ===\n" "$(basename "$test_file")"
    php "$test_file"
done
printf '\nSecureScan %s CLI syntax, release validation and regression suites: OK\n' "$EXPECTED_MINOR"
