# SecureScan 2.0.0 — Development handoff

## Release identity
- Plugin: securescan
- Final version: 2.0.0
- GLPI: 11.0.7+ / 12.x
- PHP: 8.2+
- License: GPLv3+
- Release target: main
- Development branch: release/2.0.0-cli-ci

## Release summary
SecureScan 2.0.0 consolidates the 2.0 development iterations into one public release. The plugin supports exactly one active engine: ClamAV, VirusTotal, or Disabled. Simultaneous engine activation is treated as a configuration conflict and uploads are rejected.

VirusTotal support uses API v3. The browser starts preflight using GLPI's staged upload, and then polls a dedicated status route. Each request performs one API check and returns; PHP does not sleep between polls. The session lock is released before external API work so users can continue using other GLPI tabs.

Pending analyses are represented by a random 48-hex user-bound token. The source file is copied into GLPI_PLUGIN_DOC_DIR/securescan/virustotal-jobs, stored with restrictive permissions, and re-hashed before polling. After a clean result, the original staged basename is restored atomically and checked against the expected SHA-256 before the browser replays the form. Jobs and private copies expire after 24 hours and are opportunistically cleaned.

VirusTotal request limiting is shared across endpoints. Quota-exempt operations still reserve per-minute slots but do not increase daily quota usage. Retry-After can defer subsequent requests. The pre-storage hook reads a short-lived approval cache and does not perform a synchronous outbound request.

## Important files
- setup.php: plugin version, GLPI/PHP compatibility and hooks.
- hook.php: install defaults and removal of private VirusTotal artifacts.
- src/EngineSelector.php: mutually exclusive engine resolution.
- src/Antivirus.php: pre-storage ClamAV scan and cache-only VirusTotal approval.
- src/VirusTotal.php: VirusTotal API v3, normalization, caches and request coordination.
- src/VirusTotalRequestLimiter.php: shared per-minute and daily quota state.
- src/Controller/VirusTotalScanController.php: asynchronous preflight, jobs, quarantine, restoration and cleanup.
- src/Audit.php: sanitized audit and native GLPI document history.
- public/js/securescan-wait.js: upload interception, polling and safe form replay.
- templates/config.html.twig: engine selection and configuration.
- tests/*Test.php: deterministic CLI regression suites.

## CLI and CI validation
Run locally with an installed PHP version from the supported matrix:

    bash tools/run-cli-tests.sh 8.4
    node --check public/js/securescan-wait.js

GitHub Actions is configured for PHP 8.2, 8.3, 8.4, 8.5 and 8.6. Each matrix leg runs PHP syntax checks, runtime checks, PSR-4 validation, release metadata validation, plugin XML checks, PO/MO synchronization and all standalone regression suites. The packaging job creates the installable securescan-2.0.0.zip only after the test matrix succeeds.

The local PHP 8.4.24 run executed 103 regression assertions across eight suites with zero failures. PHP syntax, JavaScript syntax, PSR-4, XML structure, gettext catalogs and ZIP integrity were also checked locally. CI matrix results are authoritative for PHP versions not installed in the local environment.

## Deployment notes
1. Back up the GLPI plugin directory and GLPI_PLUGIN_DOC_DIR/securescan.
2. Replace the installed plugin files with the contents of the installation ZIP; do not uninstall the plugin during an upgrade.
3. Confirm the PHP worker can write to GLPI_PLUGIN_DOC_DIR/securescan.
4. Confirm the plugin document directory is not web-accessible.
5. Run the selected engine test from SecureScan configuration.
6. Upload a non-sensitive test document and confirm the audit entry in GLPI history.

For VirusTotal automatic submission, confirm that the API agreement and data-sharing policy are appropriate for the organization's use. Do not submit confidential content with a Public/Community API key.

## Validation limits
- No live VirusTotal API transaction was performed in the local environment; cURL and a configured API key were not available.
- No live GLPI 11/12 instance was available for end-to-end UI, route and storage verification.
- Local regression suites are deterministic CLI tests with GLPI stand-ins. CI runs the supported PHP matrix but does not replace deployment verification on the target GLPI installation.
- Confirm private directory permissions and web-server denial explicitly in production.

## Next recommended steps
- Merge the PR after all required GitHub Actions jobs pass.
- Create the GitHub 2.0.0 release and attach the CI-generated installable ZIP and checksum.
- Perform deployment smoke tests on a GLPI 11.0.7+ and a GLPI 12.x instance.
