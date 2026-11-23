<p align="center"><img src="logo.png" alt="SecureScan" width="128" height="128"></p>
<h1 align="center">SecureScan 2.0.0</h1>
<p align="center"><strong>GLPI document upload protection with one selected antivirus engine: ClamAV or VirusTotal.</strong></p>

SecureScan checks uploaded GLPI documents before GLPI stores them. Exactly one scanning mode can be active at a time: local ClamAV or cloud-based VirusTotal API v3. Selecting neither leaves scanning disabled. Enabling both is treated as a configuration conflict and uploads fail closed.

## Compatibility
- GLPI 11.0.7 and later 11.x; GLPI 12.x.
- PHP 8.2 or newer.
- GPLv3+.

## Engines

### ClamAV
ClamAV runs on the GLPI server using clamdscan or clamscan. The command is launched directly without a shell. SecureScan requires a positive result for the exact staged file; infected, skipped, timed out, ambiguous and failed scans are rejected. For clamdscan, configure AlertExceedsMax yes in clamd.conf and restart the daemon. SecureScan adds --alert-exceeds-max=yes automatically when using clamscan.

### VirusTotal
VirusTotal API v3 is an alternative to ClamAV. The API key is stored through GLPI's secured configuration. Network preflight is asynchronous: each status request performs one remote analysis check, releases the PHP session lock, and returns without sleeping in a PHP worker.

When VirusTotal reports a pending analysis, SecureScan copies the upload into private plugin document storage, validates the SHA-256, and binds a random job token to the logged-in GLPI user. Only a completed clean result is approved. The original GLPI staged filename is restored from the private copy, with SHA-256 verification, before the upload form is resumed. Malicious, suspicious, pending, failed, invalid or unavailable results fail closed.

Automatic submission of unknown files is optional and disabled by default. Submissions are limited to 32 MB. SecureScan maintains a shared four-requests-per-minute limiter, separates quota-exempt endpoint calls from daily quota accounting, and honors VirusTotal Retry-After responses.

**Privacy notice:** VirusTotal Public/Community API submissions are shared with VirusTotal's security community and have restrictions on commercial use. Do not submit confidential, personal or business-sensitive files using a Public/Community key. Use a suitable Premium agreement for corporate production.

## Installation and configuration
1. Place the securescan directory in GLPI's plugins directory.
2. In GLPI, install and enable SecureScan from Setup → Plugins.
3. Open Setup → General → Configuration → SecureScan.
4. Choose Disabled, ClamAV or VirusTotal. Only one engine can be active.
5. For ClamAV, configure the server command and run Test selected engine.
6. For VirusTotal, enter the API key and run Test selected engine. The key is stored securely by GLPI.
7. Save the configuration. Scanning remains disabled until a valid engine configuration is selected and tested.

## Audit and privacy
Scan evidence is recorded in GLPI's native document history and files/_log/securescan.log. Diagnostic events contain hashes, normalized verdicts and bounded timing values; API keys, file contents and original filenames are not written to performance logs. VirusTotal report URLs are generated only from validated SHA-256 values.

Private asynchronous job files are stored under GLPI_PLUGIN_DOC_DIR/securescan/virustotal-jobs with restrictive permissions and are removed after completion or expiry. The web server must not expose the GLPI plugin document directory.

## Development and validation
Run the portable CLI suite with a PHP runtime matching the intended matrix entry:

    bash tools/run-cli-tests.sh 8.4

The CLI suite checks PHP syntax, runtime requirements, PSR-4 mappings, release metadata, XML structure, PO/MO synchronization and all standalone PHP regression suites. GitHub Actions runs PHP 8.2, 8.3, 8.4, 8.5 and 8.6, plus JavaScript syntax checks and installable ZIP packaging.

Build the GLPI installation archive:

    bash scripts/package.sh ./dist

The package script uses an explicit allowlist and excludes tests, CI workflows, development tools and this handoff document.

## Support
- Repository: https://github.com/monta990/securescan
- Issues: https://github.com/monta990/securescan/issues
- Releases: https://github.com/monta990/securescan/releases
