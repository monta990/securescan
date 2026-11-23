# Changelog — SecureScan

All notable changes are documented here.

## 2.0.0 — Final release

### Added
- VirusTotal API v3 as an alternative engine to ClamAV, with a single-engine selector.
- Asynchronous browser preflight for VirusTotal analyses; no PHP worker sleeps between analysis requests.
- User-bound pending jobs with private quarantine copies, SHA-256 verification, staged-file restoration and 24-hour cleanup.
- VirusTotal request-rate coordination across endpoints, daily quota accounting, and Retry-After handling.
- Sanitized performance diagnostics for hashing, report lookup, upload, polling, quarantine and staged-file restoration.
- Native GLPI history entries with validated VirusTotal report links.
- Portable CLI regression suites, PHP compatibility matrix, PSR-4 validation, XML and translation checks, and repeatable installer ZIP generation.

### Security
- Only a completed clean VirusTotal result or an explicitly verified ClamAV clean verdict allows the upload.
- Malicious, suspicious, pending, inconclusive, malformed, skipped, timed-out and unavailable results fail closed.
- The VirusTotal API key remains in GLPI secured configuration and is never exposed to the browser.
- Private job tokens are bound to the GLPI user; quarantine and restored file copies are checked against the expected SHA-256.
- ClamAV commands are executed without a shell and limited to supported executables.

### Compatibility
- GLPI 11.0.7+ / 12.x.
- PHP 8.2+.

## 1.0.3 — Previous stable release
- ClamAV-only scanning with strict scan-verdict validation.
- Native GLPI document upload hooks and scan audit logging.
