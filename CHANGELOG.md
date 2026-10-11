# Changelog — SecureScan

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 1.0.3 - 2026-10-11

### Security and scan-verdict correctness

- Parse each per-file result only after binding it to the exact temporary path; removed the uploader-controlled basename fallback.
- Evaluate skip/limit indicators against the scanner's result text rather than the complete line, preventing ordinary filenames such as `max file size policy.pdf` from being rejected falsely.
- Treat `Heuristics.Limits.Exceeded` as an unscanned/limited result and preserve malware detections as infected even if an unrelated warning also appears.
- Force `--alert-exceeds-max=yes` for `clamscan`; document the mandatory `AlertExceedsMax yes` daemon setting for `clamdscan`.
- Add guarded parser support for single-target `fd[n]: OK` / `stream: OK` output forms only when `clamdscan --fdpass` or `--stream` is explicitly selected; the administrator test must confirm the exact mode against the installed ClamAV before it is approved.
- Record timeout and output-cap evidence. Terminate the scanner when its captured output exceeds 64 KiB instead of allowing it to continue until timeout.
- Bind scan acceptance to a versioned test hash; active uploads fail closed with a clear message until the current command is retested after an upgrade.
- Extend the administrator test with a harmless 102-layer nested ZIP probe; the command is not approved unless ClamAV explicitly reports `Heuristics.Limits.Exceeded` for the probe. This verifies limit-alert behavior instead of relying only on documentation.
- Reject `--copy`, `--move`, and `--remove` ClamAV actions so rejected files cannot be copied/moved outside GLPI's temporary area by the configured scanner.
- Exclude `PHP_BINDIR` from executable trust directories and purge the obsolete `securescan_allowed_executables` setting during install/update.

### Version checker and audit

- Preserve the last known-good GitHub release version through transient failures using a bounded stale cache.
- Align audit record fields and correct the English history-tab docblock.

### Compatibility

- Retained the Document pre/post hooks, native GLPI configuration, controller authorization, POST/CSRF handling, audit format, and GLPI 11/12 compatibility declarations.

## 1.0.2 - 2026-09-04

### Security

- Hardened the scan verdict so an antivirus exit code of `0` is not treated as clean unless ClamAV provides positive evidence that the target file was scanned and reported `OK`.
- Added fail-closed handling for scan-limit, skipped, excluded, symbolic-link, access, and other ambiguous scanner responses.
- Infected results continue to reject uploads, with explicit normalized evidence recorded in the audit trail.

### Audit and logging

- Expanded `files/_log/securescan.log` records with `scan_verdict` and `scan_evidence` fields so administrators can distinguish a confirmed clean scan from an omitted or ambiguous scan.
- The `document_stored` audit event now preserves the original scan evidence and exit code instead of reconstructing a generic clean result.
- Raw ClamAV output is still bounded and is not persisted; the audit log records normalized evidence only.

### Documentation

- Documented the new positive-scan verification and audit fields in the README.

## 1.0.1 - 2026-09-03

### Security

- Closed the remaining security finding for absolute antivirus paths by resolving executable paths with `realpath()` and requiring the resolved executable to remain inside SecureScan's fixed system directories. Symlink escapes are rejected.
- Changed the remaining static security rejection message to GLPI's safe translation helper.

### Version checker

- Fixed GitHub release checks on PHP/libcurl builds where protocol-related cURL options are rejected even when the corresponding constants are exposed. The checker now uses only broadly supported cURL options, keeps redirects disabled, and verifies TLS without relying on protocol-option constants.
- Invalidated pre-1.0.1 version-check cache entries so a previous failed check cannot mask a working checker after upgrade.
- Failed GitHub release checks are no longer reported as SecureScan being up to date. A failed check is cached with no latest version and is displayed as unavailable.
- Release tags and release URLs are handled using the project's version format without a `v` prefix.

### Configuration

- Removed the obsolete `securescan_allowed_executables` setting and all internal plumbing for it. SecureScan remains explicitly restricted to the supported ClamAV scanners (`clamdscan` and `clamscan`).

## 1.0.0 - 2026-08-28

### Added

- First production release of SecureScan for GLPI 11.0.7+ and GLPI 12.x.
- Pre-storage ClamAV scanning for GLPI Documents on creation and replacement.
- Configurable ClamAV command with the `{file}` temporary-file placeholder; default: `clamdscan --no-summary {file}`.
- Mandatory successful antivirus command validation before scanning can be enabled.
- Fail-closed handling: infected files, scanner errors, unavailable scanners, and scan timeouts are rejected.
- Configurable antivirus scan timeout with a default of 30 seconds.
- Native GLPI document history and detailed `files/_log/securescan.log` audit records.
- GitHub stable-release update checker with caching, bounded responses, TLS verification, failure caching, and validated release URLs.
- English base language with Spanish (Mexico), French (France), and Brazilian Portuguese translations.

### Security and hardening

- Uses GLPI's modern Symfony Controller architecture for plugin web actions.
- Restricts configuration and antivirus-test actions to users with `config UPDATE` permission.
- Executes the configured ClamAV scanner without invoking a shell.
- Restricts the scanner executable to supported ClamAV tools and avoids inherited `PATH` resolution.
- Keeps antivirus decisions in the temporary upload phase so rejected files are not stored as GLPI Documents.
- Uses the documented GLPI hook contract to stop rejected Document add/update operations.
- Limits scanner output and enforces a configurable execution deadline.
- Uses GLPI's native configuration storage (`glpi_configs`) without a plugin-specific configuration table.
- Protects audit evidence from accidental loss when GLPI file logging is disabled.
