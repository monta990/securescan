# Changelog — SecureScan

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

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

