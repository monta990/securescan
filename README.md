# SecureScan

SecureScan analyzes uploaded GLPI documents with the antivirus available on the same server before the file is published.

## Scope

- Enable or disable antivirus scanning.
- Configure the antivirus command.
- Use `{file}` as the temporary file placeholder.
- Test the antivirus from the native SecureScan configuration tab.
- Reject infected files.
- Reject files when the antivirus cannot complete the scan.
- Scan both new documents and document replacements before GLPI stores the uploaded file.
- Do not modify the GLPI core.

Default command:

```text
clamdscan --no-summary {file}
```

Scanning is **disabled by default** after installation. The administrator must open the SecureScan configuration, validate the command using **Test antivirus**, and explicitly enable scanning. SecureScan blocks enabling until the current command has passed a successful test.

## Configuration

SecureScan uses GLPI's native configuration system:

- The plugin registers a native `Config` tab.
- Values are stored in GLPI's `glpi_configs` table using the `plugin:securescan` context.
- No plugin-specific configuration table is created.
- The plugin list gear opens GLPI's native `front/config.form.php` with the SecureScan tab selected.

## Architecture

- `setup.php`: plugin metadata, registration and runtime hooks.
- `hook.php`: installation/uninstallation and native GLPI cache reset.
- `src/Config.php`: native GLPI `Config` tab and configuration service.
- `src/Antivirus.php`: antivirus scanning and command validation service.
- `src/Controller/`: Symfony controllers for configuration save and antivirus test.
- `src/VersionChecker.php`: GitHub stable-release checker with bounded HTTPS requests and cached results.
- `templates/config.html.twig`: configuration interface.
- `locales/`: gettext catalogs, with English as the source language and `es_MX`, `fr_FR`, and `pt_BR` translations.
- `logo.png`: plugin logo in the plugin root.

## GLPI 11/12 architecture

SecureScan follows the current GLPI plugin controller model for new web actions. Plugin controllers are placed under `src/Controller/`, use route attributes, and generate their URLs by route name. GLPI's documentation states that new features added to GLPI 11+ should use Controllers.

For the plugin configuration page itself, SecureScan uses the native GLPI configuration-tab mechanism documented for plugins. This preserves the standard plugin configuration gear without introducing a legacy plugin configuration page.

The POST controller routes accept `GET` + `POST` and reject non-POST requests internally. This is intentional for compatibility with the GLPI 11.0.0–11.0.6 routing limitation documented by GLPI; GLPI 11.0.7+ and GLPI 12 can use the intended method restriction normally.

## GitHub version checker

SecureScan can check the GitHub Releases API for a newer published stable version of the plugin. The check:

- ignores draft and prerelease releases;
- accepts only strict semantic versions in the release tag (`vX.Y.Z` or `X.Y.Z`);
- validates the release URL before presenting it to the administrator;
- uses HTTPS with certificate and host verification;
- does not follow redirects;
- uses short connection and total timeouts;
- limits the response body size;
- caches the last known result for six hours; and
- falls back to the last known good result when GitHub is temporarily unavailable.

The checker runs from the SecureScan configuration page and does not participate in the antivirus decision for uploaded files. A GitHub or network failure therefore does not disable SecureScan or allow an uploaded file to bypass antivirus scanning.

The configuration page shows the installed version, the latest stable version when available, and a direct link to the corresponding GitHub release.

## Security

- Configuration actions require the GLPI configuration update right.
- GLPI 12 native re-authentication is enforced through `Config::checkGlobal(UPDATE)`.
- CSRF compliance is enabled for the plugin.
- The configured command must contain exactly one `{file}` placeholder.
- Shell separators, redirects, substitutions, comments and shell operators are rejected.
- The uploaded file path is resolved only from GLPI's temporary/upload directories and must be a readable regular file.
- Antivirus exit code `0` means clean, `1` means infected, and any other code is treated as a scan error.
- Any scan error or detected threat rejects the upload.

## Installation

1. Extract the ZIP so the plugin directory is named exactly `securescan`.
2. Place it in GLPI's `plugins/` directory, or install it through the GLPI Marketplace.
3. Install and activate SecureScan.
4. Open the SecureScan configuration using the plugin gear.
5. Verify the antivirus command.
6. Click **Test antivirus**.
7. Enable scanning only after the test succeeds.

## Compatibility

- GLPI 11.x
- GLPI 12.x
- PHP 8.2+
- PHP cURL and JSON extensions are used by the GitHub version checker; if GitHub cannot be checked, SecureScan continues to operate and provides the Releases link.

## License

GPLv3+

Copyright (C) 2026 Edwin Elias Alvarez

## Scan audit

SecureScan records a compact audit line for each antivirus test and document scan in GLPI's native file log:

`files/_log/securescan.log`

The audit record contains the timestamp, scan type, status, exit code, file size, SHA-256 fingerprint, temporary filename, item type/id and GLPI user ID. File contents and antivirus command output are not written to the audit log.

A document scan is performed from the `pre_item_add` and `pre_item_update` hooks. A non-clean result stops the operation and removes the temporary upload. When a clean scan is subsequently persisted by GLPI, an additional `document_stored` audit entry records the definitive Document ID. The same successful result is also written to the document's native GLPI **Histórico** tab using GLPI's native history API, including the result and SHA-256 fingerprint. The security decision is still made before storage. A failure to write the history entry never invalidates a document that has already been stored successfully; the detailed SecureScan log remains the audit fallback.
