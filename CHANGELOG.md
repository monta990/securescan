## 0.1.27 - 2026-08-27

### Added

- Added a GitHub stable-release version checker to the SecureScan configuration page.
- The checker compares the installed version with the latest published, non-draft, non-prerelease SecureScan release.
- Added six-hour caching with stale-cache fallback so temporary GitHub or network failures do not affect SecureScan operation.
- Added HTTPS certificate verification, disabled redirects, short connection/total timeouts, bounded response size, strict release-tag validation, and safe release URL validation.
- Added localized version-status messages and direct access to the SecureScan GitHub Releases page.

---

## 0.1.26 - 2026-08-27

### Changed

- Updated the plugin version to 0.1.26.
- Promoted the current package metadata to release version 0.1.26 for GLPI 11 and GLPI 12.
- Preserved the multilingual configuration interface and SecureScan audit/history functionality.

## 0.1.25 - 2026-08-27

### Changed

- Refined the SecureScan configuration interface.
- Use the `shield-check` icon in the configuration entry.
- Keep the enable-scanning label on one line when sufficient space is available.
- Added a direct link to the GLPI logs page from the SecureScan configuration.
- Standardized icon-to-text spacing in configuration buttons.

## 0.1.24 - 2026-08-27

### Added

- Added French (France) (`fr_FR`) translation.
- Added Brazilian Portuguese (`pt_BR`) translation.
- Updated plugin metadata to stable release status.

---

## 0.1.23

- Added a native GLPI history entry to each successfully stored clean document after SecureScan completes its pre-storage antivirus scan.
- The history entry includes the scan result and SHA-256 fingerprint; the detailed JSON audit remains in `files/_log/securescan.log`.
- History logging is best-effort and cannot invalidate a document that has already been stored successfully.

## 0.1.22

- Added a post-add/post-update audit entry after a clean document scan is successfully persisted by GLPI.
- The new `document_stored` audit record contains the definitive Document ID, allowing the antivirus scan to be correlated with the actual GLPI document without moving the security scan out of `pre_item_add` / `pre_item_update`.
- Kept the pre-add/pre-update blocking flow intact: infected files and scan errors are rejected before GLPI stores the document.
- Corrected the documented GLPI hook rejection pattern to clear `$item->input` with an empty array.
- Kept the native GLPI configuration tab, Symfony plugin controllers, route compatibility workaround, and `glpi_configs` storage unchanged.

## 0.1.21 - 2026-08-27

### Security and scanning

- Corrected document rejection in `PRE_ITEM_ADD` and `PRE_ITEM_UPDATE` to use the current GLPI hook contract (`input = false`).
- Added verifiable SecureScan audit records for document scans and antivirus tests using GLPI's native `Toolbox::logInFile()` facility.
- Audit records include timestamp, scan type, status, exit code, file size, SHA-256 fingerprint, temporary filename, item type/id, and user id; file contents and antivirus output are never logged.
- Added explicit scan-result evidence to the SecureScan configuration page.

### Preserved

- Native GLPI configuration tab and plugin configuration gear.
- Native `glpi_configs` storage; no plugin configuration table.
- Symfony controllers for configuration actions.
- Default command `clamdscan --no-summary {file}`.
- Antivirus disabled by default and successful command validation required before enabling.
- English source language with `es_MX` translation.
- GPLv3+ license and root-level `logo.png`.
- GLPI cache reset on install/update.

## 0.1.20 - 2026-08-27

- Fixed configuration persistence after successful antivirus tests.
- Fixed the invalid assumption that `Config::setConfigurationValues()` returns a boolean.
- Improved antivirus executable discovery for PHP-FPM/Apache processes with a restricted `PATH`.
- Reused the centralized configuration save method from the antivirus test controller.

# Changelog

## 0.1.19 - 2026-08-27

### Fixed

- Fixed configuration save falsely reporting failure because GLPI `Config::setConfigurationValues()` returns `void` rather than a boolean.
- Fixed successful antivirus tests being reported as unsaved for the same `void` return-value issue.
- Configuration save and antivirus test now verify the persisted values by reading them back from GLPI after writing.
- Replaced the invalid `Toolbox::logError()` call with the supported GLPI logging API.
- Fixed the installation/update configuration initialization so it does not treat the native `Config::setConfigurationValues()` `void` return value as failure.

### Preserved

- Modern Symfony Controllers for configuration actions.
- Native GLPI configuration gear and configuration tab.
- Default command `clamdscan --no-summary {file}`.
- Antivirus disabled by default.
- Successful test required before enabling scanning.

---

## 0.1.18

### Fixed

- Restored the working SecureScan configuration gear using GLPI's native configuration tab pattern (`front/config.form.php?forcetab=...`), without a plugin-side legacy configuration page.
- Removed the plugin `front/` configuration bridge that attempted to load `inc/includes.php` from the plugin directory and could fail when the plugin is installed under `marketplace/`.
- Restored the documented `Config` itemtype integration by extending GLPI's native `\\Config` class without overriding `getTable()`. This keeps configuration in `glpi_configs` and avoids `glpi_plugin_securescan_configs` lookups.
- Kept configuration actions on Symfony plugin Controllers under `src/Controller/`, with route attributes and route-name URL generation.
- Kept the GLPI 11.0.0–11.0.6 GET+POST route compatibility workaround and explicit POST validation.
- A successful antivirus test now stores the tested command and its SHA-256 fingerprint, so an administrator can test a new command and then immediately enable scanning without the validation being discarded.
- Replaced the pre-hook rejection value with an empty input array, following GLPI's documented hook pattern for stopping an add/update operation.

### Security

- Configuration save and antivirus test actions use GLPI's native `Config::checkGlobal(UPDATE)` protection, which also enforces GLPI 12 re-authentication for the sensitive configuration action.
- No plugin-specific configuration table is created.

### Preserved

- Default command: `clamdscan --no-summary {file}`.
- Scanning disabled after installation.
- Successful antivirus validation required before scanning can be enabled.
- English source language with `es_MX` translation.
- GPLv3+ license and developer Edwin Elias Alvarez.
- Root-level `logo.png`.
- GLPI cache reset on installation/update using the native cache manager with shutdown deferral.

---

## 0.1.16

- Removed the custom Symfony configuration-save and antivirus-test routes that were not being registered correctly in the installed GLPI environment.
- Restored the standard GLPI plugin configuration page entry point.
- Restored configuration saving and antivirus testing through the authenticated plugin configuration flow, with explicit success/error feedback.
- Removed the incorrect plugin-specific table lookup from SecureScan configuration.
- Kept configuration storage in GLPI's native `glpi_configs` table under the `plugin:securescan` context.
- Kept scanning disabled by default and preserved the mandatory successful-command validation before enabling scanning.
- Kept the default command `clamdscan --no-summary {file}`.

---

## 0.1.15

- Fixed Symfony route URL generation in the configuration form by using route names with `path()`.
- Fixed saving a newly tested command so a successful test is retained when the administrator saves and enables that same command.
- Invalidated the stored test hash whenever the saved command differs from the validated command.
- Replaced silent configuration-save/test exceptions with GLPI error logging.

---

## 0.1.14

- Removed the incompatible `Config::getTable()` override.
- Corrected configuration action URL handling for GLPI 11/12.

---

## 0.1.13

- Restored GLPI plugin-relative controller routes for configuration actions.
- Corrected the configuration-tab itemtype integration.
- Kept the native GLPI configuration gear and CSRF compliance.

---

## 0.1.12

- Removed the custom legacy configuration page.
- Used GLPI's native configuration form and `forcetab` integration.
- Removed the invalid plugin-side `inc/includes.php` dependency from the configuration flow.

---

## 0.1.11

- Enforced a successful antivirus test before scanning can be enabled.
- Stores a SHA-256 fingerprint of the successfully tested command.
- Invalidates the test automatically when the command changes.

---

## 0.1.10

- Corrected uploaded-file path resolution using GLPI temporary and upload directories.
- Added antivirus scanning for new documents and document replacements.
- Rejects and removes uploaded files when scanning fails or detects a threat.
- Added GLPI 12 re-authentication checks to configuration actions.
- Removed open-redirect behavior after antivirus tests.
- Added PHP 8.2 requirement metadata.
- Corrected GPLv3+ licensing metadata and source headers.
- Corrected plugin catalog logo dimensions to 40x40.

---

## 0.1.9

- Fixed SecureScan controller routes used by configuration actions.
- Fixed configuration URL handling.

---

## 0.1.8

- Fixed plugin configuration URLs to avoid the removed `Plugin::getWebDir()` method.
- Added Symfony route-name based URLs for controller actions.
- Fixed direct access to the SecureScan configuration.
- Fixed the antivirus test to use the command currently entered in the form.

---

## 0.1.7

- Added dedicated controllers for saving configuration and testing the antivirus.
- Added explicit success and error feedback.

---

## 0.1.6

- Added the standard plugin configuration gear and native SecureScan configuration tab.
- Added the compiled Spanish (Mexico) translation catalog.
- Added the English source catalog.

---

## 0.1.5

- Fixed plugin installation/update hanging caused by clearing GLPI's cache during the active request.
- Deferred the native GLPI cache reset until request shutdown.
- Preserved existing SecureScan configuration during updates.

---

## 0.1.4

- Changed license to GPLv3+.
- Set developer to Edwin Elias Alvarez.

---

## 0.1.3

- English is now the plugin source language.
- Spanish (Mexico) translations are provided through `locales/es_MX.po`.
- Changelog entries are maintained from newest to oldest.

---

## 0.1.2

- Clears GLPI caches using the native `Glpi\\Cache\\CacheManager`.
- Existing configuration is preserved during updates.

---

## 0.1.1

- Default command changed to `clamdscan --no-summary {file}`.
- Scanning remains disabled after plugin installation.
- The administrator must validate the command before enabling scanning.
- Logo changed to root-level `logo.png`.

---

## 0.1.0

- Initial SecureScan development version.
- GLPI 11/12 compatibility target.
- Antivirus command configuration using `{file}`.
- Antivirus test action.
- Document pre-add/update interception before GLPI stores the uploaded file.
- Uses GLPI's native `glpi_configs` configuration storage.
- Namespaced PHP classes and Twig configuration UI.
