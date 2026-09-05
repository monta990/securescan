<p align="center">
  <p align="center"><img src="logo.png" alt="SecureScan" width="128" height="128"></p>
</p>
<h1 align="center">SecureScan</h1>
<p align="center">
  <strong>GLPI plugin — Antivirus scanning for uploaded files before they are stored</strong>
</p>
<p align="center">
  <a href="https://github.com/glpi-project/glpi" target="_blank"><img src="https://img.shields.io/badge/GLPI-11.0.7%2B-blue" alt="GLPI 11 compatibility"></a>
  <a href="https://github.com/glpi-project/glpi" target="_blank"><img src="https://img.shields.io/badge/GLPI-12.0%2B-blue" alt="GLPI 12 compatibility"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank"><img src="https://img.shields.io/badge/License-GPL%20v3%2B-green" alt="License"></a>
  <a href="https://php.net/" target="_blank"><img src="https://img.shields.io/badge/PHP-%3E%3D8.2-purple" alt="PHP"></a>
  <a href="https://github.com/monta990/securescan/releases" target="_blank"><img src="https://img.shields.io/github/downloads/monta990/securescan/total" alt="GitHub Downloads"></a>
</p>

---

## Overview

**SecureScan** integrates an ClamAV antivirus server engine into GLPI's document upload workflow. Files are scanned **before they are published/stored as GLPI documents**. Clean files continue through the normal GLPI workflow; infected or failed scans are rejected.

The plugin is designed to keep the antivirus operation isolated from GLPI's core code and to use GLPI's native configuration, authorization, routing, CSRF protection, translations, and history mechanisms wherever applicable.

SecureScan currently supports **ClamAV only**, using the `clamdscan` or `clamscan` command-line scanners. The analysis command remains configurable from the plugin configuration page.

---

## Security model

SecureScan follows a fail-closed approach for the protected upload path:

| Scan result | SecureScan action |
|---|---|
| **Clean** | File is allowed to continue and be stored normally. |
| **Infected** | File is rejected and is not stored as a GLPI document. |
| **Scan error / execution failure** | File is rejected. |
| **Antivirus unavailable** | File is rejected rather than bypassing the scan. |
| **Invalid command configuration** | Configuration cannot be used to bypass the protected scan path. |

A successful antivirus test is required before enabling the protection. This prevents an administrator from accidentally enabling a configuration that cannot execute the configured scanner.

> **Important:** SecureScan does not replace server hardening, operating-system permissions, GLPI security updates, malware protection, backups, or other security controls. It adds an antivirus inspection layer to GLPI file handling.

---

## Features

| Feature | Details |
|---|---|
| **Pre-storage scanning** | Uploaded files are inspected before they become stored GLPI documents. |
| **ClamAV integration** | Supports ClamAV scanners such as `clamdscan --no-summary {file}` and `clamscan --no-summary {file}`. |
| **Configurable scanner command** | The administrator can configure the antivirus command and use `{file}` as the temporary-file placeholder. |
| **Command hardening** | The configured command is parsed into a direct argument vector and executed without a shell. Shell separators, substitutions, redirections, and operators are not interpreted. |
| **Temporary-file isolation** | The uploaded file is kept in a temporary location while the antivirus result is obtained. |
| **Infected-file rejection** | A positive antivirus result prevents the file from being stored. |
| **Fail-closed behavior** | Scanner execution failures do not silently allow the file through. |
| **Configuration test** | Administrators can test the current antivirus command before enabling scanning. |
| **Enable protection guard** | SecureScan requires a successful antivirus test for the current command before the protection can be enabled. |
| **Result logging** | Scan results include status, exit code, file size, SHA-256, temporary-file information, user, item type, and item ID where applicable. |
| **Document lifecycle logging** | Clean document uploads can be recorded as both scan and storage events, providing an audit trail. |
| **EICAR verification** | The standard EICAR test file can be used to verify that infected uploads are rejected without using real malware. |
| **GLPI history compatibility** | Security-related document activity can be correlated with the normal GLPI history of the affected object. |
| **Multilanguage UI** | User-facing messages are translation-ready and follow the current GLPI language. |
| **Native GLPI integration** | Configuration and controllers use GLPI's current plugin architecture instead of modifying GLPI core files. |
| **GLPI 11 / 12 targeting** | The current package metadata declares compatibility with GLPI 11.x (11.0.7+) and 12.x. |

---

## Scan lifecycle

For a protected document upload, the intended lifecycle is:

```text
User selects file
       │
       ▼
GLPI upload request
       │
       ▼
SecureScan receives the temporary file
       │
       ▼
Validate scanner configuration
       │
       ▼
Execute antivirus scan
       │
       ├───────────────┐
       │               │
       ▼               ▼
    CLEAN          INFECTED / ERROR
       │               │
       ▼               ▼
Continue GLPI      Reject upload
document flow      and remove temporary file
       │
       ▼
Document stored
       │
       ▼
Audit/log entry
```

The important security boundary is that **the antivirus decision is made while the uploaded file is still temporary**. An infected file therefore does not become an ordinary stored GLPI document.

---

## Antivirus command

The configuration page accepts a command containing the `{file}` placeholder.

Default example:

```text
clamdscan --no-summary {file}
```

`{file}` is replaced internally by the temporary path of the uploaded file.

### Command restrictions

For security, SecureScan does not treat the configured command as an unrestricted shell command. Shell syntax such as the following is intentionally not accepted:

- command separators (`;`)
- shell pipelines (`|`)
- redirection (`>`, `<`)
- command substitution (`$()` / backticks)
- shell boolean operators (`&&`, `||`)
- other shell constructs that would turn the configuration field into arbitrary command execution

The ClamAV scanner executable and arguments are converted into a direct argument vector and executed without a shell. The executable is validated automatically and must be `clamdscan` or `clamscan`, including an absolute path to one of those binaries. Basenames are resolved only from fixed system directories; explicit absolute paths must resolve to approved scanner binaries. This prevents shell metacharacters from becoming a second command language while keeping the configuration simple for administrators.

> The exact command accepted by SecureScan depends on the command validation implemented by the installed plugin version. Always test the command from **Setup → Plugins → SecureScan → Configure** before enabling protection.

---

## Configuration

Go to:

**Setup → Plugins → SecureScan → Configure**

The configuration provides the following core controls:

### Enable analysis before publishing

Controls whether SecureScan protects the supported GLPI upload workflow.

The plugin does not allow the administrator to enable the protection until the current antivirus command has passed the built-in test.

### Analysis command

Defines the scanner command. Use `{file}` as the temporary-file marker.

Example:

```text
clamdscan --no-summary {file}
```

The configured scanner command must keep the per-file result in its output so SecureScan can positively verify a clean scan. The recommended `--no-summary` form does this. Do not use output-suppressing options such as `--quiet` when they prevent ClamAV from returning the target file result; SecureScan will reject an otherwise successful `exit code 0` when no positive `OK` evidence is available.

### Test antivirus

The **Test antivirus** action creates a controlled temporary test file and executes the currently configured scanner command against it.

A successful test verifies that the configured command can be executed and returns an acceptable clean result. The test result is recorded independently from normal document scans.

If the test fails, SecureScan reports the scanner execution problem and the protection cannot be enabled for that command.

### ClamAV executable validation

SecureScan currently supports ClamAV only. The executable is validated automatically when the command is saved or tested and must be `clamdscan` or `clamscan`, or an absolute path to one of those executables. The administrator does not need to maintain a separate executable list. This security control is kept internally so the configuration remains simple while preventing the command field from being used to launch arbitrary programs.

### Antivirus timeout

Controls how long SecureScan waits for the antivirus process. The default is **30 seconds** and the allowed range is **5 to 300 seconds**. A timeout is treated as a scan error and the file is rejected.

### Automatic version checks

Automatic GitHub stable-release checks are **disabled by default**. When enabled, SecureScan caches successful checks for six hours and failed checks for 30 minutes so an unavailable GitHub service does not block normal configuration-page rendering on every request.

### Save

Configuration changes are saved through SecureScan's native GLPI/Symfony controller integration. The save operation validates the submitted configuration before persisting it.

---

## Scan verification and audit evidence

Starting with SecureScan 1.0.2, an antivirus exit code of `0` is not accepted as proof of a clean file by itself. SecureScan requires positive output evidence for the exact temporary file and accepts the clean result only when ClamAV reports that target as `OK`.

If ClamAV reports a scan limit, skipped/excluded file, symbolic-link condition, access/open failure, or another ambiguous response, SecureScan fails closed and rejects the upload. This prevents a file that was not actually scanned from being stored as clean.

The detailed audit file is `files/_log/securescan.log`. SecureScan records normalized evidence rather than persisting raw ClamAV output. A successful scan can look like:

```json
{
  "type": "document",
  "status": "clean",
  "scan_verdict": "clean",
  "scan_evidence": "target_ok",
  "exit_code": 0,
  "size": 184320,
  "sha256": "...",
  "temporary": "glpi_abc123",
  "itemtype": "Document",
  "items_id": 0
}
```

A file that ClamAV did not confirm as scanned is recorded explicitly and rejected, for example:

```json
{
  "type": "document",
  "status": "error",
  "scan_verdict": "not_scanned",
  "scan_evidence": "size_limit_reached",
  "exit_code": 0,
  "size": 2097152,
  "sha256": "..."
}
```

Common normalized evidence values include `target_ok`, `target_found`, `size_limit_reached`, `cannot_open`, `excluded`, `symbolic_link`, `exit_code_infected`, `contradictory_output`, `no_positive_scan_evidence`, and `timeout`.

Raw scanner output is intentionally not written to the audit file. File contents are never logged.

## Antivirus test

The built-in test is intentionally different from uploading a document.

It verifies the **configured scanner command itself**, including whether the server can execute the antivirus program and obtain a valid clean result.

A typical successful test produces an audit entry similar to:

```json
{
  "type": "test",
  "status": "clean",
  "scan_verdict": "clean",
  "scan_evidence": "target_ok",
  "exit_code": 0,
  "size": 26
}
```

The exact log entry can contain additional metadata such as timestamp, SHA-256, temporary-file identifier, and user ID.

### Why the test is required

Without this validation, an administrator could enable file scanning while the antivirus binary was missing, inaccessible, incorrectly configured, or returning an unexpected result. SecureScan deliberately avoids treating such a configuration as safe.

---

## Document scanning

When a supported GLPI document upload is processed while SecureScan is enabled:

1. GLPI receives the uploaded file.
2. SecureScan obtains the temporary upload.
3. SecureScan calculates identifying metadata such as SHA-256.
4. The configured antivirus command scans the temporary file.
5. A **clean** result allows the normal document workflow to continue.
6. An **infected** result rejects the upload.
7. A scanner execution error also rejects the upload.
8. Temporary scan data is cleaned up after processing.
9. Successful storage can generate a separate `document_stored` audit event.

### Clean file

A clean PDF or other supported document should appear normally in GLPI after the upload completes.

The audit trail can contain two related events:

```text
scan result: clean
       ↓
document stored: clean
```

This distinction is useful because it proves both that the file passed the antivirus inspection and that it subsequently entered GLPI's document storage workflow.

### Infected file

An infected upload is rejected before it becomes a stored GLPI document.

A typical audit event is:

```json
{
  "type": "document",
  "status": "infected",
  "exit_code": 1,
  "size": 68,
  "itemtype": "Document",
  "items_id": 0
}
```

The exact values depend on the scanner and upload context.

---

## EICAR test

For production validation, use the **EICAR Anti-Malware Testfile** instead of real malware.

EICAR is a harmless industry-standard test string designed to be detected by antivirus software. It allows administrators to verify the complete rejection path without introducing actual malicious code into the environment.

### Recommended validation

Perform these tests in a non-production or controlled environment:

| Test | Expected result |
|---|---|
| Antivirus test with the configured command | **Clean / successful** |
| Upload a normal PDF | **Accepted and stored** |
| Upload the EICAR test file | **Rejected as infected** |
| Check SecureScan audit data | Corresponding `clean` / `infected` event is present |
| Check GLPI documents | EICAR file is **not** present as a stored document |

> Never use real malware to validate the plugin. EICAR provides a safe functional test for antivirus detection and rejection.

---

## Audit trail

SecureScan records structured scan information so administrators can determine what happened during a scan without exposing the file contents in the log.

Depending on the event, the audit record can include:

| Field | Purpose |
|---|---|
| `time` | Date and time of the event. |
| `type` | Event type such as `test`, `document`, or `document_stored`. |
| `status` | Result such as `clean` or `infected`. |
| `exit_code` | Antivirus process exit code. |
| `size` | Size of the scanned file in bytes. |
| `sha256` | SHA-256 fingerprint of the scanned file. |
| `temporary` | Temporary upload identifier/path when applicable. |
| `itemtype` | GLPI item type associated with the upload. |
| `items_id` | GLPI item ID when available. |
| `user_id` | GLPI user who initiated the operation. |

### Example successful lifecycle

```text
20:13:07  document          clean       exit=0
20:13:07  document_stored   clean       exit=0
```

### Example rejected upload

```text
20:13:39  document          infected    exit=1
```

An infected file does not receive a corresponding `document_stored` event because it must not enter GLPI's document storage workflow.

---

## GLPI history

SecureScan's structured audit records and GLPI's native history serve different purposes.

- **SecureScan audit data** records the antivirus operation and its technical result.
- **GLPI history** records normal GLPI object activity and can provide the user-facing history associated with the affected object.

This separation avoids polluting standard GLPI history with large amounts of low-level scanner metadata while retaining the information required for security investigation.

When a scan is associated with a stored GLPI document, the document's normal GLPI history can be used alongside SecureScan audit data to correlate the upload with the user and timestamp.

Messages shown to users are translation-ready and follow the active GLPI language.

---

## Requirements

| Requirement | Minimum / Notes |
|---|---|
| **GLPI** | 11.x / 12.x |
| **PHP** | ≥ 8.2 |
| **Antivirus engine** | ClamAV only |
| **Scanner command** | A working command that accepts the `{file}` placeholder |
| **Server permissions** | The PHP/web-server account must be able to execute the scanner and access the temporary upload location |

### ClamAV example

On a Linux server, verify the scanner independently before configuring SecureScan:

```bash
command -v clamdscan
clamdscan --version
```

Then test a harmless local file using the same command pattern configured in SecureScan.

> The exact ClamAV service/socket configuration depends on the operating system and hosting environment. SecureScan does not install or configure ClamAV itself.

---

## Installation

### Via ZIP — recommended

1. Download the latest `.zip` from the [GitHub Releases page](https://github.com/monta990/securescan/releases).
2. In GLPI, go to **Setup → Plugins**.
3. Click **Upload a plugin**.
4. Select the SecureScan ZIP.
5. Install the plugin.
6. Enable **SecureScan**.
7. Open **Configure**.
8. Configure the antivirus command.
9. Click **Test antivirus**.
10. Confirm that the test succeeds.
11. Enable **analysis before publishing**.
12. Save the configuration.

### Manual installation

```bash
cd /var/www/glpi/plugins
unzip securescan-X.X.X.zip
```

The plugin directory must be named exactly:

```text
securescan
```

Then go to **Setup → Plugins**, install and enable SecureScan.

---

## Uninstallation

1. Go to **Setup → Plugins**.
2. Disable **SecureScan**.
3. Uninstall the plugin.

Before uninstalling in a production environment, review the plugin's configuration and audit requirements for your organization's retention policy.

---

## Security considerations

SecureScan is designed around several security principles:

### No arbitrary shell syntax

The antivirus command is not treated as unrestricted shell input. Dangerous shell constructs are rejected during command validation.

### Temporary-file scanning

The file is scanned while temporary, before normal document storage. This is the core security boundary of the plugin.

### Fail closed

An antivirus execution failure is not interpreted as a clean file. A file that cannot be positively validated is rejected.

### Explicit enablement test

The administrator must successfully test the current command before enabling scanning. Changing the command invalidates the previous successful validation.

### No file contents in audit records

The audit information identifies the file through metadata such as size and SHA-256 rather than writing the file contents into the log.

### CSRF protection

Administrative POST operations use GLPI's native CSRF protection and authorization mechanisms.

### Native GLPI architecture

SecureScan integrates with GLPI's current plugin/controller architecture rather than requiring modifications to GLPI core files.

### Defense in depth

SecureScan should be deployed together with:

- current GLPI security updates;
- current PHP and operating-system security updates;
- restrictive filesystem permissions;
- a correctly configured antivirus service;
- HTTPS;
- least-privilege service accounts;
- appropriate backups and monitoring;
- GLPI's own authentication and authorization controls.

---

## Production deployment checklist

Before enabling SecureScan in production:

- [ ] ClamAV is installed and operational.
- [ ] The web/PHP account can execute the scanner.
- [ ] The scanner can access GLPI's temporary upload files.
- [ ] `clamdscan --no-summary {file}` or the selected command works independently.
- [ ] **Test antivirus** succeeds from the SecureScan configuration page.
- [ ] A normal PDF/document is accepted.
- [ ] The EICAR test file is rejected in a controlled validation environment.
- [ ] The EICAR file is not stored as a GLPI document.
- [ ] Audit records show the expected `clean` and `infected` results.
- [ ] PHP and GLPI logs are monitored for scanner execution errors.
- [ ] Antivirus definitions are kept current.
- [ ] The production retention policy for security logs has been reviewed.

---

## Troubleshooting

### "The antivirus test failed"

Check:

1. The scanner executable exists.
2. The PHP/web-server account has permission to execute it.
3. The antivirus daemon/service is running when required.
4. The configured command contains `{file}`.
5. The command does not contain rejected shell syntax.
6. The same command works against a harmless temporary file from the server account.

### Files are rejected with an execution error

This normally indicates that SecureScan could not obtain a valid antivirus result. Check the scanner binary, daemon/socket availability, filesystem permissions, and server logs.

Do **not** disable the protection simply to make uploads work. The fail-closed behavior is intentional.

### A clean file is accepted but no `document_stored` entry appears

Verify that the normal GLPI document transaction completed successfully after the antivirus stage. A clean scan proves that the file passed the scanner; it does not by itself prove that GLPI subsequently stored the document.

### EICAR is rejected

This is the expected result. A rejected EICAR upload confirms that the detection-to-rejection path is operating correctly.

---

## Compatibility

The current plugin metadata declares:

- **GLPI 11.x (11.0.7+)**
- **GLPI 12.x**
- **PHP ≥ 8.2**
- **SecureScan 0.1.24**

Compatibility is maintained against the GLPI APIs and plugin architecture targeted by the current release.

---

## Development

Repository:

**https://github.com/monta990/securescan**

The project is developed as a standalone GLPI plugin and should not require modifications to GLPI core files.

When contributing changes that affect file handling, antivirus execution, command validation, routing, authorization, or configuration persistence, regression testing should cover both the **clean** and **rejected** paths.

At minimum, changes affecting the security boundary should verify:

1. clean file → accepted;
2. infected file → rejected;
3. scanner failure → rejected;
4. invalid command → rejected;
5. configuration test → successful only with a valid scanner;
6. changed command → previous successful test is not reused;
7. audit record → correct status and exit code;
8. no infected document → stored in GLPI.

---

## License

SecureScan is released under the **GNU General Public License v3 or later (GPLv3+)**.

See [`LICENSE`](LICENSE) for the complete license text.

---

## Buy me a coffee :)

If you like my work, you can support me with a donation:

<a href="https://www.buymeacoffee.com/monta990" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="51px" width="210px"></a>

---

## Author

**Edwin Elias Alvarez**

Project: [github.com/monta990/securescan](https://github.com/monta990/securescan)
