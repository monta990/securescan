<p align="center">
  <p align="center"><img src="logo.png" alt="SecureScan" width="128" height="128"></p>
</p>
<h1 align="center">SecureScan 2.0.0</h1>
<p align="center">
  <strong>GLPI document upload protection with one selected antivirus engine: ClamAV or VirusTotal API v3</strong>
</p>
<p align="center">
  <a href="https://github.com/glpi-project/glpi" target="_blank"><img src="https://img.shields.io/badge/GLPI-11.0.7%2B-blue" alt="GLPI 11 compatibility"></a>
  <a href="https://github.com/glpi-project/glpi" target="_blank"><img src="https://img.shields.io/badge/GLPI-12.0%2B-blue" alt="GLPI 12 compatibility"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank"><img src="https://img.shields.io/badge/License-GPL%20v3%2B-green" alt="License"></a>
  <a href="https://php.net/" target="_blank"><img src="https://img.shields.io/badge/PHP-%3E%3D8.2-purple" alt="PHP"></a>
  <a href="https://github.com/monta990/securescan/actions/workflows/ci.yml" target="_blank"><img src="https://github.com/monta990/securescan/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/monta990/securescan/releases" target="_blank"><img src="https://img.shields.io/github/v/release/monta990/securescan" alt="Latest release"></a>
  <a href="https://github.com/monta990/securescan/releases" target="_blank"><img src="https://img.shields.io/github/downloads/monta990/securescan/total" alt="GitHub Downloads"></a>
</p>

---

## Overview

**SecureScan** protects GLPI's document upload workflow by inspecting files **before they are stored as GLPI documents**. Version 2.0.0 supports two alternative antivirus engines:

- **ClamAV** — a local scanner running on the GLPI server through `clamdscan` or `clamscan`.
- **VirusTotal API v3** — a cloud-based reputation and analysis service.

Only one engine can be selected at a time. The configuration offers **Disabled**, **ClamAV (server)**, or **VirusTotal (cloud)**. Disabled turns scanning off; it does not run both providers. If an inconsistent saved configuration contains both engine flags, SecureScan treats it as a conflict and rejects uploads until an administrator selects and saves one engine.

A completed **clean** result is the only result that allows a file to continue into GLPI's normal document storage workflow. Infected, suspicious, skipped, pending, ambiguous, failed, or unavailable results are never treated as clean. VirusTotal analyses that are still pending remain in a protected temporary workflow and are not stored until a completed clean result is available.

The plugin is designed to keep antivirus operations isolated from GLPI core code and to use GLPI's native configuration, authorization, routing, CSRF protection, translations, and history mechanisms wherever applicable.

## Security model

SecureScan follows a **fail-closed** approach for the protected upload path. A file is allowed to continue only after the selected engine has produced positive evidence of a completed clean scan.

| Result / configuration state | SecureScan action |
|---|---|
| **Disabled** | Scanning is intentionally turned off. |
| **Clean** | The file may continue through GLPI's normal document workflow. |
| **Infected** | The file is rejected and is not stored as a GLPI document. |
| **Suspicious (VirusTotal)** | The file is rejected; suspicious is not treated as clean. |
| **Pending (VirusTotal)** | The file remains in the asynchronous preflight workflow. It is not stored while analysis is pending. |
| **Not scanned / ambiguous** | The file is rejected because SecureScan cannot prove that the exact file was fully scanned. |
| **Scan error / timeout / unavailable provider** | The file is rejected. |
| **Two engines enabled in saved settings** | SecureScan reports a configuration conflict and rejects uploads until one engine is selected and saved. |
| **Invalid ClamAV command or invalid VirusTotal credentials** | The selected engine cannot be approved for use. |

A successful **Test selected engine** check is required for the current configuration before the protected upload path can rely on it. Changing the ClamAV command invalidates its previous test; VirusTotal credentials and connectivity must also pass their engine test.

> **Important:** SecureScan does not replace server hardening, operating-system permissions, GLPI security updates, endpoint protection, backups, or other security controls. It adds an antivirus inspection layer to GLPI file handling.

## Features

| Feature | Details |
|---|---|
| **Pre-storage scanning** | Uploaded files are inspected before they become stored GLPI documents. |
| **ClamAV integration** | Supports ClamAV scanners such as `clamdscan --no-summary {file}` and `clamscan --no-summary {file}`. |
| **VirusTotal API v3 integration** | Provides VirusTotal as an alternative cloud engine; it does not run together with ClamAV. |
| **Single-engine selector** | Choose Disabled, ClamAV (server), or VirusTotal (cloud). Conflicting saved flags fail closed. |
| **Encrypted VirusTotal API key** | The API key is stored using GLPI's encrypted configuration and is never displayed again in the settings form. |
| **Asynchronous VirusTotal preflight** | Pending analyses are checked by separate requests without holding a PHP session lock or sleeping in a PHP worker. |
| **Private VirusTotal quarantine** | A private copy and SHA-256 verification protect the staged file while VirusTotal completes its analysis. |
| **VirusTotal quota handling** | Shared request throttling, separate daily quota accounting, and upstream `Retry-After` handling. |
| **Optional unknown-file submission** | Automatic submission of unknown files is off by default and limited to files up to 32 MB when enabled. |
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

For a protected document upload, the selected engine determines the scan path:

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
Resolve the one selected engine
       │
       ├───────────────┬──────────────────┐
       │               │                  │
       ▼               ▼                  ▼
    DISABLED         CLAMAV           VIRUSTOTAL
       │               │                  │
       ▼               ▼                  ▼
No scan runs     Scan temporary      Hash / report lookup
                 file locally              │
                       │                    ├── Completed clean
                       │                    │       │
                       │                    │       ▼
                       │                    │  Restore staged file
                       │                    │
                       │                    ├── Pending analysis
                       │                    │       │
                       │                    │       ▼
                       │                    │  Private protected copy
                       │                    │  and asynchronous polling
                       │                    │
                       └──────────┬─────────┴──────────┐
                                  │                    │
                                  ▼                    ▼
                              CLEAN             INFECTED / ERROR /
                                  │              SUSPICIOUS / UNKNOWN
                                  ▼                    │
                         Continue GLPI                 ▼
                         document flow            Reject upload
                                  │
                                  ▼
                           Document stored
                                  │
                                  ▼
                              Audit entry
```

With ClamAV, the decision is made while the uploaded file is still temporary. With VirusTotal, a pending analysis is kept in a private plugin-managed location; the original GLPI staged filename is restored only after a completed clean result and a matching SHA-256 check. An infected, suspicious, missing, invalid, pending-at-final-decision, or unavailable result never becomes an approved stored document.

## Antivirus command

The configuration page accepts a command containing the `{file}` placeholder.

Default example:

```text
clamdscan --no-summary {file}
```

`{file}` is replaced internally by the temporary path of the uploaded file.

### ClamAV scan-limit handling (important)

ClamAV can report a file as `OK` even when a scan limit caused content to be skipped. SecureScan cannot infer the daemon's active `clamd.conf` settings just from that line, so the scanner must be configured to flag exceeded limits:

- **When using `clamdscan` (the default):** set `AlertExceedsMax yes` in the daemon's `clamd.conf` and restart/reload `clamd`. This server-side setting is mandatory; it cannot be forced by a `clamdscan` client argument.
- **When using `clamscan`:** SecureScan automatically passes `--alert-exceeds-max=yes` and removes any conflicting value from the configured command.

With this setting, ClamAV marks exceeded file-size, scan-size, or recursion limits as `Heuristics.Limits.Exceeded`, and SecureScan rejects the upload as `not_scanned` instead of treating it as clean. Validate the exact command using **Test antivirus** after changes to ClamAV or the plugin. When you click **Test antivirus**, SecureScan scans both a clean test file and a small harmless ZIP archive nested beyond ClamAV’s supported recursion ceiling. The command is approved only if the second test returns ClamAV’s `Heuristics.Limits.Exceeded` finding; this check catches a `clamdscan` daemon that has not enabled `AlertExceedsMax`. Re-run this test after changes to the plugin or ClamAV configuration. The probe contains only harmless text and is removed after testing.

### Command restrictions

For security, SecureScan does not treat the configured command as an unrestricted shell command. Shell syntax such as the following is intentionally not accepted:

- command separators (`;`)
- shell pipelines (`|`)
- redirection (`>`, `<`)
- command substitution (`$()` / backticks)
- shell boolean operators (`&&`, `||`)
- other shell constructs that would turn the configuration field into arbitrary command execution

The ClamAV scanner executable and arguments are converted into a direct argument vector and executed without a shell. The executable is validated automatically and must be `clamdscan` or `clamscan`, including an absolute path to one of those binaries. Basenames are resolved only from fixed system directories; explicit absolute paths must resolve to approved scanner binaries. This prevents shell metacharacters from becoming a second command language while keeping the configuration simple for administrators. SecureScan also rejects ClamAV quarantine/action options `--copy`, `--move`, and `--remove`, including their `=...` forms, because they can persist or alter infected content outside GLPI's rejected temporary upload. The executable is not resolved from `PHP_BINDIR`; it must be installed in a fixed system directory such as `/usr/bin` or `/usr/local/bin`.

> The command is used only when **ClamAV (server)** is selected. Always test it with **Test selected engine** from **Setup → General → Configuration → SecureScan** before relying on it for protected uploads.

---

## Configuration

Open:

**Setup → General → Configuration → SecureScan**

The configuration page contains one **Active scan engine** selector:

| Selector value | Behavior |
|---|---|
| **Disabled** | SecureScan does not scan uploads. |
| **ClamAV (server)** | Uses the configured local ClamAV command. VirusTotal is not called. |
| **VirusTotal (cloud)** | Uses VirusTotal API v3. The ClamAV command is not executed. |

Only one engine can be active. The interface does not offer a combined mode. If the page detects that old or manually edited settings have both engine flags enabled, it displays a conflict warning and requires the administrator to select one engine and save.

### ClamAV (server)

When ClamAV is selected, configure the **Scan command** with exactly one `{file}` placeholder.

Default example:

```text
clamdscan --no-summary {file}
```

The command is executed without a shell and is used only for the ClamAV engine. The executable must resolve to `clamdscan` or `clamscan`; arbitrary programs and shell operators are not accepted.

The command must retain the per-file result in its output so SecureScan can positively verify the exact upload. The recommended `--no-summary` form does this. Avoid output-suppressing options such as `--quiet` when they prevent ClamAV from returning the target file result; an otherwise successful exit code of `0` is rejected when no positive `OK` evidence is available.

The **Antivirus timeout** defaults to **30 seconds**. The allowed range is **5 to 300 seconds**. A timeout rejects the file.

For `clamdscan`, set `AlertExceedsMax yes` in `clamd.conf` and restart or reload the `clamd` service. When `clamscan` is used, SecureScan adds `--alert-exceeds-max=yes` automatically and removes conflicting values. See [ClamAV scan-limit handling](#clamav-scan-limit-handling-important) for why this is important.

### VirusTotal (cloud)

Select **VirusTotal (cloud)** to use VirusTotal by itself. ClamAV does not run in this mode.

#### API key

Enter a VirusTotal API key in the **VirusTotal API key** field. GLPI encrypts the key using the GLPI instance security key. Once saved, the plaintext is not displayed again. When an API key is already configured, leaving the field blank preserves the stored key; use **Remove stored VirusTotal API key** to remove it.

You can obtain the key from the [VirusTotal API key page](https://www.virustotal.com/gui/my-apikey).

Use **Test selected engine** to verify that the configured key and outbound HTTPS/API connectivity work. The test validates access to the service; it does not submit the uploaded business document as a sample.

#### Submit unknown files to VirusTotal automatically

This option is **off by default**.

When disabled, SecureScan looks up the file by SHA-256. If VirusTotal has no report for that hash, the file is not submitted automatically and the upload is not approved.

When enabled, an unknown file up to **32 MB** may be submitted for analysis. The file remains in a private protected workflow while VirusTotal processes it. SecureScan continues checking the analysis status and stores the document only after VirusTotal reports a completed clean result. Larger files are not submitted automatically.

#### Privacy, terms, and API limits

VirusTotal Public/Community API access is limited to **4 requests per minute and 500 requests per day** in the public tier. SecureScan applies shared local request throttling, keeps quota-exempt API operations separate from daily quota accounting, and honors upstream `Retry-After` responses. Actual limits and permitted use depend on the VirusTotal agreement associated with the API key.

VirusTotal Public/Community API must not be used in commercial products, services, or business workflows. Use an appropriate Premium agreement for corporate production. Files submitted to VirusTotal and queried indicators may be added to its shared dataset and may be accessible to the security community. **Never submit confidential, personal, customer, employee, or business-sensitive documents using a Public/Community key.**

See [VirusTotal API terms and limits](https://docs.virustotal.com/reference/public-vs-premium-api).

### Automatic version checks

Automatic GitHub stable-release checks are **disabled by default**. When enabled, SecureScan checks for stable releases and caches successful checks for **six hours** and failed checks for **30 minutes** so an unavailable GitHub service does not block normal configuration-page rendering on every request.

### Test selected engine

The **Test selected engine** button tests the engine currently selected in the configuration:

- **ClamAV:** runs a clean-file check and the ClamAV scan-limit safety probe described below.
- **VirusTotal:** verifies the API key and the ability to reach the VirusTotal API.

A successful test is recorded separately from normal document scans. A changed ClamAV command must be tested again. A VirusTotal configuration must pass its connection test before it can be relied on for document preflight.

### Save

Save the selected engine and its settings from the same configuration page. The save operation validates the submitted configuration before persisting it through GLPI's native plugin/controller integration. Do not enable a second engine in the underlying configuration. If there is a legacy configuration conflict, select exactly one engine and save so both stored engine flags are written consistently.

## Scan verification and audit evidence

SecureScan does not accept a ClamAV exit code of `0` as proof of a clean file by itself. It requires positive output evidence for the **exact temporary file** and accepts a clean result only when ClamAV reports that target as `OK` (or the supported single-file transport result when explicitly configured).

ClamAV can report a file as `OK` even when a scan limit caused part of the content to be skipped. SecureScan therefore verifies scan-limit reporting as part of the administrator's ClamAV test. If ClamAV reports a scan limit, skipped/excluded file, symbolic-link condition, access/open failure, contradictory response, or another ambiguous result, SecureScan fails closed.

### ClamAV status and verdict states

The audit record distinguishes the high-level `status` from the more detailed `scan_verdict`:

| ClamAV outcome | `status` | `scan_verdict` | Result |
|---|---|---|---|
| Exact target positively reported as clean | `clean` | `clean` | Allowed to continue. |
| Exact target reported as infected | `infected` | `infected` | Rejected. |
| Scan limit or skipped content | `error` | `not_scanned` | Rejected; this is not a clean result. |
| Missing, ambiguous, foreign-target, or contradictory output | `error` | `unknown` | Rejected. |
| Timeout, excessive output, or scanner execution error | `error` | `error` | Rejected. |

ClamAV's conventional exit codes are interpreted together with the output: `0` means no threat was reported, `1` normally indicates a detection, and `2+` indicates a scan error. SecureScan still requires target-specific output evidence; an exit code alone never approves the file.

Common normalized `scan_evidence` values include `target_ok`, `target_ok_transport` (a single-file `clamdscan --fdpass`/`--stream` response when explicitly configured), `target_found`, `size_limit_reached`, `cannot_open`, `excluded`, `symbolic_link`, `exit_code_infected`, `contradictory_output`, `ambiguous_output`, `no_positive_scan_evidence`, `configuration_not_retested`, `timeout`, and `output_limit_reached`. Target results are matched against the exact temporary path, not only the basename, and skip indicators are checked in result text rather than the uploaded filename.

A successful ClamAV scan can be recorded as:

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
  "exit_code": 1,
  "size": 2097152,
  "sha256": "..."
}
```

Raw scanner output is intentionally not written to the audit file. File contents are never logged. Output is capped at **64 KiB**; a scanner that exceeds that cap is terminated and the upload is rejected with `output_limit_reached`.

### VirusTotal status and verdict states

VirusTotal results are normalized into distinct states:

| VirusTotal state | Meaning | SecureScan action |
|---|---|---|
| `clean` | Completed report with no malicious or suspicious detections and positive harmless/undetected evidence. | May continue after the staged file is restored and its SHA-256 is verified. |
| `infected` | One or more malicious detections. | Reject. |
| `suspicious` | One or more suspicious detections and no malicious count. | Reject. |
| `pending` | Analysis is queued or in progress, or a retryable remote response requires another check. | Keep the upload pending; do not store it yet. |
| `not_found` | No existing file report was found. | Reject unless optional automatic unknown-file submission is enabled and a completed clean result is later returned. |
| `unavailable` | API credentials, network, response, analysis state, or report data cannot be validated. | Reject. |

For VirusTotal, only a completed analysis with positive clean evidence is approved. Missing statistics, failed/aborted/unknown analysis states, malicious detections, and suspicious detections are not interpreted as clean.

The detailed audit file is `files/_log/securescan.log`. Audit entries contain normalized verdicts and bounded metadata rather than raw API responses, API keys, file contents, or original filenames.

## Antivirus test

The **Test selected engine** action validates the engine currently selected in the configuration. It is intentionally different from uploading a document.

### ClamAV test

For ClamAV, the test creates a controlled temporary clean file and executes the configured scanner command. It then scans a small harmless ZIP archive nested to 102 levels, beyond ClamAV's supported recursion ceiling of 100. The ClamAV command is approved only when the clean file is positively reported as clean **and** the nested archive triggers the expected `Heuristics.Limits.Exceeded` result.

This second probe catches a `clamdscan` daemon that has not enabled `AlertExceedsMax`. The probe contains only harmless text and is removed after testing.

A typical clean test entry looks like:

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

The limit guard is recorded separately as a `test_limit_guard` event with `scan_verdict: not_scanned` and `scan_evidence: size_limit_reached`. This is an expected safety check, not an indication that the ordinary clean-file test failed.

### VirusTotal test

For VirusTotal, the test checks that the saved API key is usable and that SecureScan can reach the VirusTotal API over HTTPS. It does not upload the current user's document or use an arbitrary file as a sample.

The key is retained encrypted by GLPI and is never echoed back into the page or audit log.

### Why the test is required

Without engine validation, an administrator could enable file scanning while the local scanner is missing or inaccessible, a ClamAV daemon is not reporting scan-limit violations, an API key is invalid, or outbound connectivity is unavailable. SecureScan deliberately avoids treating such a configuration as safe.

## Document scanning

When a supported GLPI document upload is processed while a scan engine is selected:

1. GLPI receives the uploaded file.
2. SecureScan obtains the temporary upload and calculates identifying metadata such as SHA-256.
3. SecureScan resolves the one configured engine.
4. **ClamAV mode:** the configured local scanner inspects the temporary file and SecureScan validates the exact target result.
5. **VirusTotal mode:** SecureScan looks up the SHA-256 through VirusTotal API v3. If a report is not available and automatic unknown-file submission is enabled, it submits the file within the configured size limit.
6. A **completed clean** result allows the normal document workflow to continue.
7. An **infected** or **suspicious** result rejects the upload.
8. A scan error, skipped file, pending final state, missing report without permitted submission, or unavailable provider never counts as clean.
9. For a pending VirusTotal analysis, SecureScan stores a protected private copy, checks the analysis asynchronously, validates SHA-256, and restores the original GLPI staged filename only after the clean result.
10. Successful storage can generate a separate `document_stored` audit event.

### Clean file

A clean PDF or other supported document should appear normally in GLPI after the upload completes.

For ClamAV, the audit trail can contain two related events:

```text
scan result: clean
       ↓
document stored: clean
```

For VirusTotal, the document is not resumed into GLPI's normal storage flow until the completed clean result is saved and the protected staged copy has been restored. The SHA-256 of the restored file must match the original hash.

This distinction is useful because it proves both that the file passed antivirus inspection and that it subsequently entered GLPI's document storage workflow.

### Infected file

An infected upload is rejected before it becomes a stored GLPI document. VirusTotal suspicious verdicts are also rejected; they are not downgraded to clean.

A typical ClamAV audit event is:

```json
{
  "type": "document",
  "status": "infected",
  "scan_verdict": "infected",
  "exit_code": 1,
  "size": 68,
  "itemtype": "Document",
  "items_id": 0
}
```

The exact values depend on the selected engine and upload context.

## EICAR test

For local ClamAV validation, use the **EICAR Anti-Malware Testfile** instead of real malware.

EICAR is a harmless industry-standard test string designed to be detected by antivirus software. It allows administrators to verify the complete local detection-and-rejection path without introducing actual malicious code into the environment.

For VirusTotal mode, follow the VirusTotal agreement and your organization's data-handling policy. Do not submit confidential or business-sensitive files for testing. The plugin's VirusTotal connection test does not submit the current document.

## Audit trail

SecureScan records structured scan information so administrators can determine what happened during a scan without exposing file contents or secrets in the log.

Depending on the event and selected engine, the audit record can include:

| Field | Purpose |
|---|---|
| `time` | Date and time of the event. |
| `type` | Event type such as `test`, `document`, `document_preflight`, `analysis_submitted`, `analysis_completed`, or `document_stored`. |
| `status` | Normalized result such as `clean`, `infected`, `suspicious`, `pending`, `not_found`, `unavailable`, or `error`. |
| `scan_verdict` | More detailed normalized verdict, including ClamAV `not_scanned` or `unknown` states. |
| `scan_evidence` | Bounded explanation of the evidence or failure reason. |
| `exit_code` | Local antivirus process exit code, when applicable. |
| `size` | Size of the scanned file in bytes. |
| `sha256` | SHA-256 fingerprint of the scanned file. |
| `temporary` | Temporary upload identifier/path when applicable. |
| `itemtype` | GLPI item type associated with the upload. |
| `items_id` | GLPI item ID when available. |
| `user_id` | GLPI user who initiated the operation. |
| `providers` | Normalized, non-secret provider evidence when applicable. |

### Example successful lifecycle

```text
20:13:07  document          clean       exit=0
20:13:07  document_stored   clean       exit=0
```

### Example rejected upload

```text
20:13:39  document          infected    exit=1
```

An infected or suspicious file does not receive a corresponding `document_stored` event because it must not enter GLPI's document storage workflow.

The detailed diagnostic log is `files/_log/securescan.log`. VirusTotal request-performance records use normalized timing and status values; API keys, raw API payloads, original filenames, and file contents are not logged.

## GLPI history

SecureScan's structured audit records and GLPI's native history complement one another.

- **SecureScan audit data** records the antivirus operation, normalized provider result, and technical evidence in `files/_log/securescan.log`.
- **GLPI native document history** provides a concise user-facing security entry associated with the stored document, including the clean result and SHA-256 where available. A validated VirusTotal report link may be included for a clean VirusTotal result.

This keeps low-level scanner and request-performance details in the dedicated audit log while preserving a native GLPI history entry that can be correlated with the document, user, and timestamp.

Messages shown to users are translation-ready and follow the active GLPI language.

## Requirements

| Requirement | Minimum / Notes |
|---|---|
| **GLPI** | 11.x (11.0.7+) / 12.x |
| **PHP** | ≥ 8.2 |
| **Scan engine** | Select one: local ClamAV, VirusTotal API v3, or Disabled. |
| **ClamAV mode** | `clamdscan` or `clamscan` installed on the GLPI server; PHP/web-server account can execute it and read the temporary upload. |
| **VirusTotal mode** | A valid VirusTotal API key, outbound HTTPS connectivity, and a GLPI instance security key usable for encrypted configuration. |
| **VirusTotal private storage** | The plugin document directory must be writable by GLPI and must not be exposed directly by the web server. |
| **Scanner command** | For ClamAV, a supported command containing exactly one `{file}` placeholder. |
| **Server permissions** | The PHP/web-server account must be able to access the temporary upload location and the selected engine's required resources. |

### ClamAV example

On a Linux server, verify the scanner independently before configuring SecureScan:

```bash
command -v clamdscan
clamdscan --version
```

Then test a harmless local file using the same command pattern configured in SecureScan.

> The exact ClamAV service/socket configuration depends on the operating system and hosting environment. SecureScan does not install or configure ClamAV itself.

### VirusTotal connectivity

The GLPI server must be able to establish outbound HTTPS connections to the VirusTotal API. The API key is stored encrypted through GLPI's secure configuration mechanism. SecureScan does not require a locally installed ClamAV binary when VirusTotal is selected.

## Installation

### Via ZIP — recommended

1. Download the latest versioned `.zip` from the [GitHub Releases page](https://github.com/monta990/securescan/releases).
2. In GLPI, go to **Setup → Plugins**.
3. Click **Upload a plugin**.
4. Select the SecureScan ZIP.
5. Install the plugin.
6. Enable **SecureScan**.
7. Open **Setup → General → Configuration → SecureScan**.
8. Select exactly one engine: **Disabled**, **ClamAV (server)**, or **VirusTotal (cloud)**.
9. Configure the selected engine.
10. Click **Test selected engine**.
11. Confirm that the test succeeds.
12. Save the configuration and verify the selected engine before testing document uploads.

### Manual installation

```bash
cd /var/www/glpi/plugins
unzip securescan-2.0.0.zip
```

The plugin directory must be named exactly:

```text
securescan
```

Then go to **Setup → Plugins**, install and enable SecureScan, and open **Setup → General → Configuration → SecureScan** to select and test the engine.

## Uninstallation

1. Go to **Setup → Plugins**.
2. Disable **SecureScan**.
3. Uninstall the plugin.

Before uninstalling in a production environment, review the plugin's configuration and audit requirements for your organization's retention policy.

---

## Security considerations

SecureScan is designed around several security principles:

### Exactly one active engine

ClamAV and VirusTotal are alternatives, not layers that run together. The configuration selector stores one active mode. If both underlying flags are found enabled, SecureScan treats the state as a conflict and rejects uploads until an administrator resolves it.

### No arbitrary shell syntax

The ClamAV command is not treated as unrestricted shell input. Dangerous shell constructs are rejected during command validation. The scanner executable is restricted to `clamdscan` or `clamscan`, and quarantine/action options that could persist infected files outside GLPI's rejected temporary upload are rejected.

### Temporary-file scanning

The file is scanned while temporary, before normal document storage. This is the core security boundary of the plugin.

### Fail closed

An antivirus execution failure is not interpreted as a clean file. A file that cannot be positively validated is rejected. VirusTotal pending, suspicious, missing, or unavailable reports are not treated as clean.

### Explicit engine test

The administrator must successfully test the currently selected engine before relying on it. Changing the ClamAV command invalidates its previous successful test.

### Encrypted VirusTotal API key

The VirusTotal API key is stored through GLPI's secure configuration mechanism and encrypted with the GLPI instance security key. The plaintext is not rendered back into the configuration form or written to audit records.

### Private asynchronous VirusTotal files

When VirusTotal analysis is pending, SecureScan keeps a private protected copy under `GLPI_PLUGIN_DOC_DIR/securescan/virustotal-jobs`. Jobs are bound to the logged-in GLPI user, the copied file is checked against its SHA-256, and job files are removed after completion or expiry (24 hours). The web server must not expose the GLPI plugin document directory.

### VirusTotal privacy and license restrictions

VirusTotal files and queried indicators may be shared with its security community. The Public/Community API has usage restrictions and must not be used for commercial business workflows. Use a suitable Premium agreement for corporate production and never submit confidential, personal, customer, employee, or business-sensitive documents through the Public/Community API.

### No file contents in audit records

The audit information identifies the file through metadata such as size and SHA-256 rather than writing file contents into the log. VirusTotal raw API payloads and API keys are not persisted as diagnostics.

### CSRF protection

Administrative POST operations use GLPI's native CSRF protection and authorization mechanisms.

### Native GLPI architecture

SecureScan integrates with GLPI's current plugin/controller architecture rather than requiring modifications to GLPI core files.

### Defense in depth

SecureScan should be deployed together with:

- current GLPI security updates;
- current PHP and operating-system security updates;
- restrictive filesystem permissions;
- a correctly configured ClamAV service or a suitable VirusTotal agreement;
- HTTPS;
- least-privilege service accounts;
- appropriate backups and monitoring;
- GLPI's own authentication and authorization controls.

## Production deployment checklist

Before enabling SecureScan in production:

- [ ] Confirm GLPI is 11.0.7+ or a supported GLPI 12.x release and PHP is 8.2 or newer.
- [ ] Select exactly one engine. Do not enable ClamAV and VirusTotal together.
- [ ] Confirm the selected engine passes **Test selected engine**.
- [ ] For ClamAV, install and start ClamAV on the GLPI server.
- [ ] For `clamdscan`, set `AlertExceedsMax yes` in `clamd.conf` and restart/reload `clamd`.
- [ ] For `clamscan`, confirm SecureScan's automatic `--alert-exceeds-max=yes` behavior is active.
- [ ] Confirm the web/PHP account can execute the scanner and access GLPI's temporary upload files.
- [ ] Confirm the configured ClamAV command uses exactly one `{file}` placeholder and works independently.
- [ ] For VirusTotal, store a valid API key and verify outbound HTTPS connectivity.
- [ ] Review the VirusTotal agreement, Public/Community limits, data sharing, and commercial-use restrictions.
- [ ] Keep automatic unknown-file submission disabled unless the organization's data policy explicitly permits it.
- [ ] If automatic submission is enabled, confirm that users understand that unknown files up to 32 MB may be submitted to VirusTotal.
- [ ] Confirm the private plugin document directory is not web-accessible and is writable by GLPI.
- [ ] Upload a normal PDF/document and confirm that a completed clean result allows storage.
- [ ] In a controlled environment, upload the EICAR test file with ClamAV selected and confirm it is rejected.
- [ ] Confirm an infected or suspicious result is not stored as a GLPI document.
- [ ] Confirm pending VirusTotal analyses are not stored until a completed clean result is available.
- [ ] Confirm audit records show expected engine, status, verdict, and evidence without exposing keys or file contents.
- [ ] Monitor PHP and GLPI logs for scanner or API errors.
- [ ] Review the production retention policy for security logs and backups.

## Troubleshooting

### "The antivirus test failed" (ClamAV)

Check:

1. The scanner executable exists and resolves to `clamdscan` or `clamscan`.
2. The PHP/web-server account has permission to execute it.
3. The antivirus daemon/service is running when required.
4. The configured command contains exactly one `{file}` placeholder.
5. The command does not contain rejected shell syntax or blocked ClamAV quarantine/action options.
6. The same command works against a harmless temporary file from the server account.
7. For `clamdscan`, `AlertExceedsMax yes` is set in `clamd.conf` and the daemon has been restarted/reloaded.
8. The nested ZIP limit probe returns the expected `Heuristics.Limits.Exceeded` result.

### VirusTotal connection test failed

Check:

1. The API key is correct and belongs to an account with the expected API access.
2. The GLPI instance security key is available so GLPI can decrypt the saved API key.
3. The server can establish outbound HTTPS connections to VirusTotal.
4. DNS, proxy, firewall, TLS certificate, and host-level network restrictions are correct.
5. The API key has not exceeded its quota or been revoked.

Do not copy the API key into GLPI logs, support tickets, or screenshots.

### VirusTotal reports "not found"

A hash lookup did not return an existing file report. By default, SecureScan does **not** submit unknown files automatically. The upload is therefore not approved. Enable **Submit unknown files to VirusTotal automatically** only when the organization's privacy, licensing, and data-handling policy permits sample submission.

### VirusTotal analysis remains pending

A pending analysis is not a clean verdict. SecureScan keeps the file in its private job storage and checks again according to the API response, local rate limiter, and any upstream `Retry-After` value. Verify the server can reach VirusTotal and that the request quota is available. The document is not stored until a completed clean result is available.

### VirusTotal reports an unavailable, suspicious, or infected result

These results are intentionally not approved. Check the VirusTotal report and API response using the report link provided in the interface or audit record. Do not bypass the fail-closed behavior to force the upload.

### "More than one engine is enabled"

The saved configuration contains both ClamAV and VirusTotal flags. Open **Setup → General → Configuration → SecureScan**, choose exactly one engine (or Disabled), and save. Uploads remain blocked while the conflict is unresolved.

### Files are rejected with an execution error

This normally indicates that SecureScan could not obtain a valid antivirus result. For ClamAV, check the scanner binary, daemon/socket availability, filesystem permissions, scan-limit configuration, and server logs. For VirusTotal, check API credentials, HTTPS connectivity, quota, and private job storage.

Do **not** disable the protection simply to make uploads work. The fail-closed behavior is intentional.

### A clean file is accepted but no `document_stored` entry appears

Verify that the normal GLPI document transaction completed successfully after the antivirus stage. A clean scan proves that the file passed the scanner; it does not by itself prove that GLPI subsequently stored the document.

### EICAR is rejected

This is the expected result when **ClamAV** is selected. A rejected EICAR upload confirms that the local detection-to-rejection path is operating correctly.

## Compatibility

The SecureScan 2.0.0 package metadata declares:

- **GLPI 11.x (11.0.7+)**
- **GLPI 12.x**
- **PHP ≥ 8.2**
- **SecureScan 2.0.0**

CI validation covers PHP 8.2, 8.3, 8.4, 8.5, and 8.6. Runtime compatibility is maintained against the GLPI APIs and plugin architecture targeted by the release.

## Development

Repository:

**https://github.com/monta990/securescan**

The project is developed as a standalone GLPI plugin and should not require modifications to GLPI core files.

### Portable CLI regression tests

Run the portable CLI test runner using the PHP runtime matching the intended matrix entry:

```bash
bash tools/run-cli-tests.sh 8.4
```

The CLI validation checks PHP syntax, runtime requirements, PSR-4 mappings, release metadata, XML structure, PO/MO synchronization, and the standalone PHP regression suites. GitHub Actions runs the supported PHP matrix (8.2, 8.3, 8.4, 8.5, and 8.6), JavaScript syntax checks, and the installable ZIP packaging checks.

### Build the installable ZIP

```bash
bash scripts/package.sh ./dist
```

The package script uses an explicit allowlist and excludes tests, CI workflows, development tools, and this handoff document.

### Security regression coverage

When contributing changes that affect file handling, antivirus execution, command validation, VirusTotal API requests, asynchronous jobs, routing, authorization, or configuration persistence, regression testing should cover both the **clean** and **rejected** paths.

At minimum, changes affecting the security boundary should verify:

1. clean file → accepted only after completed clean evidence;
2. infected file → rejected;
3. VirusTotal suspicious result → rejected;
4. ClamAV scan limit / skipped file → rejected as `not_scanned`;
5. scanner/API failure → rejected or remains pending only when safely retryable;
6. invalid command or API key → rejected;
7. selected engine test → successful only with valid current settings;
8. two enabled engines → conflict and fail-closed behavior;
9. VirusTotal pending job → bound to the user and SHA-256 verified;
10. audit record → correct status and evidence without secrets;
11. no infected or suspicious document → stored in GLPI.

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
