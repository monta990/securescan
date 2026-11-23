<?php

namespace GlpiPlugin\Securescan;

/**
 * SecureScan audit logging.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */
final class Audit
{
    /**
     * Record a scan without storing file contents or sensitive command output.
     */
    public static function record(string $type, array $result, string $file, ?object $item = null): void
    {
        $record = [
            'time'           => date('c'),
            'type'           => $type,
            'status'         => $result['status'] ?? ($result['ok'] ? 'clean' : 'error'),
            'scan_verdict'   => $result['scan_verdict'] ?? null,
            'scan_evidence'  => $result['scan_evidence'] ?? null,
            'exit_code'      => $result['exit_code'] ?? null,
            'size'           => is_file($file) ? filesize($file) : null,
            'sha256'         => is_file($file) ? hash_file('sha256', $file) : null,
            'temporary'      => is_file($file) ? basename($file) : null,
            'itemtype'       => $item !== null ? $item::class : null,
            'items_id'       => self::getItemId($item),
            'user_id'        => class_exists('Session') ? (int) \Session::getLoginUserID() : 0,
            'providers'      => self::normalizeProviders($result['providers'] ?? []),
        ];

        self::write($record);
    }


    /**
     * Record sanitized timing diagnostics for VirusTotal preflight operations.
     * No filenames, API keys, raw API bodies or analysis identifiers are stored.
     *
     * @param array<string, mixed> $timings
     */
    public static function recordPerformance(
        string $stage,
        string $status,
        string $sha256,
        ?int $size,
        array $timings,
        int $pollCount = 0,
        ?int $elapsedMs = null,
        ?int $userId = null
    ): void {
        $allowed = [
            'hash_ms',
            'report_lookup_ms',
            'report_connect_ms',
            'report_tls_ms',
            'report_first_byte_ms',
            'sample_upload_ms',
            'sample_upload_connect_ms',
            'sample_upload_tls_ms',
            'sample_upload_first_byte_ms',
            'analysis_poll_ms',
            'analysis_poll_ms_total',
            'analysis_connect_ms',
            'analysis_tls_ms',
            'analysis_first_byte_ms',
            'connect_ms',
            'tls_ms',
            'first_byte_ms',
            'quarantine_copy_ms',
            'quarantine_hash_ms',
            'staged_restore_ms',
            'controller_ms',
        ];
        $safeTimings = [];
        foreach ($allowed as $key) {
            if (isset($timings[$key]) && is_numeric($timings[$key])) {
                $safeTimings[$key] = max(0, min(3600000, (int) $timings[$key]));
            }
        }

        $record = [
            'time' => date('c'),
            'type' => 'performance',
            'stage' => substr($stage, 0, 40),
            'status' => substr($status, 0, 24),
            'sha256' => preg_match('/^[a-f0-9]{64}$/D', $sha256) === 1 ? $sha256 : null,
            'size' => $size !== null ? max(0, $size) : null,
            'user_id' => $userId ?? (class_exists('Session') ? (int) \Session::getLoginUserID() : 0),
            'poll_count' => max(0, min(10000, $pollCount)),
            'elapsed_ms' => $elapsedMs !== null ? max(0, min(86400000, $elapsedMs)) : null,
            'timings' => $safeTimings,
        ];
        self::write($record);
    }

    /**
     * Record preflight failures that happen before a readable staged file exists.
     * The original filename is not logged; only a one-way fingerprint is kept.
     */
    public static function recordPreflightFailure(string $evidence, string $source, string $filename): void
    {
        $record = [
            'time' => date('c'),
            'type' => 'document_preflight',
            'status' => 'error',
            'scan_verdict' => 'unknown',
            'scan_evidence' => substr($evidence, 0, 64),
            'exit_code' => null,
            'size' => null,
            'sha256' => null,
            'temporary' => null,
            'itemtype' => 'Document',
            'items_id' => 0,
            'user_id' => class_exists('Session') ? (int) \Session::getLoginUserID() : 0,
            'providers' => [],
            'source' => in_array($source, ['tmp', 'upload'], true) ? $source : 'unknown',
            'staged_name_fingerprint' => hash('sha256', $filename),
        ];

        self::write($record);
    }

    /**
     * Record the successful persistence of a scanned document.
     * This is intentionally separate from the pre-add/pre-update scan record
     * because GLPI does not assign the final item ID until after the pre hook.
     */
    public static function recordStored(
        string $type,
        string $status,
        string $scanVerdict,
        string $scanEvidence,
        ?int $exitCode,
        ?int $size,
        ?string $sha256,
        ?object $item = null,
        array $providers = []
    ): void {
        $record = [
            'time'           => date('c'),
            'type'           => $type,
            'status'         => $status,
            'scan_verdict'   => $scanVerdict,
            'scan_evidence'  => $scanEvidence,
            'exit_code'      => $exitCode,
            'size'           => $size,
            'sha256'         => $sha256,
            'temporary'      => null,
            'itemtype'       => $item !== null ? $item::class : null,
            'items_id'       => self::getItemId($item),
            'user_id'        => class_exists('Session') ? (int) \Session::getLoginUserID() : 0,
            'providers'      => self::normalizeProviders($providers),
        ];

        self::write($record);
        self::writeDocumentHistory($status, $sha256, $item, $providers);
    }

    /**
     * Add the successful scan result to the native GLPI history of the
     * document. This keeps the audit visible from the document's
     * History tab while the detailed JSON evidence remains in
     * files/_log/securescan.log.
     */
    private static function writeDocumentHistory(
        string $status,
        ?string $sha256,
        ?object $item,
        array $providers = []
    ): void {
        if ($item === null || !method_exists($item, 'getID')) {
            return;
        }

        $itemsId = (int) $item->getID();
        if ($itemsId <= 0) {
            return;
        }

        $reportUrl = $providers['virustotal']['report_url'] ?? null;
        $expectedUrl = VirusTotal::getFileReportUrl((string) ($sha256 ?? ''));
        if ($status === 'clean' && $expectedUrl !== null && is_string($reportUrl)
            && hash_equals($expectedUrl, $reportUrl)
        ) {
            // Use GLPI's plugin-history callback so the external URL is rendered
            // as a validated, clickable link instead of escaped plain text.
            try {
                $historyId = \Log::history(
                    $itemsId,
                    $item::class,
                    [0, (string) $sha256, $expectedUrl],
                    self::class,
                    \Log::HISTORY_PLUGIN
                );
                if ($historyId !== false) {
                    return;
                }
            } catch (\Throwable $e) {
                \Toolbox::logDebug($e);
                // Fall back to the ordinary text history message below.
            }
        }

        $message = $status === 'clean'
            ? sprintf(
                __('SecureScan: file scanned successfully and stored. Result: clean. SHA-256: %s', 'securescan'),
                $sha256 ?? 'N/A'
            )
            : sprintf(
                __('SecureScan: file scanned and stored. Result: %s. SHA-256: %s', 'securescan'),
                $status,
                $sha256 ?? 'N/A'
            );

        // GLPI's native history API uses search option 0 plus the
        // HISTORY_LOG_SIMPLE_MESSAGE action for free-form audit messages.
        try {
            \Log::history(
                $itemsId,
                $item::class,
                [0, '', $message],
                0,
                \Log::HISTORY_LOG_SIMPLE_MESSAGE
            );
        } catch (\Throwable $e) {
            // A history-entry failure must never invalidate an already
            // stored clean document. The detailed SecureScan log remains
            // the fallback evidence.
            \Toolbox::logDebug($e);
        }
    }

    /**
     * Provide the plugin history label for GLPI's native Log renderer.
     */
    public static function getTypeName($nb = 0): string
    {
        return __('SecureScan', 'securescan');
    }

    /**
     * Render one validated VirusTotal report link in GLPI's native history.
     * Only the SHA-256 and the exact URL derived from that hash are accepted.
     *
     * @param array<string, mixed> $data GLPI log row
     */
    public static function getHistoryEntry(array $data): string
    {
        $sha256 = (string) ($data['old_value'] ?? '');
        $reportUrl = (string) ($data['new_value'] ?? '');
        $expectedUrl = VirusTotal::getFileReportUrl($sha256);
        if ($expectedUrl === null || !hash_equals($expectedUrl, $reportUrl)) {
            return '';
        }

        $message = sprintf(
            __('SecureScan: file scanned successfully and stored. Result: clean. SHA-256: %s', 'securescan'),
            $sha256
        );
        $linkLabel = __('View VirusTotal analysis', 'securescan');
        $escape = static fn(string $value): string => htmlspecialchars(
            $value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        return $escape($message)
            . ' <a href="' . $escape($expectedUrl)
            . '" target="_blank" rel="noopener noreferrer">'
            . $escape($linkLabel)
            . '</a>';
    }

    private static function getItemId(?object $item): int
    {
        if ($item === null || !isset($item->fields['id'])) {
            return 0;
        }

        return (int) $item->fields['id'];
    }

    /**
     * Keep only normalized, non-secret provider evidence in the audit log.
     */
    private static function normalizeProviders(mixed $providers): array
    {
        if (!is_array($providers)) {
            return [];
        }

        $normalized = [];
        foreach ($providers as $name => $result) {
            if (!is_string($name) || !is_array($result)) {
                continue;
            }
            $normalized[$name] = [
                'status' => isset($result['status']) ? substr((string) $result['status'], 0, 32) : 'unknown',
                'evidence' => isset($result['evidence']) ? substr((string) $result['evidence'], 0, 64) : 'unknown',
                'malicious' => max(0, (int) ($result['malicious'] ?? 0)),
                'suspicious' => max(0, (int) ($result['suspicious'] ?? 0)),
                'total' => max(0, (int) ($result['total'] ?? 0)),
            ];
            if (isset($result['analysis_id']) && is_string($result['analysis_id'])) {
                $normalized[$name]['analysis_id'] = substr($result['analysis_id'], 0, 512);
            }
            if ($name === 'virustotal' && isset($result['report_url']) && is_string($result['report_url'])) {
                $url = $result['report_url'];
                if (preg_match('~^https://www\.virustotal\.com/gui/file/[a-f0-9]{64}/detection$~D', $url) === 1) {
                    $normalized[$name]['report_url'] = $url;
                }
            }
        }

        return $normalized;
    }

    private static function write(array $record): void
    {
        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json !== false) {
            \Toolbox::logInFile('securescan', $json . PHP_EOL, true);
        }
    }
}
