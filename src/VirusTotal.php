<?php

/**
 * SecureScan VirusTotal API v3 integration.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */

namespace GlpiPlugin\Securescan;

use CURLFile;
use Throwable;

/**
 * VirusTotal cloud antivirus provider.
 *
 * VirusTotal is an alternative to ClamAV, not a second simultaneous layer.
 * In VirusTotal mode only a completed clean report allows a document upload;
 * unknown, malicious, suspicious, pending, rate-limited or unavailable results
 * are rejected before GLPI stores the document.
 */
final class VirusTotal
{
    private const API_BASE = 'https://www.virustotal.com/api/v3';
    private const EMPTY_FILE_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    private const MAX_RESPONSE_BYTES = 1048576;
    private const MAX_UPLOAD_BYTES = 33554432;
    private const CONNECT_TIMEOUT = 4;
    private const REQUEST_TIMEOUT = 12;
    private const UPLOAD_TIMEOUT = 30;
    private const ANALYSIS_REQUEST_TIMEOUT = 8;
    private const ANALYSIS_POLL_MIN_INTERVAL_SECONDS = 15;
    private const PENDING_ANALYSIS_TTL = 86400;
    private const REQUESTS_PER_MINUTE = 4;
    private const REQUESTS_PER_DAY = 500;

    /**
     * Query the VirusTotal report for an uploaded file and, optionally, submit
     * an unknown sample. File uploads are disabled by default in configuration.
     *
     * @return array{
     *   status: string,
     *   sha256: string,
     *   malicious: int,
     *   suspicious: int,
     *   total: int,
     *   analysis_id?: string,
     *   http_status?: int,
     *   evidence: string
     * }
     */
    public static function scanFile(string $file, bool $submitUnknown = false): array
    {
        $empty = [
            'status'     => 'unavailable',
            'sha256'     => '',
            'malicious'  => 0,
            'suspicious' => 0,
            'total'      => 0,
            'evidence'   => 'not_configured',
        ];

        $apiKey = Config::getVirusTotalApiKey();
        if ($apiKey === '') {
            return $empty;
        }

        if (!is_file($file) || !is_readable($file)) {
            $empty['evidence'] = 'file_unavailable';
            return $empty;
        }

        $hashStarted = microtime(true);
        $sha256 = hash_file('sha256', $file);
        $timings = [
            'hash_ms' => (int) round((microtime(true) - $hashStarted) * 1000),
        ];
        if (!is_string($sha256) || preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            $empty['evidence'] = 'hash_failed';
            $empty['timings'] = $timings;
            return $empty;
        }

        // A browser preflight has already received a completed result. The cache
        // is keyed by file hash and API-key fingerprint, so the normal GLPI
        // pre-storage hook can approve the same file without another VT request.
        $cached = self::readApprovedScan($sha256, $apiKey);
        if ($cached !== null) {
            $cached['timings'] = array_merge($timings, ['approved_cache_hit' => 1]);
            return $cached;
        }

        // Reuse a known analysis before asking for a file report. This avoids
        // spending a normal file-report lookup for every retry and, importantly,
        // lets a direct GLPI retry complete as soon as the existing analysis ends.
        $analysisId = self::readPendingAnalysisId($sha256);
        if ($analysisId !== null) {
            $pending = self::pollAnalysis($sha256, $analysisId);
            $pending['timings'] = array_merge($timings, $pending['timings'] ?? []);
            return $pending;
        }

        $response = self::request('GET', '/files/' . $sha256, $apiKey);
        $timings['report_lookup_ms'] = max(0, (int) ($response['duration_ms'] ?? 0));
        $timings['report_connect_ms'] = max(0, (int) ($response['connect_ms'] ?? 0));
        $timings['report_tls_ms'] = max(0, (int) ($response['tls_ms'] ?? 0));
        $timings['report_first_byte_ms'] = max(0, (int) ($response['first_byte_ms'] ?? 0));
        $result = self::mapReportResponse($response, $sha256);
        $result['timings'] = $timings;
        $reportStatus = (string) ($result['status'] ?? 'unavailable');

        if (in_array($reportStatus, ['clean', 'infected', 'suspicious'], true)) {
            self::storeApprovedScan($result, $apiKey);
            self::clearPendingAnalysisId($sha256);
            return self::withReportUrl($result);
        }

        // Never occupy a PHP worker waiting for VirusTotal. A new submission
        // returns a pending ID; the browser preflight polls it through short,
        // independent HTTP requests. Non-JavaScript/API uploads fail closed.
        if ($reportStatus !== 'not_found' || !$submitUnknown) {
            return self::withReportUrl($result);
        }

        $fileSize = filesize($file);
        if (!is_int($fileSize) || $fileSize < 0 || $fileSize > self::MAX_UPLOAD_BYTES) {
            $result['status'] = 'not_found';
            $result['evidence'] = 'not_found_upload_skipped_size';
            return self::withReportUrl($result);
        }

        // POST /files only starts the remote scan. It does not wait for the
        // analysis to finish and does not hold the GLPI pre-storage request.
        $uploadResponse = self::request('POST', '/files', $apiKey, $file);
        $timings['sample_upload_ms'] = max(0, (int) ($uploadResponse['duration_ms'] ?? 0));
        $timings['sample_upload_connect_ms'] = max(0, (int) ($uploadResponse['connect_ms'] ?? 0));
        $timings['sample_upload_tls_ms'] = max(0, (int) ($uploadResponse['tls_ms'] ?? 0));
        $timings['sample_upload_first_byte_ms'] = max(0, (int) ($uploadResponse['first_byte_ms'] ?? 0));
        $result['timings'] = $timings;
        if (!in_array((int) ($uploadResponse['http_status'] ?? 0), [200, 201], true)) {
            $result['status'] = 'unavailable';
            $result['http_status'] = (int) ($uploadResponse['http_status'] ?? 0);
            $result['evidence'] = self::responseEvidence($uploadResponse, 'upload_failed');
            return self::withReportUrl($result);
        }

        $payload = self::decodePayload((string) ($uploadResponse['body'] ?? ''));
        $analysisId = $payload['data']['id'] ?? null;
        if (!is_string($analysisId)
            || preg_match('/^[A-Za-z0-9._:=+\/\-]{1,512}$/D', $analysisId) !== 1
        ) {
            $result['status'] = 'unavailable';
            $result['evidence'] = 'invalid_upload_response';
            return self::withReportUrl($result);
        }

        self::storePendingAnalysisId($sha256, $analysisId);

        return self::withReportUrl(array_merge($result, [
            'status' => 'pending',
            'evidence' => 'sample_submitted_analysis_pending',
            'analysis_id' => $analysisId,
            'timings' => $timings,
        ]));
    }

    /**
     * Read only a completed preflight approval for the GLPI pre-storage hook.
     * This method deliberately performs no network request: the core GLPI upload
     * path must never occupy a PHP worker waiting for VirusTotal.
     *
     * @return array<string, mixed>
     */
    public static function getApprovedScan(string $file): array
    {
        $result = [
            'status' => 'unavailable',
            'sha256' => '',
            'malicious' => 0,
            'suspicious' => 0,
            'total' => 0,
            'evidence' => 'browser_preflight_required',
        ];
        $apiKey = Config::getVirusTotalApiKey();
        if ($apiKey === '') {
            $result['evidence'] = 'not_configured';
            return $result;
        }
        if (!is_file($file) || !is_readable($file)) {
            $result['evidence'] = 'file_unavailable';
            return $result;
        }
        $sha256 = hash_file('sha256', $file);
        if (!is_string($sha256) || preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            $result['evidence'] = 'hash_failed';
            return $result;
        }
        $result['sha256'] = $sha256;

        $approved = self::readApprovedScan($sha256, $apiKey);
        if ($approved !== null) {
            return $approved;
        }

        $analysisId = self::readPendingAnalysisId($sha256);
        if ($analysisId !== null) {
            $result['status'] = 'pending';
            $result['evidence'] = 'browser_preflight_required_analysis_pending';
            $result['analysis_id'] = $analysisId;
            return self::withReportUrl($result);
        }

        return self::withReportUrl($result);
    }

    /**
     * Check one analysis resource without sleeping. This is called by a short
     * authenticated AJAX request, so no PHP worker stays occupied between polls.
     *
     * @return array<string, mixed>
     */
    public static function pollAnalysis(string $sha256, string $analysisId): array
    {
        $sha256 = strtolower(trim($sha256));
        if (preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1
            || preg_match('/^[A-Za-z0-9._:=+\/\-]{1,512}$/D', $analysisId) !== 1
        ) {
            return self::withReportUrl(self::unavailableAnalysis('invalid_analysis_reference'));
        }

        $apiKey = Config::getVirusTotalApiKey();
        if ($apiKey === '') {
            return self::withReportUrl(self::baseResult($sha256, 'unavailable', 'not_configured'));
        }

        $storedAnalysisId = self::readPendingAnalysisId($sha256);
        if ($storedAnalysisId === null || !hash_equals($storedAnalysisId, $analysisId)) {
            return self::withReportUrl(self::baseResult($sha256, 'unavailable', 'analysis_reference_expired'));
        }

        $response = self::request('GET', '/analyses/' . rawurlencode($analysisId), $apiKey, null, self::ANALYSIS_REQUEST_TIMEOUT);
        $httpStatus = (int) ($response['http_status'] ?? 0);

        if ($httpStatus === 200) {
            $payload = self::decodePayload((string) ($response['body'] ?? ''));
            if ($payload === null) {
                return self::withReportUrl(array_merge(self::baseResult($sha256, 'pending', 'analysis_invalid_json'), [
                    'analysis_id' => $analysisId,
                    'timings' => [
                        'analysis_poll_ms' => max(0, (int) ($response['duration_ms'] ?? 0)),
                        'analysis_connect_ms' => max(0, (int) ($response['connect_ms'] ?? 0)),
                        'analysis_tls_ms' => max(0, (int) ($response['tls_ms'] ?? 0)),
                        'analysis_first_byte_ms' => max(0, (int) ($response['first_byte_ms'] ?? 0)),
                    ],
                ]));
            }

            $normalized = self::normalizeAnalysis($payload);
            $result = array_merge($normalized, [
                'sha256' => $sha256,
                'analysis_id' => $analysisId,
                'http_status' => $httpStatus,
                'timings' => [
                    'analysis_poll_ms' => max(0, (int) ($response['duration_ms'] ?? 0)),
                    'analysis_connect_ms' => max(0, (int) ($response['connect_ms'] ?? 0)),
                    'analysis_tls_ms' => max(0, (int) ($response['tls_ms'] ?? 0)),
                    'analysis_first_byte_ms' => max(0, (int) ($response['first_byte_ms'] ?? 0)),
                ],
            ]);

            if ($normalized['status'] !== 'pending') {
                // The controller first persists the terminal result in its job
                // record, then calls completePendingAnalysis(). Keeping this
                // reference until that succeeds makes interrupted status requests
                // safely retryable.
                self::storeApprovedScan($result, $apiKey);
            }

            return self::withReportUrl($result);
        }

        if ($httpStatus === 400) {
            $errorPayload = self::decodePayload((string) ($response['body'] ?? ''));
            $errorCode = is_array($errorPayload) ? (string) ($errorPayload['error']['code'] ?? '') : '';
            if ($errorCode === 'NotAvailableYet') {
                return self::withReportUrl(array_merge(self::baseResult($sha256, 'pending', 'analysis_not_available_yet', $httpStatus), [
                    'analysis_id' => $analysisId,
                    'retry_after' => self::ANALYSIS_POLL_MIN_INTERVAL_SECONDS,
                    'timings' => [
                        'analysis_poll_ms' => max(0, (int) ($response['duration_ms'] ?? 0)),
                        'analysis_connect_ms' => max(0, (int) ($response['connect_ms'] ?? 0)),
                        'analysis_tls_ms' => max(0, (int) ($response['tls_ms'] ?? 0)),
                        'analysis_first_byte_ms' => max(0, (int) ($response['first_byte_ms'] ?? 0)),
                    ],
                ]));
            }
        }

        // The Analysis endpoint for a submitted sample can be queried without
        // consuming the Public API's normal file-report quota. Keep transient
        // responses retryable; never interpret them as a completed clean scan.
        $evidence = self::responseEvidence($response, 'analysis_request_failed');
        if ($httpStatus === 404 || $httpStatus === 429 || $httpStatus >= 500 || $httpStatus === 0) {
            $retryAfter = $httpStatus === 429
                ? max(1, (int) ($response['retry_after'] ?? 30))
                : self::ANALYSIS_POLL_MIN_INTERVAL_SECONDS;
            return self::withReportUrl(array_merge(self::baseResult($sha256, 'pending', $evidence, $httpStatus), [
                'analysis_id' => $analysisId,
                'retry_after' => $retryAfter,
                'timings' => [
                        'analysis_poll_ms' => max(0, (int) ($response['duration_ms'] ?? 0)),
                        'analysis_connect_ms' => max(0, (int) ($response['connect_ms'] ?? 0)),
                        'analysis_tls_ms' => max(0, (int) ($response['tls_ms'] ?? 0)),
                        'analysis_first_byte_ms' => max(0, (int) ($response['first_byte_ms'] ?? 0)),
                    ],
            ]));
        }

        return self::withReportUrl(array_merge(self::baseResult($sha256, 'unavailable', $evidence, $httpStatus), [
            'analysis_id' => $analysisId,
            'timings' => [
                        'analysis_poll_ms' => max(0, (int) ($response['duration_ms'] ?? 0)),
                        'analysis_connect_ms' => max(0, (int) ($response['connect_ms'] ?? 0)),
                        'analysis_tls_ms' => max(0, (int) ($response['tls_ms'] ?? 0)),
                        'analysis_first_byte_ms' => max(0, (int) ($response['first_byte_ms'] ?? 0)),
                    ],
        ]));
    }

    /**
     * Clear the pending analysis reference only after the browser job has
     * persisted the terminal result or a terminal rejection.
     */
    public static function completePendingAnalysis(string $sha256): void
    {
        self::clearPendingAnalysisId(strtolower(trim($sha256)));
    }

    /**
     * Check that a supplied API key can access the public file-report endpoint.
     * A 404 for the known empty-file hash is considered authenticated: it means
     * the API accepted the key but has no report for that hash.
     *
     * @return array{ok: bool, message: string, http_status?: int}
     */
    public static function testConnection(string $apiKey): array
    {
        $apiKey = trim($apiKey);
        if (!self::isValidApiKeyShape($apiKey)) {
            return [
                'ok'      => false,
                'message' => __s('Enter a valid-looking VirusTotal API key before testing the connection.', 'securescan'),
            ];
        }

        $response = self::request('GET', '/files/' . self::EMPTY_FILE_SHA256, $apiKey);
        $status = (int) ($response['http_status'] ?? 0);

        if (($response['error'] ?? '') === 'curl_unavailable') {
            return [
                'ok' => false,
                'http_status' => 0,
                'message' => __s('The PHP cURL extension is required for VirusTotal API requests.', 'securescan'),
            ];
        }

        if ($status === 200 || $status === 404) {
            return [
                'ok'          => true,
                'http_status' => $status,
                'message'     => __s('VirusTotal accepted the API key and the connection test succeeded.', 'securescan'),
            ];
        }

        if ($status === 401 || $status === 403) {
            return [
                'ok'          => false,
                'http_status' => $status,
                'message'     => __s('VirusTotal rejected the API key. Check the key and its API permissions.', 'securescan'),
            ];
        }

        if ($status === 429) {
            return [
                'ok'          => false,
                'http_status' => $status,
                'message'     => __s('VirusTotal rate limit reached. Wait before testing again; the API key was not verified.', 'securescan'),
            ];
        }

        return [
            'ok'          => false,
            'http_status' => $status,
            'message'     => __s('VirusTotal connection could not be verified. Check outbound HTTPS connectivity and the API response.', 'securescan'),
        ];
    }

    /**
     * Normalize a VirusTotal v3 file report into SecureScan verdicts.
     * Public for deterministic tests; raw API data is never written to logs.
     *
     * @return array{status: string, malicious: int, suspicious: int, total: int, evidence: string}
     */
    public static function normalizeReport(array $payload): array
    {
        $stats = $payload['data']['attributes']['last_analysis_stats'] ?? null;
        return self::normalizeStatistics($stats, 'report_stats_missing');
    }

    /**
     * Normalize a VirusTotal analysis object. Only a completed analysis with
     * positive harmless/undetected evidence can be approved.
     *
     * @return array{status: string, malicious: int, suspicious: int, total: int, evidence: string}
     */
    public static function normalizeAnalysis(array $payload): array
    {
        $attributes = $payload['data']['attributes'] ?? null;
        if (!is_array($attributes)) {
            return self::unavailableAnalysis('analysis_attributes_missing');
        }

        $analysisStatus = strtolower((string) ($attributes['status'] ?? ''));
        if ($analysisStatus !== 'completed') {
            if (in_array($analysisStatus, ['failed', 'aborted'], true)) {
                return self::unavailableAnalysis('analysis_' . $analysisStatus);
            }

            if (!in_array($analysisStatus, ['queued', 'in-progress'], true)) {
                return self::unavailableAnalysis('analysis_unknown_status');
            }

            return [
                'status' => 'pending',
                'malicious' => 0,
                'suspicious' => 0,
                'total' => 0,
                'evidence' => 'analysis_' . str_replace('-', '_', $analysisStatus),
            ];
        }

        return self::normalizeStatistics($attributes['stats'] ?? null, 'analysis_stats_missing');
    }

    /** @return array{status: string, malicious: int, suspicious: int, total: int, evidence: string} */
    private static function normalizeStatistics(mixed $stats, string $missingEvidence): array
    {
        if (!is_array($stats)) {
            return [
                'status' => 'unavailable',
                'malicious' => 0,
                'suspicious' => 0,
                'total' => 0,
                'evidence' => $missingEvidence,
            ];
        }

        $malicious = self::safeCount($stats['malicious'] ?? 0);
        $suspicious = self::safeCount($stats['suspicious'] ?? 0);
        $total = 0;
        foreach ($stats as $count) {
            $total += self::safeCount($count);
        }

        if ($malicious > 0) {
            return [
                'status' => 'infected',
                'malicious' => $malicious,
                'suspicious' => $suspicious,
                'total' => $total,
                'evidence' => 'malicious_detections',
            ];
        }

        if ($suspicious > 0) {
            return [
                'status' => 'suspicious',
                'malicious' => 0,
                'suspicious' => $suspicious,
                'total' => $total,
                'evidence' => 'suspicious_detections',
            ];
        }

        $confirmedClean = self::safeCount($stats['harmless'] ?? 0)
            + self::safeCount($stats['undetected'] ?? 0);
        if ($confirmedClean > 0) {
            return [
                'status' => 'clean',
                'malicious' => 0,
                'suspicious' => 0,
                'total' => $total,
                'evidence' => 'harmless_or_undetected',
            ];
        }

        return [
            'status' => 'unavailable',
            'malicious' => 0,
            'suspicious' => 0,
            'total' => 0,
            'evidence' => 'empty_analysis_stats',
        ];
    }

    /** @return array{status: string, malicious: int, suspicious: int, total: int, evidence: string} */
    private static function unavailableAnalysis(string $evidence): array
    {
        return [
            'status' => 'unavailable',
            'malicious' => 0,
            'suspicious' => 0,
            'total' => 0,
            'evidence' => $evidence,
        ];
    }

    /** Add the safe GUI URL derived from a validated SHA-256 to every result. */
    private static function withReportUrl(array $result): array
    {
        $url = self::getFileReportUrl((string) ($result['sha256'] ?? ''));
        if ($url !== null) {
            $result['report_url'] = $url;
        }
        return $result;
    }

    private static function approvedScanPath(string $sha256, bool $createDirectory = false): ?string
    {
        if (!defined('GLPI_PLUGIN_DOC_DIR') || preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            return null;
        }
        $base = rtrim((string) GLPI_PLUGIN_DOC_DIR, '/\\') . DIRECTORY_SEPARATOR . 'securescan';
        $directory = $base . DIRECTORY_SEPARATOR . 'virustotal-approved';
        if (is_link($base) || is_link($directory)) {
            return null;
        }
        if (!is_dir($directory) && (!$createDirectory || (!@mkdir($directory, 0700, true) && !is_dir($directory))) {
            return null;
        }
        @chmod($base, 0700);
        @chmod($directory, 0700);
        return $directory . DIRECTORY_SEPARATOR . $sha256 . '.json';
    }

    private static function readApprovedScan(string $sha256, string $apiKey): ?array
    {
        $path = self::approvedScanPath($sha256);
        if ($path === null || is_link($path) || !is_file($path) || !is_readable($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        $record = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($record)
            || !isset($record['created_at'], $record['api_key_hash'], $record['result'])
            || !is_int($record['created_at'])
            || time() - $record['created_at'] > 900
            || !is_string($record['api_key_hash'])
            || !hash_equals(self::getTestedKeyHash($apiKey), $record['api_key_hash'])
            || !is_array($record['result'])
            || !in_array($record['result']['status'] ?? '', ['clean', 'infected', 'suspicious'], true)
            || !hash_equals($sha256, (string) ($record['result']['sha256'] ?? ''))
        ) {
            @unlink($path);
            return null;
        }
        return self::withReportUrl($record['result']);
    }

    private static function storeApprovedScan(array $result, string $apiKey): void
    {
        if (!in_array($result['status'] ?? '', ['clean', 'infected', 'suspicious'], true)) {
            return;
        }
        $sha256 = (string) ($result['sha256'] ?? '');
        $path = self::approvedScanPath($sha256, true);
        if ($path === null || is_link($path)) {
            return;
        }
        try {
            $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
            $json = json_encode([
                'created_at' => time(),
                'api_key_hash' => self::getTestedKeyHash($apiKey),
                'result' => $result,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (@file_put_contents($temporary, $json, LOCK_EX) === false) {
                return;
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $path)) {
                @unlink($temporary);
            }
        } catch (Throwable) {
            // Cache is an optimization only; a missed cache causes a fresh API lookup.
        }
    }

    private static function pendingAnalysisPath(string $sha256, bool $createDirectory = false): ?string
    {
        if (!defined('GLPI_PLUGIN_DOC_DIR') || preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            return null;
        }

        $baseDirectory = rtrim((string) GLPI_PLUGIN_DOC_DIR, '/\\') . DIRECTORY_SEPARATOR . 'securescan';
        $directory = $baseDirectory . DIRECTORY_SEPARATOR . 'virustotal-pending';
        if (is_link($baseDirectory) || is_link($directory)) {
            return null;
        }
        if (!is_dir($directory)) {
            if (!$createDirectory || (!@mkdir($directory, 0700, true) && !is_dir($directory))) {
                return null;
            }
        }
        @chmod($baseDirectory, 0700);
        @chmod($directory, 0700);
        return $directory . DIRECTORY_SEPARATOR . $sha256 . '.json';
    }

    private static function readPendingAnalysisId(string $sha256): ?string
    {
        $path = self::pendingAnalysisPath($sha256);
        if ($path === null || is_link($path) || !is_file($path) || !is_readable($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        $record = is_string($raw) ? json_decode($raw, true) : null;
        $created = is_array($record) ? (int) ($record['created_at'] ?? 0) : 0;
        $analysisId = is_array($record) ? ($record['analysis_id'] ?? null) : null;
        if ($created <= 0 || time() - $created > self::PENDING_ANALYSIS_TTL
            || !is_string($analysisId)
            || preg_match('/^[A-Za-z0-9._:=+\/\-]{1,512}$/D', $analysisId) !== 1
        ) {
            self::clearPendingAnalysisId($sha256);
            return null;
        }
        return $analysisId;
    }

    private static function storePendingAnalysisId(string $sha256, string $analysisId): void
    {
        $path = self::pendingAnalysisPath($sha256, true);
        if ($path === null || is_link($path)) {
            return;
        }

        try {
            $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
            $json = json_encode([
                'analysis_id' => $analysisId,
                'created_at' => time(),
            ], JSON_THROW_ON_ERROR);
            if (@file_put_contents($temporary, $json, LOCK_EX) === false) {
                return;
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $path)) {
                @unlink($temporary);
            }
        } catch (Throwable) {
            // The current request still polls its in-memory analysis ID.
        }
    }

    private static function clearPendingAnalysisId(string $sha256): void
    {
        $path = self::pendingAnalysisPath($sha256);
        if ($path !== null && !is_link($path) && is_file($path)) {
            @unlink($path);
        }
    }

    /**
     * Build VirusTotal's documented GUI link for the most recent file report.
     * The hash is validated and normalized before it is placed in the URL.
     */
    public static function getFileReportUrl(string $sha256): ?string
    {
        $sha256 = strtolower(trim($sha256));
        if (preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            return null;
        }

        return 'https://www.virustotal.com/gui/file/' . $sha256 . '/detection';
    }

    public static function getTestedKeyHash(string $apiKey): string
    {
        return hash('sha256', "virustotal-api-v3\n" . $apiKey);
    }

    public static function isValidApiKeyShape(string $apiKey): bool
    {
        return strlen($apiKey) >= 16
            && strlen($apiKey) <= 200
            && preg_match('/^[A-Za-z0-9_-]+$/D', $apiKey) === 1;
    }

    /**
     * @return array{status: string, sha256: string, malicious: int, suspicious: int, total: int, evidence: string, http_status?: int}
     */
    private static function mapReportResponse(array $response, string $sha256): array
    {
        $status = (int) ($response['http_status'] ?? 0);
        if ($status === 200) {
            $payload = self::decodePayload((string) ($response['body'] ?? ''));
            if ($payload === null) {
                return self::baseResult($sha256, 'unavailable', 'invalid_report_json', $status);
            }

            return array_merge(
                self::baseResult($sha256, 'unavailable', 'report_unparsed', $status),
                self::normalizeReport($payload)
            );
        }

        if ($status === 404) {
            return self::baseResult($sha256, 'not_found', 'hash_not_in_virustotal', $status);
        }

        return self::baseResult($sha256, 'unavailable', self::responseEvidence($response, 'api_request_failed'), $status);
    }

    /**
     * Execute one fixed-host HTTPS request. Redirects are disabled to prevent
     * forwarding the x-apikey header or an uploaded file to another host.
     *
     * @return array{http_status:int,body:string,error?:string,duration_ms?:int,connect_ms?:int,tls_ms?:int,first_byte_ms?:int,retry_after?:int}
     */
    private static function request(
        string $method,
        string $path,
        string $apiKey,
        ?string $file = null,
        ?int $timeout = null
    ): array {
        if (!extension_loaded('curl') || !function_exists('curl_init')) {
            return ['http_status' => 0, 'body' => '', 'error' => 'curl_unavailable'];
        }

        if (!in_array($method, ['GET', 'POST'], true) || !str_starts_with($path, '/')) {
            return ['http_status' => 0, 'body' => '', 'error' => 'invalid_request'];
        }

        $quotaExempt = ($method === 'POST' && $path === '/files')
            || ($method === 'GET' && str_starts_with($path, '/analyses/'));
        $requestAllowance = self::reserveApiRequest(!$quotaExempt);
        if (!$requestAllowance['allowed']) {
            return [
                'http_status' => 429,
                'body' => '',
                'error' => (string) ($requestAllowance['error'] ?? 'local_rate_limit'),
                'retry_after' => max(1, (int) ($requestAllowance['retry_after'] ?? 15)),
            ];
        }

        $url = self::API_BASE . $path;
        $curl = curl_init($url);
        if ($curl === false) {
            return ['http_status' => 0, 'body' => '', 'error' => 'curl_init_failed'];
        }

        $body = '';
        $tooLarge = false;
        $retryAfterHeader = null;
        $options = [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => $timeout ?? ($file === null ? self::REQUEST_TIMEOUT : self::UPLOAD_TIMEOUT),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'x-apikey: ' . $apiKey,
            ],
            CURLOPT_USERAGENT => 'SecureScan/' . (defined('PLUGIN_SECURESCAN_VERSION') ? PLUGIN_SECURESCAN_VERSION : '2.0.0'),
            CURLOPT_HEADERFUNCTION => static function ($handle, string $headerLine) use (&$retryAfterHeader): int {
                $length = strlen($headerLine);
                if (stripos($headerLine, 'Retry-After:') === 0) {
                    $retryAfterHeader = trim(substr($headerLine, strlen('Retry-After:')));
                }
                return $length;
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$tooLarge): int {
                $remaining = self::MAX_RESPONSE_BYTES - strlen($body);
                if ($remaining <= 0) {
                    $tooLarge = true;
                    return 0;
                }

                $body .= substr($chunk, 0, $remaining);
                if (strlen($chunk) > $remaining) {
                    $tooLarge = true;
                    return 0;
                }

                return strlen($chunk);
            },
        ];

        if ($method === 'POST') {
            if ($file === null || !is_file($file) || !is_readable($file)) {
                curl_close($curl);
                return ['http_status' => 0, 'body' => '', 'error' => 'upload_file_unavailable'];
            }

            $fileSize = filesize($file);
            if (!is_int($fileSize) || $fileSize < 0 || $fileSize > self::MAX_UPLOAD_BYTES) {
                curl_close($curl);
                return ['http_status' => 0, 'body' => '', 'error' => 'upload_file_too_large'];
            }

            $mime = 'application/octet-stream';
            $options[CURLOPT_POST] = true;
            // Use a neutral upload name; never disclose the original GLPI filename.
            $options[CURLOPT_POSTFIELDS] = [
                'file' => new CURLFile($file, $mime, 'securescan-sample.bin'),
            ];
        }

        if (!curl_setopt_array($curl, $options)) {
            curl_close($curl);
            return ['http_status' => 0, 'body' => '', 'error' => 'curl_options_failed'];
        }

        $executed = curl_exec($curl);
        $info = curl_getinfo($curl);
        $httpStatus = (int) ($info['http_code'] ?? curl_getinfo($curl, CURLINFO_RESPONSE_CODE));
        $curlError = curl_errno($curl);
        $durationMs = max(0, (int) round(((float) ($info['total_time'] ?? 0.0)) * 1000));
        $connectMs = max(0, (int) round(((float) ($info['connect_time'] ?? 0.0)) * 1000));
        $tlsMs = max(0, (int) round(((float) ($info['appconnect_time'] ?? 0.0)) * 1000));
        $firstByteMs = max(0, (int) round(((float) ($info['starttransfer_time'] ?? 0.0)) * 1000));
        curl_close($curl);
        $timing = [
            'duration_ms' => $durationMs,
            'connect_ms' => $connectMs,
            'tls_ms' => $tlsMs,
            'first_byte_ms' => $firstByteMs,
        ];
        $retryAfterSeconds = self::parseRetryAfterHeader($retryAfterHeader);
        if ($retryAfterSeconds !== null) {
            $timing['retry_after'] = $retryAfterSeconds;
        }
        if ($httpStatus === 429) {
            self::deferApiRequests($retryAfterSeconds ?? 30);
        }

        if ($tooLarge) {
            return array_merge(['http_status' => $httpStatus, 'body' => '', 'error' => 'response_too_large'], $timing);
        }

        if ($executed === false || $curlError !== 0) {
            return array_merge(['http_status' => $httpStatus, 'body' => '', 'error' => 'network_error'], $timing);
        }

        return array_merge(['http_status' => $httpStatus, 'body' => $body], $timing);
    }

    /** Reserve a per-minute API request slot and, when applicable, daily quota. */
    private static function reserveApiRequest(bool $consumeDailyQuota): array
    {
        if (!defined('GLPI_PLUGIN_DOC_DIR')) {
            return ['allowed' => true];
        }

        $directory = rtrim((string) GLPI_PLUGIN_DOC_DIR, '/\\') . DIRECTORY_SEPARATOR . 'securescan';
        return VirusTotalRequestLimiter::reserve($directory, $consumeDailyQuota);
    }

    /** Apply VirusTotal's Retry-After to all subsequent API calls from this plugin. */
    private static function deferApiRequests(int $seconds): void
    {
        if (!defined('GLPI_PLUGIN_DOC_DIR')) {
            return;
        }

        $directory = rtrim((string) GLPI_PLUGIN_DOC_DIR, '/\\') . DIRECTORY_SEPARATOR . 'securescan';
        VirusTotalRequestLimiter::defer($directory, $seconds);
    }

    /** Parse Retry-After as delta seconds or an HTTP date, with a safe upper bound. */
    private static function parseRetryAfterHeader(?string $header): ?int
    {
        if ($header === null || $header === '') {
            return null;
        }

        if (ctype_digit($header)) {
            return max(1, min(600, (int) $header));
        }

        $timestamp = strtotime($header);
        if ($timestamp === false) {
            return null;
        }

        return max(1, min(600, $timestamp - time()));
    }

    private static function decodePayload(string $body): ?array
    {
        if ($body === '' || strlen($body) > self::MAX_RESPONSE_BYTES) {
            return null;
        }

        try {
            $payload = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            return is_array($payload) ? $payload : null;
        } catch (Throwable) {
            return null;
        }
    }

    private static function safeCount(mixed $value): int
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            return 0;
        }

        return max(0, min(1000000, (int) $value));
    }

    private static function responseEvidence(array $response, string $fallback): string
    {
        $error = $response['error'] ?? '';
        if ($error === 'local_rate_limit') {
            return 'local_rate_limit';
        }
        if ($error === 'local_daily_quota') {
            return 'local_daily_quota';
        }

        $httpStatus = (int) ($response['http_status'] ?? 0);
        if ($httpStatus === 429) {
            return 'api_rate_limit';
        }
        if (in_array($httpStatus, [401, 403], true)) {
            return 'api_authentication_failed';
        }
        if ($httpStatus >= 500 && $httpStatus <= 599) {
            return 'api_server_error';
        }

        return match ($error) {
            'network_error' => 'network_error',
            'curl_unavailable' => 'curl_unavailable',
            'curl_options_failed' => 'curl_options_failed',
            'response_too_large' => 'response_too_large',
            'upload_file_too_large' => 'upload_file_too_large',
            'upload_file_unavailable' => 'upload_file_unavailable',
            default => $fallback,
        };
    }

    /**
     * @return array{status: string, sha256: string, malicious: int, suspicious: int, total: int, evidence: string, http_status?: int}
     */
    private static function baseResult(string $sha256, string $status, string $evidence, int $httpStatus = 0): array
    {
        $result = [
            'status'     => $status,
            'sha256'     => $sha256,
            'malicious'  => 0,
            'suspicious' => 0,
            'total'      => 0,
            'evidence'   => $evidence,
        ];
        if ($httpStatus > 0) {
            $result['http_status'] = $httpStatus;
        }
        return $result;
    }
}
