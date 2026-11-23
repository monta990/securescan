<?php

namespace GlpiPlugin\Securescan\Controller;

use Glpi\Controller\AbstractController;
use GlpiPlugin\Securescan\Audit;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use GlpiPlugin\Securescan\EngineSelector;
use GlpiPlugin\Securescan\VirusTotal;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Asynchronous VirusTotal preflight for GLPI's staged Document uploads.
 * Each request performs one API operation and returns immediately; no request
 * sleeps or occupies a PHP worker while VirusTotal runs its analysis.
 */
final class VirusTotalScanController extends AbstractController
{
    private const JOB_TTL = 86400;

    #[Route('/ajax/Scan/Start', name: 'securescan_scan_start', methods: ['POST'])]
    public function start(Request $request): JsonResponse
    {
        $requestStarted = microtime(true);
        if (!$this->canScanDocuments()) {
            return $this->json(['status' => 'error', 'message' => __s('You do not have permission to scan document uploads.', 'securescan')], 403);
        }

        $config = SecureScanConfig::getConfig();
        if (EngineSelector::resolve($config) !== EngineSelector::VIRUSTOTAL) {
            return $this->json(['status' => 'error', 'message' => __s('VirusTotal is not the selected SecureScan engine.', 'securescan')], 409);
        }

        $filename = $request->request->getString('filename');
        $source = $request->request->getString('source', 'tmp');
        $file = self::resolveStagedFile($source, $filename);
        if ($file === null) {
            // A staging failure occurs before VirusTotal is called, so record it
            // explicitly; otherwise the user sees an error with no audit trace.
            Audit::recordPreflightFailure('staged_file_not_found', $source, $filename);
            return $this->json(['status' => 'error', 'message' => __s('The staged upload could not be found. Re-select the file and try again.', 'securescan')], 400);
        }

        $userId = (int) \Session::getLoginUserID();
        // Persist/release the PHP session before any outbound VirusTotal request.
        // PHP's default file-session handler locks the session until the request
        // finishes; without closing it, polling would block other GLPI tabs.
        self::releaseSessionLock();

        try {
            // This method hashes and submits if needed, but never waits for VT.
            $result = VirusTotal::scanFile($file, !empty($config['securescan_virustotal_auto_upload']));
        } catch (\Throwable $e) {
            \Toolbox::logDebug($e);
            $result = ['status' => 'unavailable', 'evidence' => 'preflight_exception', 'sha256' => '', 'report_url' => null];
        }

        $status = (string) ($result['status'] ?? 'unavailable');
        $response = [
            'status' => $status,
            'evidence' => (string) ($result['evidence'] ?? 'unknown'),
            'sha256' => (string) ($result['sha256'] ?? ''),
            'analysis_url' => (string) ($result['report_url'] ?? VirusTotal::getFileReportUrl((string) ($result['sha256'] ?? '')) ?? ''),
            'report_url' => (string) ($result['report_url'] ?? VirusTotal::getFileReportUrl((string) ($result['sha256'] ?? '')) ?? ''),
            'malicious' => max(0, (int) ($result['malicious'] ?? 0)),
            'suspicious' => max(0, (int) ($result['suspicious'] ?? 0)),
            'total' => max(0, (int) ($result['total'] ?? 0)),
            'timings' => is_array($result['timings'] ?? null) ? $result['timings'] : [],
        ];

        if ($status === 'pending') {
            $analysisId = $result['analysis_id'] ?? null;
            if (!is_string($analysisId) || $response['sha256'] === '') {
                return $this->json(['status' => 'error', 'message' => __s('VirusTotal did not return a valid analysis reference.', 'securescan')], 502);
            }

            $jobCopyStarted = microtime(true);
            $token = self::createJob([
                'analysis_id' => $analysisId,
                'sha256' => $response['sha256'],
                'filename' => $filename,
                'source' => $source,
                'user_id' => $userId,
                'created_at' => time(),
                'performance' => $response['timings'],
                'poll_count' => 0,
                'analysis_poll_ms_total' => 0,
            ], $file);
            if ($token === null) {
                return $this->json(['status' => 'error', 'message' => __s('SecureScan could not save the pending analysis reference. The file was not stored.', 'securescan')], 500);
            }
            $quarantineCopyMs = max(0, (int) round((microtime(true) - $jobCopyStarted) * 1000));
            $response['timings']['quarantine_copy_ms'] = $quarantineCopyMs;
            $savedJob = self::readJob($token);
            if (is_array($savedJob)) {
                $savedJob['performance'] = is_array($savedJob['performance'] ?? null) ? $savedJob['performance'] : [];
                $savedJob['performance']['quarantine_copy_ms'] = $quarantineCopyMs;
                self::writeJob($token, $savedJob);
            }
            $response['token'] = $token;
            $response['retry_after'] = 2;
            $response['message'] = __s('VirusTotal is analyzing the file. You can continue using GLPI in other tabs; this page will resume the upload when the analysis is complete.', 'securescan');
            $response['timings']['controller_ms'] = max(0, (int) round((microtime(true) - $requestStarted) * 1000));
            Audit::recordPerformance(
                'analysis_submitted',
                'pending',
                $response['sha256'],
                is_file($file) ? (int) filesize($file) : null,
                $response['timings'],
                0,
                (int) $response['timings']['controller_ms'],
                $userId
            );
            return $this->json($response);
        }

        if (in_array($status, ['infected', 'suspicious', 'unavailable', 'not_found'], true)) {
            Audit::record('document_preflight', [
                'ok' => false,
                'status' => $status,
                'scan_verdict' => $status,
                'scan_evidence' => 'virustotal_' . substr($response['evidence'], 0, 64),
                'providers' => ['virustotal' => $response],
            ], $file);
            $response['message'] = self::messageForStatus($status);
            if (in_array($status, ['infected', 'suspicious'], true)) {
                @unlink($file);
            }
        }

        $response['timings']['controller_ms'] = max(0, (int) round((microtime(true) - $requestStarted) * 1000));
        Audit::recordPerformance(
            'initial_lookup',
            $status,
            $response['sha256'],
            is_file($file) ? (int) filesize($file) : null,
            $response['timings'],
            0,
            (int) $response['timings']['controller_ms'],
            $userId
        );
        return $this->json($response);
    }

    #[Route('/ajax/Scan/Status/{token}', name: 'securescan_scan_status', methods: ['GET'])]
    public function status(string $token): JsonResponse
    {
        $requestStarted = microtime(true);
        if (!$this->canScanDocuments()) {
            return $this->json(['status' => 'error', 'message' => __s('You do not have permission to check this analysis.', 'securescan')], 403);
        }

        $job = self::readJob($token);
        if ($job === null || (int) ($job['user_id'] ?? 0) !== (int) \Session::getLoginUserID()) {
            return $this->json(['status' => 'error', 'message' => __s('The pending analysis has expired. Re-select the file to start again.', 'securescan')], 404);
        }

        // Authentication, permission and job ownership have been checked. Release
        // PHP's session lock before file hashing and the external API call so other
        // GLPI tabs can continue using the same logged-in session.
        self::releaseSessionLock();

        // The GLPI staging directory is temporary and may be cleaned while a
        // remote analysis is pending. Poll against SecureScan's private copy,
        // then restore the original GLPI staged basename only after a clean result.
        $file = self::resolveJobFile($token);
        if ($file === null) {
            Audit::recordPreflightFailure('quarantine_file_missing', (string) ($job['source'] ?? 'tmp'), (string) ($job['filename'] ?? ''));
            self::deleteJob($token);
            return $this->json(['status' => 'error', 'message' => __s('SecureScan could not recover the protected temporary copy. Select the file again and retry.', 'securescan')], 410);
        }

        $hashCheckStarted = microtime(true);
        $actualHash = hash_file('sha256', $file);
        $hashCheckMs = max(0, (int) round((microtime(true) - $hashCheckStarted) * 1000));
        if (!is_string($actualHash) || !hash_equals((string) ($job['sha256'] ?? ''), $actualHash)) {
            Audit::recordPreflightFailure('quarantine_hash_mismatch', (string) ($job['source'] ?? 'tmp'), (string) ($job['filename'] ?? ''));
            self::deleteJob($token);
            return $this->json(['status' => 'error', 'message' => __s('The protected file copy changed during scanning. Select the file again and retry.', 'securescan')], 409);
        }

        // A terminal result is kept in the job until GLPI's original staged file
        // is restored. If the web request is interrupted during restoration, the
        // next poll can finish without querying VirusTotal again.
        $pollStarted = microtime(true);
        $savedResult = $job['completed_result'] ?? null;
        if (is_array($savedResult) && in_array($savedResult['status'] ?? '', ['clean', 'infected', 'suspicious', 'unavailable'], true)) {
            $result = $savedResult;
        } else {
            try {
                // Exactly one GET /analyses/{id} per request; no sleep/wait loop.
                $result = VirusTotal::pollAnalysis((string) $job['sha256'], (string) $job['analysis_id']);
            } catch (\Throwable $e) {
                \Toolbox::logDebug($e);
                $result = [
                    'status' => 'pending',
                    'evidence' => 'analysis_poll_exception',
                    'sha256' => (string) $job['sha256'],
                    'retry_after' => 15,
                ];
            }
        }

        $pollWallMs = max(0, (int) round((microtime(true) - $pollStarted) * 1000));
        $status = (string) ($result['status'] ?? 'unavailable');
        $response = [
            'status' => $status,
            'evidence' => (string) ($result['evidence'] ?? 'unknown'),
            'sha256' => (string) ($result['sha256'] ?? $job['sha256']),
            'analysis_url' => (string) ($result['report_url'] ?? VirusTotal::getFileReportUrl((string) $job['sha256']) ?? ''),
            'malicious' => max(0, (int) ($result['malicious'] ?? 0)),
            'suspicious' => max(0, (int) ($result['suspicious'] ?? 0)),
            'total' => max(0, (int) ($result['total'] ?? 0)),
        ];

        // Count upstream API reads, not local throttle responses that returned
        // before contacting VirusTotal.
        if (($result['evidence'] ?? '') !== 'local_rate_limit') {
            $job['poll_count'] = max(0, (int) ($job['poll_count'] ?? 0)) + 1;
        }
        $job['analysis_poll_ms_total'] = max(0, (int) ($job['analysis_poll_ms_total'] ?? 0))
            + max(0, (int) ($result['timings']['analysis_poll_ms'] ?? $pollWallMs));
        $jobPerformance = is_array($job['performance'] ?? null) ? $job['performance'] : [];
        $jobPerformance['quarantine_hash_ms'] = max(0, (int) ($jobPerformance['quarantine_hash_ms'] ?? 0)) + $hashCheckMs;
        $job['performance'] = $jobPerformance;

        if ($status === 'pending') {
            // Persist only diagnostic counters; failure here must not interrupt a valid pending analysis.
            self::writeJob($token, $job);
            // Poll promptly twice, then let the shared limiter determine when another
            // API slot is available. A server Retry-After (especially HTTP 429)
            // always takes precedence over this local schedule.
            $successfulPolls = max(0, (int) ($job['poll_count'] ?? 0));
            $defaultRetryAfter = $successfulPolls <= 1 ? 6 : 15;
            $response['retry_after'] = max(1, min(600, (int) ($result['retry_after'] ?? $defaultRetryAfter)));
            $response['token'] = $token;
            return $this->json($response);
        }

        $job['completed_result'] = $result;
        if (!self::writeJob($token, $job)) {
            // This does not approve or reject the document. The job and pending
            // analysis reference remain in place so the client can retry safely.
            return $this->json(['status' => 'error', 'message' => __s('SecureScan could not save the completed scan result. Retry the status check; the file has not been stored.', 'securescan')], 500);
        }
        VirusTotal::completePendingAnalysis((string) ($job['sha256'] ?? ''));
        $jobPerformance['analysis_poll_ms_total'] = max(0, (int) ($job['analysis_poll_ms_total'] ?? 0));
        $jobPerformance['analysis_poll_ms'] = max(0, (int) ($result['timings']['analysis_poll_ms'] ?? $pollWallMs));
        foreach (['analysis_connect_ms', 'analysis_tls_ms', 'analysis_first_byte_ms'] as $timingKey) {
            if (isset($result['timings'][$timingKey])) {
                $jobPerformance[$timingKey] = max(0, (int) $result['timings'][$timingKey]);
            }
        }
        $jobPerformance['controller_ms'] = max(0, (int) round((microtime(true) - $requestStarted) * 1000));
        Audit::recordPerformance(
            'analysis_completed',
            $status,
            (string) ($job['sha256'] ?? ''),
            is_file($file) ? (int) filesize($file) : null,
            $jobPerformance,
            (int) ($job['poll_count'] ?? 0),
            max(0, (time() - (int) ($job['created_at'] ?? time())) * 1000),
            (int) ($job['user_id'] ?? 0)
        );

        if ($status === 'clean') {
            $restoreStarted = microtime(true);
            $restored = self::restoreStagedFile(
                (string) ($job['source'] ?? 'tmp'),
                (string) ($job['filename'] ?? ''),
                $file,
                (string) ($job['sha256'] ?? ''),
                $token
            );
            if ($restored === null) {
                // The VirusTotal result is already terminal and saved in the job.
                // Keep the browser polling this endpoint; the next request retries
                // only the local restore step and does not call VirusTotal again.
                $response['status'] = 'pending';
                $response['evidence'] = 'approved_waiting_for_staged_restore';
                $response['retry_after'] = 5;
                $response['token'] = $token;
                $response['message'] = __s('VirusTotal approved the file. SecureScan is restoring it to GLPI temporary storage before continuing.', 'securescan');
                return $this->json($response);
            }
            $restoreMs = max(0, (int) round((microtime(true) - $restoreStarted) * 1000));
            Audit::recordPerformance(
                'staged_file_restored',
                'clean',
                (string) ($job['sha256'] ?? ''),
                is_file($restored) ? (int) filesize($restored) : null,
                ['staged_restore_ms' => $restoreMs],
                (int) ($job['poll_count'] ?? 0),
                null,
                (int) ($job['user_id'] ?? 0)
            );
            self::deleteJob($token);
            return $this->json($response);
        }

        Audit::record('document_preflight', [
            'ok' => false,
            'status' => $status,
            'scan_verdict' => $status,
            'scan_evidence' => 'virustotal_' . substr($response['evidence'], 0, 64),
            'providers' => ['virustotal' => $response],
        ], $file);
        $response['message'] = self::messageForStatus($status);
        if (in_array($status, ['infected', 'suspicious'], true)) {
            $staged = self::resolveStagedFile((string) ($job['source'] ?? 'tmp'), (string) ($job['filename'] ?? ''));
            if ($staged !== null) {
                @unlink($staged);
            }
        }
        self::deleteJob($token);

        return $this->json($response);
    }

    private function canScanDocuments(): bool
    {
        return (int) \Session::getLoginUserID() > 0
            && (\Session::haveRight('document', CREATE) || \Session::haveRight('document', UPDATE));
    }

    private function json(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    private static function releaseSessionLock(): void
    {
        if (function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE) {
            @session_write_close();
        }
    }

    private static function messageForStatus(string $status): string
    {
        return match ($status) {
            'infected' => __s('VirusTotal detected malicious content. SecureScan rejected the file.', 'securescan'),
            'suspicious' => __s('VirusTotal marked the file as suspicious. SecureScan rejected the file.', 'securescan'),
            'not_found' => __s('VirusTotal has no completed report for this file. The file was not stored.', 'securescan'),
            default => __s('VirusTotal could not verify the file. SecureScan rejected the upload.', 'securescan'),
        };
    }

    private static function resolveStagedFile(string $source, string $filename): ?string
    {
        $directory = match ($source) {
            'tmp' => defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : null,
            'upload' => defined('GLPI_UPLOAD_DIR') ? GLPI_UPLOAD_DIR : null,
            default => null,
        };
        if (!is_string($directory) || !self::isSafeStagedFilename($filename)) {
            return null;
        }

        $base = realpath($directory);
        $path = $base === false ? false : realpath($base . DIRECTORY_SEPARATOR . $filename);
        if ($base === false || $path === false || is_link($base . DIRECTORY_SEPARATOR . $filename)
            || !str_starts_with($path, rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
            || !is_file($path) || !is_readable($path)
        ) {
            return null;
        }
        return $path;
    }

    private static function jobsDirectory(bool $create = false): ?string
    {
        if (!defined('GLPI_PLUGIN_DOC_DIR')) {
            return null;
        }
        $base = rtrim((string) GLPI_PLUGIN_DOC_DIR, '/\\') . DIRECTORY_SEPARATOR . 'securescan';
        $directory = $base . DIRECTORY_SEPARATOR . 'virustotal-jobs';
        if (is_link($base) || is_link($directory)) {
            return null;
        }
        if (!is_dir($directory) && (!$create || (!@mkdir($directory, 0700, true) && !is_dir($directory)))) {
            return null;
        }
        @chmod($base, 0700);
        @chmod($directory, 0700);
        return $directory;
    }

    private static function isSafeStagedFilename(string $filename): bool
    {
        // GLPI prepends a random upload tag to the user's original filename.
        // Original names may contain spaces, accents and parentheses; only path
        // separators, control characters and filesystem-reserved characters are
        // rejected. Realpath containment is still checked by resolveStagedFile().
        return $filename !== ''
            && $filename !== '.'
            && $filename !== '..'
            && strlen($filename) <= 255
            && preg_match('/[<>:"\/\\\\|?*\x00-\x1F\x7F]/', $filename) !== 1;
    }

    private static function createJob(array $job, string $sourceFile): ?string
    {
        $directory = self::jobsDirectory(true);
        if ($directory === null || !is_file($sourceFile) || !is_readable($sourceFile)) {
            return null;
        }
        self::cleanupExpiredJobs($directory);

        // Reuse an existing identical job only when its private file copy is
        // present and still matches the expected hash.
        foreach (glob($directory . DIRECTORY_SEPARATOR . '*.json') ?: [] as $existingPath) {
            if (is_link($existingPath) || !is_file($existingPath)) {
                continue;
            }
            $existingRaw = @file_get_contents($existingPath);
            $existing = is_string($existingRaw) ? json_decode($existingRaw, true) : null;
            if (!is_array($existing)) {
                continue;
            }
            $existingToken = basename($existingPath, '.json');
            $sameJob = (int) ($existing['user_id'] ?? 0) === (int) ($job['user_id'] ?? -1)
                && hash_equals((string) ($existing['sha256'] ?? ''), (string) ($job['sha256'] ?? ''))
                && hash_equals((string) ($existing['analysis_id'] ?? ''), (string) ($job['analysis_id'] ?? ''))
                && (string) ($existing['filename'] ?? '') === (string) ($job['filename'] ?? '')
                && (string) ($existing['source'] ?? '') === (string) ($job['source'] ?? '')
                && time() - (int) ($existing['created_at'] ?? 0) <= self::JOB_TTL;
            $existingFile = self::resolveJobFile($existingToken);
            if ($sameJob && $existingFile !== null) {
                $existingHash = hash_file('sha256', $existingFile);
                if (is_string($existingHash) && hash_equals((string) $job['sha256'], $existingHash)) {
                    return $existingToken;
                }
            }
        }

        try {
            $token = bin2hex(random_bytes(24));
            $quarantinePath = $directory . DIRECTORY_SEPARATOR . $token . '.bin';
            $quarantineTemporary = $quarantinePath . '.tmp';
            if (!@copy($sourceFile, $quarantineTemporary)) {
                return null;
            }
            @chmod($quarantineTemporary, 0600);
            $copiedHash = hash_file('sha256', $quarantineTemporary);
            if (!is_string($copiedHash) || !hash_equals((string) ($job['sha256'] ?? ''), $copiedHash)
                || !@rename($quarantineTemporary, $quarantinePath)
            ) {
                @unlink($quarantineTemporary);
                @unlink($quarantinePath);
                return null;
            }
            @chmod($quarantinePath, 0600);

            $job['quarantine_file'] = $token . '.bin';
            $path = $directory . DIRECTORY_SEPARATOR . $token . '.json';
            $temporary = $path . '.tmp';
            $json = json_encode($job, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (@file_put_contents($temporary, $json, LOCK_EX) === false) {
                @unlink($quarantinePath);
                return null;
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $path)) {
                @unlink($temporary);
                @unlink($quarantinePath);
                return null;
            }
            return $token;
        } catch (\Throwable) {
            return null;
        }
    }

    private static function resolveJobFile(string $token): ?string
    {
        if (preg_match('/^[a-f0-9]{48}$/D', $token) !== 1) {
            return null;
        }
        $directory = self::jobsDirectory();
        $base = $directory !== null ? realpath($directory) : false;
        if ($base === false) {
            return null;
        }
        $candidate = $base . DIRECTORY_SEPARATOR . $token . '.bin';
        if (is_link($candidate)) {
            return null;
        }
        $path = realpath($candidate);
        if ($path === false
            || !str_starts_with($path, rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
            || !is_file($path)
            || !is_readable($path)
        ) {
            return null;
        }
        return $path;
    }

    private static function writeJob(string $token, array $job): bool
    {
        if (preg_match('/^[a-f0-9]{48}$/D', $token) !== 1) {
            return false;
        }
        $directory = self::jobsDirectory();
        if ($directory === null) {
            return false;
        }
        $path = $directory . DIRECTORY_SEPARATOR . $token . '.json';
        if (is_link($path) || !is_file($path)) {
            return false;
        }
        try {
            $temporary = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
            $json = json_encode($job, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (@file_put_contents($temporary, $json, LOCK_EX) === false) {
                return false;
            }
            @chmod($temporary, 0600);
            $backup = $path . '.' . bin2hex(random_bytes(6)) . '.bak';
            if (!@rename($path, $backup)) {
                @unlink($temporary);
                return false;
            }
            if (!@rename($temporary, $path)) {
                @rename($backup, $path);
                @unlink($temporary);
                return false;
            }
            @unlink($backup);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function restoreStagedFile(
        string $source,
        string $filename,
        string $quarantineFile,
        string $expectedHash,
        string $token
    ): ?string {
        $existing = self::resolveStagedFile($source, $filename);
        if ($existing !== null) {
            $existingHash = hash_file('sha256', $existing);
            return is_string($existingHash) && hash_equals($expectedHash, $existingHash) ? $existing : null;
        }

        $directory = match ($source) {
            'tmp' => defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : null,
            'upload' => defined('GLPI_UPLOAD_DIR') ? GLPI_UPLOAD_DIR : null,
            default => null,
        };
        if (!is_string($directory) || !self::isSafeStagedFilename($filename)) {
            return null;
        }
        $base = realpath($directory);
        if ($base === false || !is_dir($base) || !is_writable($base)) {
            return null;
        }
        $target = $base . DIRECTORY_SEPARATOR . $filename;
        if (file_exists($target) || is_link($target)) {
            return null;
        }

        $temporary = $base . DIRECTORY_SEPARATOR . '.securescan-' . $token . '.tmp';
        if (is_link($temporary) || file_exists($temporary) || !@copy($quarantineFile, $temporary)) {
            return null;
        }
        @chmod($temporary, 0600);
        $restoredHash = hash_file('sha256', $temporary);
        if (!is_string($restoredHash) || !hash_equals($expectedHash, $restoredHash) || !@rename($temporary, $target)) {
            @unlink($temporary);
            return null;
        }

        return self::resolveStagedFile($source, $filename);
    }

    /**
     * Opportunistically clean abandoned private job files at most once per hour.
     * Called from plugin initialization for authenticated GLPI requests.
     */
    public static function cleanupExpiredJobsOnRequest(): void
    {
        $directory = self::jobsDirectory();
        if ($directory === null) {
            return;
        }

        $marker = $directory . DIRECTORY_SEPARATOR . '.cleanup-check';
        $handle = @fopen($marker, 'c');
        if ($handle === false) {
            return;
        }
        @chmod($marker, 0600);
        if (flock($handle, LOCK_EX)) {
            clearstatcache(true, $marker);
            $modified = @filemtime($marker);
            if (!is_int($modified) || $modified <= 0 || time() - $modified >= 3600) {
                self::cleanupExpiredJobs($directory);
                @touch($marker);
            }
            flock($handle, LOCK_UN);
        }
        fclose($handle);
    }

    private static function cleanupExpiredJobs(string $directory): void
    {
        $now = time();
        $paths = array_merge(
            glob($directory . DIRECTORY_SEPARATOR . '*.json') ?: [],
            glob($directory . DIRECTORY_SEPARATOR . '*.bin') ?: [],
            glob($directory . DIRECTORY_SEPARATOR . '*.tmp') ?: [],
            glob($directory . DIRECTORY_SEPARATOR . '*.bak') ?: []
        );
        foreach ($paths as $path) {
            if (is_link($path) || !is_file($path)) {
                continue;
            }
            $modified = @filemtime($path);
            if (is_int($modified) && $modified > 0 && $now - $modified > self::JOB_TTL) {
                @unlink($path);
            }
        }
    }

    private static function readJob(string $token): ?array
    {
        if (preg_match('/^[a-f0-9]{48}$/D', $token) !== 1) {
            return null;
        }
        $directory = self::jobsDirectory();
        if ($directory === null) {
            return null;
        }
        $path = $directory . DIRECTORY_SEPARATOR . $token . '.json';
        if (is_link($path) || !is_file($path) || !is_readable($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        $job = is_string($raw) ? json_decode($raw, true) : null;
        $created = is_array($job) ? (int) ($job['created_at'] ?? 0) : 0;
        if (!is_array($job) || $created <= 0 || time() - $created > self::JOB_TTL) {
            self::deleteJob($token);
            return null;
        }
        return $job;
    }

    private static function deleteJob(string $token): void
    {
        if (preg_match('/^[a-f0-9]{48}$/D', $token) !== 1) {
            return;
        }
        $directory = self::jobsDirectory();
        if ($directory === null) {
            return;
        }
        foreach ([$token . '.json', $token . '.bin'] as $filename) {
            $path = $directory . DIRECTORY_SEPARATOR . $filename;
            if (!is_link($path) && is_file($path)) {
                @unlink($path);
            }
        }
    }
}
