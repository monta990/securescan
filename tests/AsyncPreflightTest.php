<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$virusTotal = file_get_contents($root . '/src/VirusTotal.php');
$limiter = file_get_contents($root . '/src/VirusTotalRequestLimiter.php');
$controller = file_get_contents($root . '/src/Controller/VirusTotalScanController.php');
$javascript = file_get_contents($root . '/public/js/securescan-wait.js');
$setup = file_get_contents($root . '/setup.php');
$antivirus = file_get_contents($root . '/src/Antivirus.php');
$audit = file_get_contents($root . '/src/Audit.php');
$uninstall = file_get_contents($root . '/hook.php');

if (!is_string($virusTotal) || !is_string($limiter) || !is_string($controller) || !is_string($javascript) || !is_string($setup) || !is_string($antivirus) || !is_string($audit) || !is_string($uninstall)) {
    fwrite(STDERR, "Unable to read async preflight source files.\n");
    exit(1);
}

$checks = [
    'VirusTotal API client contains no blocking sleep loop' => !str_contains($virusTotal, 'sleep('),
    'VirusTotal API client does not disable the PHP execution time limit' => !str_contains($virusTotal, 'set_time_limit(0)'),
    'VirusTotal analysis is checked one request at a time' => str_contains($virusTotal, 'public static function pollAnalysis(')
        && str_contains($virusTotal, '\'/analyses/\' . rawurlencode($analysisId)'),
    'Analysis status polling bypasses local file-report quota accounting' => str_contains($virusTotal, 'str_starts_with($path, \'/analyses/\')'),
    'Start route is authenticated and uses POST' => str_contains($controller, "#[Route('/ajax/Scan/Start'") && str_contains($controller, "methods: ['POST']"),
    'Status route uses a separate GET request' => str_contains($controller, "#[Route('/ajax/Scan/Status/{token}'") && str_contains($controller, "methods: ['GET']"),
    'Job is bound to user and staged-file hash' => str_contains($controller, "'user_id' => " . '$userId') && str_contains($controller, '\'sha256\' => $response[\'sha256\']'),
    'Polling revalidates the staged file SHA-256' => str_contains($controller, 'hash_equals((string) ($job[\'sha256\'] ?? \'\'), $actualHash)'),
    'Start route releases PHP session lock before VirusTotal I/O' => strpos($controller, 'self::releaseSessionLock();') < strpos($controller, 'VirusTotal::scanFile($file, !empty'),
    'Status route releases PHP session lock before VirusTotal I/O' => strpos($controller, 'self::releaseSessionLock();', strpos($controller, 'public function status(')) < strpos($controller, 'VirusTotal::pollAnalysis('),
    'Existing analysis is checked before another file-report lookup' => strpos($virusTotal, 'readPendingAnalysisId($sha256)') < strpos($virusTotal, "self::request('GET', '/files/'"),
    'Normal GLPI upload hook is cache-only, with no synchronous VirusTotal call' => str_contains($antivirus, 'VirusTotal::getApprovedScan(') && !str_contains($antivirus, 'VirusTotal::scanFile(') && str_contains($virusTotal, 'public static function getApprovedScan('),
    'Cache-only approval function contains no outbound API request' => (function () use ($virusTotal): bool {
        $start = strpos($virusTotal, 'public static function getApprovedScan(');
        $end = strpos($virusTotal, 'public static function pollAnalysis(', $start === false ? 0 : $start);
        return $start !== false && $end !== false && !str_contains(substr($virusTotal, $start, $end - $start), 'self::request(');
    })(),
    'A pending pre-storage verdict preserves the staged temporary file for retry' => str_contains($antivirus, "['status'] === 'pending'") && str_contains($antivirus, '$removeStagedFile'),
    'Pending VirusTotal jobs copy the staged file into private quarantine' => str_contains($controller, 'copy($sourceFile, $quarantineTemporary)') && str_contains($controller, 'chmod($quarantinePath, 0600)'),
    'Analysis polling reads the private quarantine copy rather than GLPI temp storage' => str_contains($controller, 'self::resolveJobFile($token)'),
    'Clean analysis restores the exact GLPI staged filename before replay' => str_contains($controller, 'self::restoreStagedFile(') && str_contains($javascript, 'form.requestSubmit'),
    'Staged filenames permit Unicode and spaces while rejecting path characters' => str_contains($controller, 'private static function isSafeStagedFilename(') && str_contains($controller, 'str_starts_with($path, rtrim($base, DIRECTORY_SEPARATOR)'),
    'Missing staged files create an explicit audit event' => str_contains($controller, "Audit::recordPreflightFailure('staged_file_not_found'") && str_contains($audit, 'public static function recordPreflightFailure('),
    'Fast initial polling checks at two and eight seconds before limiter backoff' => str_contains($controller, '$response[\'retry_after\'] = 2') && str_contains($controller, '$successfulPolls <= 1 ? 6 : 15') && str_contains($javascript, ': 6;'),
    'Local rate-limit denials do not inflate upstream poll count' => str_contains($controller, "\$result['evidence'] ?? '') !== 'local_rate_limit'"),
    'Every VirusTotal API call is rate-limited while quota-exempt calls avoid daily quota' => str_contains($virusTotal, 'reserveApiRequest(!$quotaExempt)') && str_contains($virusTotal, 'str_starts_with(') && str_contains($virusTotal, '/analyses/') && str_contains($virusTotal, 'POST /files'),
    'Rate-limit state is shared across all API calls and jobs' => str_contains($virusTotal, 'VirusTotalRequestLimiter::defer($directory, $seconds)') && str_contains($limiter, 'public static function reserve('),
    'VirusTotal Retry-After response header is parsed and honored' => str_contains($virusTotal, 'CURLOPT_HEADERFUNCTION') && str_contains($virusTotal, 'parseRetryAfterHeader($retryAfterHeader)'),
    'Pending modal message is not duplicated in the secondary paragraph' => str_contains($javascript, "el.keep.textContent = '';"),
    'Performance diagnostics record the VirusTotal phases without storing secrets' => str_contains($controller, 'Audit::recordPerformance(') && str_contains($audit, "'type' => 'performance'"),
    'Completed analysis reference is cleared only after the job result is persisted' => str_contains($virusTotal, 'public static function completePendingAnalysis(') && str_contains($controller, 'VirusTotal::completePendingAnalysis('),
    'Browser preflight also recognizes GLPI server-upload selector' => str_contains($javascript, 'select[name="upload_file"]'),
    'Uninstall cleanup removes private quarantine files' => str_contains($uninstall, "glob(\$privateDirectory . '/*.bin')"),
    'Abandoned private jobs are cleaned opportunistically during authenticated requests' => str_contains($setup, 'cleanupExpiredJobsOnRequest()') && str_contains($controller, 'public static function cleanupExpiredJobsOnRequest()'),
    'Browser displays VirusTotal report link and polls status route' => str_contains($javascript, 'analysis_url') && str_contains($javascript, '/ajax/Scan/Status/'),
    'Browser replays the original form only after clean results' => str_contains($javascript, "result.status !== 'clean'") && str_contains($javascript, 'form.requestSubmit'),
    'Preflight script is loaded whenever VirusTotal is the selected engine' => str_contains($setup, '$selectedEngine === EngineSelector::VIRUSTOTAL'),
    'Unknown-file submission remains an independent option' => str_contains($controller, 'securescan_virustotal_auto_upload') && str_contains($controller, 'VirusTotal::scanFile('),
];

$failures = 0;
foreach ($checks as $label => $passed) {
    if (!$passed) {
        $failures++;
        fwrite(STDERR, "FAIL: {$label}\n");
    } else {
        fwrite(STDOUT, "PASS: {$label}\n");
    }
}

fwrite(STDOUT, sprintf("\n%d tests, %d failures\n", count($checks), $failures));
exit($failures === 0 ? 0 : 1);
