<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/VirusTotalRequestLimiter.php';

use GlpiPlugin\Securescan\VirusTotalRequestLimiter;

$check = static function (string $label, bool $passed): void {
    if (!$passed) {
        fwrite(STDERR, "FAIL: {$label}\n");
        exit(1);
    }
    fwrite(STDOUT, "PASS: {$label}\n");
};

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'securescan-api-limit-' . bin2hex(random_bytes(8));
$now = 1_800_000_000;

$first = VirusTotalRequestLimiter::reserve($base, true, $now);
$check('quota-consuming API request is allowed initially', ($first['allowed'] ?? false) === true);

$exempt1 = VirusTotalRequestLimiter::reserve($base, false, $now + 1);
$exempt2 = VirusTotalRequestLimiter::reserve($base, false, $now + 2);
$exempt3 = VirusTotalRequestLimiter::reserve($base, false, $now + 3);
$check('quota-exempt requests are still counted toward minute rate', ($exempt1['allowed'] ?? false) && ($exempt2['allowed'] ?? false) && ($exempt3['allowed'] ?? false));

$blocked = VirusTotalRequestLimiter::reserve($base, false, $now + 4);
$check('fifth call in the rolling minute is blocked', ($blocked['allowed'] ?? true) === false && ($blocked['error'] ?? '') === 'local_rate_limit');
$check('rate-limit response includes seconds until a slot opens', ($blocked['retry_after'] ?? 0) === 56);

$afterWindow = VirusTotalRequestLimiter::reserve($base, false, $now + 60);
$check('quota-exempt request is allowed after rate window expires', ($afterWindow['allowed'] ?? false) === true);

VirusTotalRequestLimiter::defer($base, 45, $now + 60);
$deferred = VirusTotalRequestLimiter::reserve($base, false, $now + 61);
$check('upstream Retry-After blocks every endpoint through shared state', ($deferred['allowed'] ?? true) === false && ($deferred['retry_after'] ?? 0) === 44);

$path = $base . DIRECTORY_SEPARATOR . 'virustotal-quota.json';
$contents = file_get_contents($path);
$state = is_string($contents) ? json_decode($contents, true) : null;
$dailyCount = is_array($state) && is_array($state['requests'] ?? null)
    ? count(array_filter($state['requests'], static fn(array $entry): bool => ($entry['quota'] ?? false) === true))
    : -1;
$check('quota-exempt operations do not increase the daily quota count', $dailyCount === 1);

$dailyFollowup = VirusTotalRequestLimiter::reserve($base, true, $now + 120);
$dailyContents = file_get_contents($path);
$dailyState = is_string($dailyContents) ? json_decode($dailyContents, true) : null;
$dailyCountAfter = is_array($dailyState) && is_array($dailyState['requests'] ?? null)
    ? count(array_filter($dailyState['requests'], static fn(array $entry): bool => ($entry['quota'] ?? false) === true))
    : -1;
$check('only quota-consuming operations increase the daily quota count', ($dailyFollowup['allowed'] ?? false) && $dailyCountAfter === 2);

// Existing installations may still have the old integer timestamp list. Those
// entries represented quota-consuming calls and must be migrated conservatively.
$legacyDir = $base . '-legacy';
@mkdir($legacyDir, 0700, true);
file_put_contents($legacyDir . DIRECTORY_SEPARATOR . 'virustotal-quota.json', json_encode([$now, $now + 1]));
$migrated = VirusTotalRequestLimiter::reserve($legacyDir, false, $now + 2);
$migratedContents = file_get_contents($legacyDir . DIRECTORY_SEPARATOR . 'virustotal-quota.json');
$migratedState = is_string($migratedContents) ? json_decode($migratedContents, true) : null;
$check('legacy timestamp-list state is migrated without losing prior request counts', ($migrated['allowed'] ?? false) && is_array($migratedState) && count($migratedState['requests'] ?? []) === 3);

$permissions = fileperms($path);
$check('limiter state file is private', is_int($permissions) && (($permissions & 0777) === 0600));

$dailyDir = $base . '-daily';
$dailyExhaustedCorrectly = true;
for ($index = 0; $index < 500; $index++) {
    $entry = VirusTotalRequestLimiter::reserve($dailyDir, true, $now + ($index * 61));
    if (($entry['allowed'] ?? false) !== true) {
        $dailyExhaustedCorrectly = false;
        break;
    }
}
$dailyLimit = VirusTotalRequestLimiter::reserve($dailyDir, true, $now + (500 * 61));
$dailyExempt = VirusTotalRequestLimiter::reserve($dailyDir, false, $now + (500 * 61));
$check('500 quota-consuming calls exhaust the daily quota', $dailyExhaustedCorrectly && ($dailyLimit['allowed'] ?? true) === false && ($dailyLimit['error'] ?? '') === 'local_daily_quota');
$check('quota-exempt calls remain outside daily quota after exhaustion', ($dailyExempt['allowed'] ?? false) === true);

@unlink($dailyDir . DIRECTORY_SEPARATOR . 'virustotal-quota.json');
@rmdir($dailyDir);
@unlink($path);
@unlink($legacyDir . DIRECTORY_SEPARATOR . 'virustotal-quota.json');
@rmdir($legacyDir);
@rmdir($base);
fwrite(STDOUT, "\n12 tests, 0 failures\n");
