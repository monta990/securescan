<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/VirusTotal.php';

use GlpiPlugin\Securescan\VirusTotal;

$tests = 0;
$failures = [];

$check = static function (string $name, bool $condition) use (&$tests, &$failures): void {
    $tests++;
    if (!$condition) {
        $failures[] = $name;
        fwrite(STDERR, "FAIL: {$name}\n");
    } else {
        fwrite(STDOUT, "PASS: {$name}\n");
    }
};

$malicious = VirusTotal::normalizeReport([
    'data' => ['attributes' => ['last_analysis_stats' => [
        'malicious' => 3, 'suspicious' => 0, 'harmless' => 20, 'undetected' => 40,
    ]]],
]);
$check('malicious detections are classified as infected', $malicious['status'] === 'infected' && $malicious['malicious'] === 3);

$suspicious = VirusTotal::normalizeReport([
    'data' => ['attributes' => ['last_analysis_stats' => [
        'malicious' => 0, 'suspicious' => 2, 'harmless' => 10,
    ]]],
]);
$check('suspicious detections remain distinct', $suspicious['status'] === 'suspicious' && $suspicious['suspicious'] === 2);

$clean = VirusTotal::normalizeReport([
    'data' => ['attributes' => ['last_analysis_stats' => [
        'malicious' => 0, 'suspicious' => 0, 'harmless' => 12, 'undetected' => 38, 'timeout' => 2,
    ]]],
]);
$check('harmless and undetected results can produce a clean verdict', $clean['status'] === 'clean' && $clean['total'] === 52);

$inconclusive = VirusTotal::normalizeReport([
    'data' => ['attributes' => ['last_analysis_stats' => [
        'malicious' => 0, 'suspicious' => 0, 'timeout' => 12, 'failure' => 3, 'type-unsupported' => 8,
    ]]],
]);
$check('timeouts and unsupported types cannot become a clean verdict', $inconclusive['status'] === 'unavailable');
$missing = VirusTotal::normalizeReport(['data' => ['attributes' => []]]);
$check('missing analysis statistics are inconclusive', $missing['status'] === 'unavailable');
$empty = VirusTotal::normalizeReport(['data' => ['attributes' => ['last_analysis_stats' => []]]]);
$check('empty analysis statistics are inconclusive', $empty['status'] === 'unavailable');

$queued = VirusTotal::normalizeAnalysis(['data' => ['attributes' => ['status' => 'queued']]]);
$check('queued VirusTotal analysis remains pending', $queued['status'] === 'pending');
$running = VirusTotal::normalizeAnalysis(['data' => ['attributes' => ['status' => 'in-progress']]]);
$check('in-progress VirusTotal analysis remains pending', $running['status'] === 'pending');

$completedClean = VirusTotal::normalizeAnalysis(['data' => ['attributes' => [
    'status' => 'completed', 'stats' => ['malicious' => 0, 'suspicious' => 0, 'harmless' => 14, 'undetected' => 27],
]]]);
$check('completed clean analysis can approve the upload', $completedClean['status'] === 'clean' && $completedClean['total'] === 41);

$completedMalicious = VirusTotal::normalizeAnalysis(['data' => ['attributes' => [
    'status' => 'completed', 'stats' => ['malicious' => 2, 'suspicious' => 0, 'harmless' => 5],
]]]);
$check('completed malicious analysis rejects the upload', $completedMalicious['status'] === 'infected' && $completedMalicious['malicious'] === 2);

$completedSuspicious = VirusTotal::normalizeAnalysis(['data' => ['attributes' => [
    'status' => 'completed', 'stats' => ['malicious' => 0, 'suspicious' => 1, 'harmless' => 8],
]]]);
$check('completed suspicious analysis remains rejected', $completedSuspicious['status'] === 'suspicious');

$failedAnalysis = VirusTotal::normalizeAnalysis(['data' => ['attributes' => ['status' => 'failed']]]);
$check('failed VirusTotal analysis is unavailable and never clean', $failedAnalysis['status'] === 'unavailable');
$unknownAnalysis = VirusTotal::normalizeAnalysis(['data' => ['attributes' => ['status' => 'unexpected-state']]]);
$check('unknown VirusTotal analysis states fail closed instead of waiting indefinitely', $unknownAnalysis['status'] === 'unavailable' && $unknownAnalysis['evidence'] === 'analysis_unknown_status');
$completedWithoutStats = VirusTotal::normalizeAnalysis(['data' => ['attributes' => ['status' => 'completed']]]);
$check('completed analysis without statistics remains unavailable', $completedWithoutStats['status'] === 'unavailable');

$check('valid API-key shape is accepted', VirusTotal::isValidApiKeyShape(str_repeat('a', 64)));
$check('API keys containing whitespace are rejected', !VirusTotal::isValidApiKeyShape('invalid key with spaces'));
$check('tested-key fingerprint is stable', hash_equals(
    VirusTotal::getTestedKeyHash('sample-api-key-0123456789'),
    VirusTotal::getTestedKeyHash('sample-api-key-0123456789')
));

fwrite(STDOUT, sprintf("\n%d tests, %d failures\n", $tests, count($failures)));
exit($failures === [] ? 0 : 1);
