<?php

declare(strict_types=1);

class Toolbox
{
    /** @var list<string> */
    public static array $entries = [];

    public static function logInFile(string $name, string $message, bool $force = false): void
    {
        self::$entries[] = $message;
    }
}

class Session
{
    public static function getLoginUserID(): int
    {
        return 42;
    }
}

require_once __DIR__ . '/../src/Audit.php';

$check = static function (string $label, bool $passed): void {
    if (!$passed) {
        fwrite(STDERR, "FAIL: {$label}\n");
        exit(1);
    }
    fwrite(STDOUT, "PASS: {$label}\n");
};

\GlpiPlugin\Securescan\Audit::recordPerformance(
    'analysis_completed',
    'clean',
    str_repeat('a', 64),
    2048,
    [
        'sample_upload_ms' => 812,
        'analysis_poll_ms_total' => 3300,
        'controller_ms' => 120,
        'api_key' => 'must-never-be-logged',
        'filename' => 'secret.xlsx',
        'analysis_id' => 'sensitive-id',
    ],
    4,
    15000,
    42
);

$entry = json_decode(Toolbox::$entries[0] ?? '', true);
$check('performance record was written', is_array($entry));
$check('performance record has the correct event type', ($entry['type'] ?? null) === 'performance');
$check('performance durations are retained', ($entry['timings']['sample_upload_ms'] ?? null) === 812 && ($entry['timings']['analysis_poll_ms_total'] ?? null) === 3300);
$check('performance record excludes API key, filename and analysis ID', !array_key_exists('api_key', $entry['timings']) && !array_key_exists('filename', $entry['timings']) && !array_key_exists('analysis_id', $entry['timings']));
$check('performance record includes poll count and elapsed time', ($entry['poll_count'] ?? null) === 4 && ($entry['elapsed_ms'] ?? null) === 15000);

fwrite(STDOUT, "\n5 tests, 0 failures\n");
