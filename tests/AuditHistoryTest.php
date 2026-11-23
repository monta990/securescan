<?php

declare(strict_types=1);

// Minimal GLPI stand-ins for standalone tests outside a live GLPI instance.
if (!function_exists('__')) {
    function __(string $message, ?string $domain = null): string
    {
        return $message;
    }
}

if (!class_exists('Toolbox')) {
    class Toolbox
    {
        public static function logInFile(string $name, string $message, bool $force = false): void
        {
        }

        public static function logDebug(Throwable $exception): void
        {
        }
    }
}

if (!class_exists('Log')) {
    class Log
    {
        public const HISTORY_PLUGIN = 1000;
        public const HISTORY_LOG_SIMPLE_MESSAGE = 12;
        public static array $historyCalls = [];

        public static function history(
            int $itemsId,
            string $itemtype,
            array $changes,
            string|int $itemtypeLink = '',
            int $linkedAction = 0
        ): bool {
            self::$historyCalls[] = [$itemsId, $itemtype, $changes, $itemtypeLink, $linkedAction];
            return true;
        }
    }
}

require_once __DIR__ . '/../src/VirusTotal.php';
require_once __DIR__ . '/../src/Audit.php';

use GlpiPlugin\Securescan\Audit;
use GlpiPlugin\Securescan\VirusTotal;

final class AuditHistoryTestDocument
{
    /** @var array<string, int> */
    public array $fields;

    public function __construct(int $id)
    {
        $this->fields = ['id' => $id];
    }

    public function getID(): int
    {
        return $this->fields['id'];
    }
}

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

$sha256 = str_repeat('a', 64);
$url = VirusTotal::getFileReportUrl($sha256);
$check(
    'VirusTotal file report URL is derived from a valid SHA-256',
    $url === 'https://www.virustotal.com/gui/file/' . $sha256 . '/detection'
);
$check('uppercase SHA-256 is normalized', VirusTotal::getFileReportUrl(strtoupper($sha256)) === $url);
$check('invalid SHA-256 cannot produce a VirusTotal URL', VirusTotal::getFileReportUrl('not-a-hash') === null);

$entry = Audit::getHistoryEntry([
    'old_value' => $sha256,
    'new_value' => (string) $url,
]);
$check('GLPI history entry renders a clickable VirusTotal link',
    str_contains($entry, '<a href="' . $url . '"')
    && str_contains($entry, 'target="_blank"')
    && str_contains($entry, 'rel="noopener noreferrer"')
    && str_contains($entry, 'View VirusTotal analysis')
);
$check('tampered external URL is rejected by the history renderer', Audit::getHistoryEntry([
    'old_value' => $sha256,
    'new_value' => 'https://example.com/report',
]) === '');
$check('mismatched SHA-256 and report URL is rejected', Audit::getHistoryEntry([
    'old_value' => str_repeat('b', 64),
    'new_value' => (string) $url,
]) === '');

$item = new AuditHistoryTestDocument(123);
Log::$historyCalls = [];
Audit::recordStored(
    'document_stored',
    'clean',
    'clean',
    'virustotal_harmless_or_undetected',
    null,
    4096,
    $sha256,
    $item,
    [
        'virustotal' => [
            'status' => 'clean',
            'evidence' => 'harmless_or_undetected',
            'report_url' => $url,
        ],
    ]
);
$virusTotalHistoryCall = Log::$historyCalls[0] ?? null;
$check(
    'successful VirusTotal storage writes a native plugin-history entry with the report URL',
    is_array($virusTotalHistoryCall)
    && $virusTotalHistoryCall[0] === 123
    && $virusTotalHistoryCall[1] === AuditHistoryTestDocument::class
    && $virusTotalHistoryCall[2] === [0, $sha256, $url]
    && $virusTotalHistoryCall[3] === Audit::class
    && $virusTotalHistoryCall[4] === Log::HISTORY_PLUGIN
);

Log::$historyCalls = [];
Audit::recordStored(
    'document_stored',
    'clean',
    'clean',
    'target_ok',
    0,
    4096,
    $sha256,
    $item,
    [
        'clamav' => [
            'status' => 'clean',
            'evidence' => 'target_ok',
        ],
    ]
);
$clamAvHistoryCall = Log::$historyCalls[0] ?? null;
$check(
    'ClamAV storage keeps the standard text-only GLPI history entry',
    is_array($clamAvHistoryCall)
    && $clamAvHistoryCall[0] === 123
    && $clamAvHistoryCall[1] === AuditHistoryTestDocument::class
    && $clamAvHistoryCall[3] === 0
    && $clamAvHistoryCall[4] === Log::HISTORY_LOG_SIMPLE_MESSAGE
    && str_contains((string) ($clamAvHistoryCall[2][2] ?? ''), 'Result: clean')
);

fwrite(STDOUT, sprintf("\n%d tests, %d failures\n", $tests, count($failures)));
exit($failures === [] ? 0 : 1);
