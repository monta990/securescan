<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/EngineSelector.php';

use GlpiPlugin\Securescan\EngineSelector;

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

$check('no enabled engines means Disabled', EngineSelector::resolve([
    'securescan_enabled' => 0,
    'securescan_virustotal_enabled' => 0,
]) === EngineSelector::DISABLED);

$check('ClamAV alone is selected', EngineSelector::resolve([
    'securescan_enabled' => 1,
    'securescan_virustotal_enabled' => 0,
]) === EngineSelector::CLAMAV);

$check('VirusTotal alone is selected independently of ClamAV', EngineSelector::resolve([
    'securescan_enabled' => 0,
    'securescan_virustotal_enabled' => 1,
]) === EngineSelector::VIRUSTOTAL);

$check('both engines enabled is treated as a configuration conflict', EngineSelector::resolve([
    'securescan_enabled' => 1,
    'securescan_virustotal_enabled' => 1,
]) === EngineSelector::CONFLICT);

$check('exclusive guard accepts ClamAV alone', (static function (): bool {
    try {
        EngineSelector::assertExclusive(true, false);
        return true;
    } catch (\Throwable) {
        return false;
    }
})());

$check('exclusive guard accepts VirusTotal alone', (static function (): bool {
    try {
        EngineSelector::assertExclusive(false, true);
        return true;
    } catch (\Throwable) {
        return false;
    }
})());

$check('exclusive guard rejects both engines enabled', (static function (): bool {
    try {
        EngineSelector::assertExclusive(true, true);
        return false;
    } catch (\InvalidArgumentException) {
        return true;
    }
})());

fwrite(STDOUT, sprintf("\n%d tests, %d failures\n", $tests, count($failures)));
exit($failures === [] ? 0 : 1);
