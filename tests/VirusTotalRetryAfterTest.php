<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/VirusTotal.php';

use GlpiPlugin\Securescan\VirusTotal;

$method = new ReflectionMethod(VirusTotal::class, 'parseRetryAfterHeader');
$method->setAccessible(true);
$parse = static fn (?string $value): ?int => $method->invoke(null, $value);

$checks = [
    'delta-seconds are parsed' => $parse('30') === 30,
    'empty header is ignored' => $parse(null) === null,
    'invalid header is ignored' => $parse('not-a-delay') === null,
    'zero delay is clamped to one second' => $parse('0') === 1,
    'excessive delay is clamped to ten minutes' => $parse('9999') === 600,
    'HTTP-date header is parsed' => $parse(gmdate('D, d M Y H:i:s', time() + 45) . ' GMT') >= 1,
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
