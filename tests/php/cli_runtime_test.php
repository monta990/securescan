<?php
declare(strict_types=1);
$expectedMinor = getenv('SECURESCAN_EXPECTED_PHP_MINOR');
if (!is_string($expectedMinor) || !preg_match('/^8\.(2|3|4|5|6)$/', $expectedMinor)) {
    fwrite(STDERR, "SECURESCAN_EXPECTED_PHP_MINOR must be one of 8.2, 8.3, 8.4, 8.5 or 8.6.\n"); exit(2);
}
$actualMinor = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
if ($actualMinor !== $expectedMinor) { fwrite(STDERR, sprintf("Expected PHP %s CLI, got %s.\n", $expectedMinor, PHP_VERSION)); exit(1); }
if (PHP_VERSION_ID < 80200) { fwrite(STDERR, sprintf("SecureScan requires PHP 8.2 or newer; got %s.\n", PHP_VERSION)); exit(1); }
$missing = array_values(array_filter(['json', 'openssl'], static fn(string $extension): bool => !extension_loaded($extension)));
if ($missing !== []) { fwrite(STDERR, 'Missing required CLI extensions: ' . implode(', ', $missing) . "\n"); exit(1); }
fwrite(STDOUT, sprintf("PASS: PHP CLI runtime %s satisfies the SecureScan %s matrix leg.\n", PHP_VERSION, $expectedMinor));
