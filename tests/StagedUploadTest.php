<?php

declare(strict_types=1);

namespace Glpi\Controller {
    abstract class AbstractController
    {
    }
}

namespace {
    $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'securescan-stage-' . bin2hex(random_bytes(8));
    $tmp = $base . DIRECTORY_SEPARATOR . 'tmp';
    $uploads = $base . DIRECTORY_SEPARATOR . 'uploads';
    $pluginDocs = $base . DIRECTORY_SEPARATOR . 'plugin-docs';
    mkdir($tmp, 0700, true);
    mkdir($uploads, 0700, true);
    mkdir($pluginDocs, 0700, true);

    define('GLPI_TMP_DIR', $tmp);
    define('GLPI_UPLOAD_DIR', $uploads);
    define('GLPI_PLUGIN_DOC_DIR', $pluginDocs);

    require_once __DIR__ . '/../src/Controller/VirusTotalScanController.php';

    $class = 'GlpiPlugin\\Securescan\\Controller\\VirusTotalScanController';
    $invoke = static function (string $method, array $args = []) use ($class): mixed {
        $reflection = new ReflectionMethod($class, $method);
        $reflection->setAccessible(true);
        return $reflection->invokeArgs(null, $args);
    };
    $checks = 0;
    $failures = [];
    $check = static function (string $label, bool $condition) use (&$checks, &$failures): void {
        $checks++;
        if (!$condition) {
            $failures[] = $label;
            fwrite(STDERR, "FAIL: {$label}\n");
        } else {
            fwrite(STDOUT, "PASS: {$label}\n");
        }
    };

    $filename = '01234567890123456789012credenciales temporales ñ (2).csv';
    $contents = str_repeat("x", 205);
    $source = $tmp . DIRECTORY_SEPARATOR . $filename;
    file_put_contents($source, $contents);
    $hash = hash('sha256', $contents);

    $check('205-byte file with spaces and accents in its GLPI staged name is accepted', $invoke('isSafeStagedFilename', [$filename]) === true);
    $check('Path traversal is rejected', $invoke('isSafeStagedFilename', ['../outside.csv']) === false);
    $check('Windows path separators are rejected', $invoke('isSafeStagedFilename', ['..\\outside.csv']) === false);
    $check('Control characters are rejected', $invoke('isSafeStagedFilename', ["bad\nname.csv"]) === false);
    $check('Unicode staged basename resolves inside GLPI temporary directory', $invoke('resolveStagedFile', ['tmp', $filename]) === realpath($source));

    $serverFilename = 'small 205 bytes (ñ).csv';
    $serverSource = $uploads . DIRECTORY_SEPARATOR . $serverFilename;
    file_put_contents($serverSource, $contents);
    $check('205-byte server-upload file with spaces and Unicode is accepted', $invoke('isSafeStagedFilename', [$serverFilename]) === true);
    $check('Server-upload selector resolves inside GLPI upload directory', $invoke('resolveStagedFile', ['upload', $serverFilename]) === realpath($serverSource));

    $job = [
        'analysis_id' => 'test-analysis-id-123',
        'sha256' => $hash,
        'filename' => $filename,
        'source' => 'tmp',
        'user_id' => 9,
        'created_at' => time(),
    ];
    $token = $invoke('createJob', [$job, $source]);
    $check('Pending job copies the staged file into private job storage', is_string($token) && preg_match('/^[a-f0-9]{48}$/D', $token) === 1);
    $duplicateToken = $invoke('createJob', [$job, $source]);
    $check('Identical pending job reuses the existing private copy and token', is_string($token) && $duplicateToken === $token);

    if (is_string($token)) {
        $quarantine = $invoke('resolveJobFile', [$token]);
        $check('Private quarantine copy exists and matches the expected SHA-256', is_string($quarantine) && hash_file('sha256', $quarantine) === $hash);

        unlink($source);
        $restored = $invoke('restoreStagedFile', ['tmp', $filename, $quarantine, $hash, $token]);
        $check('Clean result can restore the same GLPI staged basename from quarantine', is_string($restored) && is_file($restored) && hash_file('sha256', $restored) === $hash);

        $job['quarantine_file'] = $token . '.bin';
        $job['completed_result'] = ['status' => 'clean', 'sha256' => $hash];
        $check('Completed analysis result can be persisted for retry without polling again', $invoke('writeJob', [$token, $job]) === true);
        $readJob = $invoke('readJob', [$token]);
        $check('Persisted job retains completed verdict', is_array($readJob) && ($readJob['completed_result']['status'] ?? '') === 'clean');
        $invoke('deleteJob', [$token]);
        $check('Job cleanup removes metadata and quarantined file', !file_exists($pluginDocs . '/securescan/virustotal-jobs/' . $token . '.json') && !file_exists($pluginDocs . '/securescan/virustotal-jobs/' . $token . '.bin'));
    }

    @unlink($source);
    @unlink($serverSource);
    $removeTree = static function (string $directory) use (&$removeTree): void {
        if (!is_dir($directory)) return;
        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            $path = $directory . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($path) && !is_link($path)) $removeTree($path);
            else @unlink($path);
        }
        @rmdir($directory);
    };
    $removeTree($base);

    fwrite(STDOUT, sprintf("\n%d tests, %d failures\n", $checks, count($failures)));
    exit($failures === [] ? 0 : 1);
}
