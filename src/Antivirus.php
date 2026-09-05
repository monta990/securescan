<?php

namespace GlpiPlugin\Securescan;

use Session;

/**
 * Antivirus integration for uploaded GLPI documents.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 *
 * SecureScan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SecureScan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SecureScan. If not, see <https://www.gnu.org/licenses/>.
 */
final class Antivirus
{
    /**
     * Clean scans waiting for the corresponding post-add/update hook.
     *
     * PRE_ITEM_ADD/PRE_ITEM_UPDATE run before GLPI assigns the final item ID.
     * Keep the scan fingerprint in memory so the post hook can write an audit
     * entry containing the definitive Document ID without weakening the
     * pre-storage security check.
     *
     * @var array<int, array{status: string, scan_verdict: string, scan_evidence: string, exit_code: ?int, sha256: ?string, size: ?int}>
     */
    private static ?\WeakMap $pendingScans = null;

    private static function getPendingScans(): \WeakMap
    {
        return self::$pendingScans ??= new \WeakMap();
    }

    /**
     * Scan a new Document upload before Document::prepareInputForAdd().
     */
    public static function preDocumentAdd($item): void
    {
        self::scanDocumentInput($item);
    }

    /**
     * Scan a replacement Document upload before Document::prepareInputForUpdate().
     */
    public static function preDocumentUpdate($item): void
    {
        self::scanDocumentInput($item);
    }

    private static function scanDocumentInput($item): void
    {
        if (!$item instanceof \Document) {
            return;
        }

        $config = Config::getConfig();

        if (empty($config['securescan_enabled'])) {
            return;
        }

        $upload = self::extractUploadPath($item->input);

        if (!$upload['present']) {
            return;
        }

        if ($upload['path'] === null) {
            self::rejectUpload(
                $item,
                __s('SecureScan could not locate the temporary uploaded file.', 'securescan'),
                null
            );
            return;
        }

        $result = self::scan(
            $upload['path'],
            (string) $config['securescan_command'],
            false,
            (int) ($config['securescan_timeout'] ?? 30)
        );

        Audit::record('document', $result, $upload['path'], $item);

        if ($result['ok']) {
            self::getPendingScans()[$item] = [
                'status'        => (string) ($result['status'] ?? 'clean'),
                'scan_verdict'  => (string) ($result['scan_verdict'] ?? 'clean'),
                'scan_evidence' => (string) ($result['scan_evidence'] ?? 'unknown'),
                'exit_code'     => isset($result['exit_code']) ? (int) $result['exit_code'] : null,
                'sha256'        => is_file($upload['path']) ? hash_file('sha256', $upload['path']) : null,
                'size'          => is_file($upload['path']) ? filesize($upload['path']) : null,
            ];
        }

        if (!$result['ok']) {
            self::rejectUpload($item, $result['message'], $upload['path']);
        }
    }

    /**
     * Record the successful creation after GLPI has assigned the Document ID.
     */
    public static function postDocumentAdd($item): void
    {
        self::recordStoredDocument($item);
    }

    /**
     * Record the successful update after GLPI has persisted the Document.
     */
    public static function postDocumentUpdate($item): void
    {
        self::recordStoredDocument($item);
    }

    private static function recordStoredDocument($item): void
    {
        if (!$item instanceof \Document) {
            return;
        }

        $pendingScans = self::getPendingScans();
        if (!isset($pendingScans[$item])) {
            return;
        }

        $pending = $pendingScans[$item];
        unset($pendingScans[$item]);

        Audit::recordStored(
            'document_stored',
            $pending['status'],
            $pending['scan_verdict'],
            $pending['scan_evidence'],
            $pending['exit_code'],
            $pending['size'],
            $pending['sha256'],
            $item
        );
    }

    public static function test(string $command, int $timeout = 30): array
    {
        $tmp = tempnam(sys_get_temp_dir(), 'securescan_');

        if ($tmp === false) {
            return [
                'ok'      => false,
                'message' => __s('Unable to create the temporary test file.', 'securescan'),
            ];
        }

        try {
            if (file_put_contents($tmp, "SecureScan antivirus test\n") === false) {
                return [
                    'ok'      => false,
                    'message' => __s('Unable to write the temporary test file.', 'securescan'),
                ];
            }

            $result = self::scan($tmp, $command, true, $timeout);
            Audit::record('test', $result, $tmp);
            return $result;
        } finally {
            @unlink($tmp);
        }
    }

    private static function rejectUpload($item, string $message, ?string $file): void
    {
        if ($file !== null && is_file($file)) {
            @unlink($file);
        }

        // PRE_ITEM_ADD/PRE_ITEM_UPDATE: an empty input array stops the operation.
        $item->input = false;

        Session::addMessageAfterRedirect($message, false, ERROR);
    }

    /**
     * @return array{present: bool, path: ?string}
     */
    private static function extractUploadPath(array $input): array
    {
        if (!empty($input['_filename']) && is_array($input['_filename'])) {
            $filename = reset($input['_filename']);

            return [
                'present' => true,
                'path'    => is_string($filename)
                    ? self::resolveUploadPath(GLPI_TMP_DIR, $filename)
                    : null,
            ];
        }

        if (!empty($input['upload_file']) && is_string($input['upload_file'])) {
            return [
                'present' => true,
                'path'    => self::resolveUploadPath(GLPI_UPLOAD_DIR, $input['upload_file']),
            ];
        }

        return [
            'present' => false,
            'path'    => null,
        ];
    }

    private static function resolveUploadPath(string $directory, string $filename): ?string
    {
        if ($filename === '' || strpbrk($filename, '/\\') !== false) {
            return null;
        }

        $path = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . $filename;

        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        return $path;
    }

    /**
     * @return array{ok: bool, message: string, status?: string, output?: string, exit_code?: int}
     */
    private static function scan(string $file, string $template, bool $test = false, int $timeout = 30): array
    {
        if (!is_file($file) || !is_readable($file)) {
            return [
                'ok'      => false,
                'message' => __s('SecureScan could not access the temporary file.', 'securescan'),
                'status'  => 'error',
                'output'  => '',
                'exit_code' => 255,
            ];
        }

        $timeout = max(5, min(300, $timeout));
        if (!function_exists('proc_open')) {
            return [
                'ok'      => false,
                'message' => __s('SecureScan requires the PHP proc_open() function to be available.', 'securescan'),
                'status'  => 'error',
                'output'  => '',
                'exit_code' => 255,
            ];
        }

        $argv = self::buildCommandArgv($template, $file);
        if ($argv === null) {
            return [
                'ok'      => false,
                'message' => __s('The antivirus command is invalid or the executable is not a supported ClamAV scanner.', 'securescan'),
                'status'  => 'error',
                'output'  => '',
                'exit_code' => 255,
            ];
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $pipes = [];
        $process = @proc_open($argv, $descriptors, $pipes, null, null, ['suppress_errors' => true]);
        if (!is_resource($process)) {
            return [
                'ok'      => false,
                'message' => __s('SecureScan could not start the antivirus process.', 'securescan'),
                'status'  => 'error',
                'output'  => '',
                'exit_code' => 255,
            ];
        }

        if (isset($pipes[0]) && is_resource($pipes[0])) {
            fclose($pipes[0]);
        }

        foreach ([1, 2] as $pipeId) {
            if (isset($pipes[$pipeId]) && is_resource($pipes[$pipeId])) {
                stream_set_blocking($pipes[$pipeId], false);
            }
        }

        $output = '';
        $timedOut = false;
        $startedAt = microtime(true);
        $maxOutputBytes = 65536;

        while (true) {
            $status = proc_get_status($process);
            $running = (bool) ($status['running'] ?? false);

            foreach ([1, 2] as $pipeId) {
                if (!isset($pipes[$pipeId]) || !is_resource($pipes[$pipeId])) {
                    continue;
                }
                $chunk = stream_get_contents($pipes[$pipeId]);
                if ($chunk !== false && $chunk !== '') {
                    $remaining = $maxOutputBytes - strlen($output);
                    if ($remaining > 0) {
                        $output .= substr($chunk, 0, $remaining);
                    }
                }
            }

            if (!$running) {
                $exitCode = (int) ($status['exitcode'] ?? -1);
                if ($exitCode < 0) {
                    $exitCode = (int) proc_close($process);
                } else {
                    proc_close($process);
                }
                break;
            }

            if ((microtime(true) - $startedAt) >= $timeout) {
                $timedOut = true;
                @proc_terminate($process, 15);
                usleep(250000);
                $status = proc_get_status($process);
                if (($status['running'] ?? false) === true) {
                    @proc_terminate($process, 9);
                }
                $exitCode = 124;
                proc_close($process);
                break;
            }

            $read = [];
            foreach ([1, 2] as $pipeId) {
                if (isset($pipes[$pipeId]) && is_resource($pipes[$pipeId])) {
                    $read[] = $pipes[$pipeId];
                }
            }
            if ($read !== []) {
                $write = null;
                $except = null;
                @stream_select($read, $write, $except, 0, 100000);
            } else {
                usleep(100000);
            }
        }

        foreach ([1, 2] as $pipeId) {
            if (isset($pipes[$pipeId]) && is_resource($pipes[$pipeId])) {
                $chunk = stream_get_contents($pipes[$pipeId]);
                if ($chunk !== false && $chunk !== '') {
                    $remaining = $maxOutputBytes - strlen($output);
                    if ($remaining > 0) {
                        $output .= substr($chunk, 0, $remaining);
                    }
                }
                fclose($pipes[$pipeId]);
            }
        }

        if ($timedOut) {
            return [
                'ok' => false,
                'message' => sprintf(__s('The antivirus scan exceeded the configured timeout of %d seconds. The file was rejected.', 'securescan'), $timeout),
                'status' => 'error',
                'output' => $output,
                'exit_code' => $exitCode,
            ];
        }

        // ClamAV convention: 0 = no threat reported, 1 = infected, 2+ = scan error.
        // Exit code 0 is not sufficient evidence of a completed scan: ClamAV may
        // skip a file because of size/recursion limits while still returning 0.
        $evidence = self::analyzeScanOutput($output, $file, $exitCode);

        if ($exitCode === 0) {
            if ($evidence['verdict'] === 'clean') {
                return [
                    'ok'            => true,
                    'message'       => $test
                        ? __s('The antivirus responded successfully and the test file is clean.', 'securescan')
                        : '',
                    'status'        => 'clean',
                    'scan_verdict'  => 'clean',
                    'scan_evidence' => $evidence['evidence'],
                    'output'        => $output,
                    'exit_code'     => $exitCode,
                ];
            }

            return [
                'ok'            => false,
                'message'       => __s('SecureScan could not confirm that the antivirus scanned the file. The file was rejected.', 'securescan'),
                'status'        => 'error',
                'scan_verdict'  => $evidence['verdict'],
                'scan_evidence' => $evidence['evidence'],
                'output'        => $output,
                'exit_code'     => $exitCode,
            ];
        }

        if ($exitCode === 1) {
            return [
                'ok'            => false,
                'message'       => __s('The antivirus detected a threat. The file was rejected.', 'securescan'),
                'status'        => 'infected',
                'scan_verdict'  => 'infected',
                'scan_evidence' => $evidence['evidence'],
                'output'        => $output,
                'exit_code'     => $exitCode,
            ];
        }

        return [
            'ok'            => false,
            'message'       => sprintf(
                __s('SecureScan could not complete the antivirus scan (code %d). The file was rejected.', 'securescan'),
                $exitCode
            ),
            'status'        => 'error',
            'scan_verdict'  => 'error',
            'scan_evidence' => $evidence['evidence'],
            'output'        => $output,
            'exit_code'     => $exitCode,
        ];
    }

    /**
     * Derive a positive, target-specific scan verdict from ClamAV output.
     *
     * Exit code 0 is accepted only when ClamAV explicitly reports the uploaded
     * file as OK. Skip/limit/error indicators take precedence and an ambiguous
     * response fails closed. The raw scanner output remains bounded in scan().
     *
     * @return array{verdict: string, evidence: string}
     */
    private static function analyzeScanOutput(string $output, string $file, int $exitCode): array
    {
        $lines = preg_split('/\R/', $output) ?: [];
        $target = rtrim($file);
        $targetBase = basename($file);

        $skipPatterns = [
            'size_limit_reached' => '/(?:size limit reached|max(?:imum)?[ -]?(?:file|scan) size|maxfilesize|maxscansize|scan limit)/i',
            'cannot_open' => '/(?:can\'t|cannot|unable to)\s+(?:open|access|read|scan)\b/i',
            'excluded' => '/\b(?:excluded|skipped|not scanned)\b/i',
            'symbolic_link' => '/\bsymbolic link\b/i',
        ];

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            foreach ($skipPatterns as $evidence => $pattern) {
                if (preg_match($pattern, $line) === 1) {
                    return [
                        'verdict'  => 'not_scanned',
                        'evidence' => $evidence,
                    ];
                }
            }
        }

        $targetOk = false;
        $targetFound = false;

        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }

            if (preg_match('/^(.*?)\s*:\s*OK$/i', $line, $matches) === 1) {
                $reportedTarget = trim($matches[1], " \t\"'");
                if ($reportedTarget === $target || basename($reportedTarget) === $targetBase) {
                    $targetOk = true;
                    continue;
                }
            }

            if (preg_match('/^(.*?)\s*:\s*.*\bFOUND$/i', $line, $matches) === 1) {
                $reportedTarget = trim($matches[1], " \t\"'");
                if ($reportedTarget === $target || basename($reportedTarget) === $targetBase) {
                    $targetFound = true;
                }
            }
        }

        if ($exitCode === 1) {
            return [
                'verdict'  => 'infected',
                'evidence' => $targetFound ? 'target_found' : 'exit_code_infected',
            ];
        }

        if ($exitCode === 0 && $targetFound) {
            return [
                'verdict'  => 'unknown',
                'evidence' => 'contradictory_output',
            ];
        }

        if ($exitCode === 0 && $targetOk) {
            return [
                'verdict'  => 'clean',
                'evidence' => 'target_ok',
            ];
        }

        return [
            'verdict'  => 'unknown',
            'evidence' => 'no_positive_scan_evidence',
        ];
    }

    /**
     * Convert the administrator's ClamAV command line into a direct argv array.
     * No shell is used; the executable is resolved only from fixed system
     * directories when a basename is configured.
     */
    private static function buildCommandArgv(string $template, string $file): ?array
    {
        $tokens = self::tokenizeCommand($template);
        if ($tokens === null || $tokens === [] || count(array_keys($tokens, '{file}', true)) !== 1) {
            return null;
        }

        $filePositions = array_keys($tokens, '{file}', true);
        if (count($filePositions) !== 1) {
            return null;
        }

        $tokens[$filePositions[0]] = $file;
        $executable = $tokens[0] ?? '';
        if ($executable === '' || $executable === '{file}') {
            return null;
        }

        $allowlist = ['clamdscan', 'clamscan'];
        if (!self::isExecutableAllowed($executable, $allowlist)) {
            return null;
        }

        $resolved = self::resolveExecutablePath($executable);
        if ($resolved === null) {
            return null;
        }

        $tokens[0] = $resolved;
        return $tokens;
    }

    public static function getTestedConfigurationHash(string $command): string
    {
        return hash('sha256', $command);
    }

    public static function validateCommand(string $command): ?string
    {
        if (self::buildCommandArgv($command, '/dev/null') === null) {
            return __s('The antivirus command is invalid or the executable is not a supported ClamAV scanner.', 'securescan');
        }
        return null;
    }

    private static function isExecutableAllowed(string $executable, array $allowlist): bool
    {
        if (preg_match('/^(?:[A-Za-z]:[\\/]|\\/)/', $executable) === 1) {
            $resolved = realpath($executable);
            if ($resolved === false || !is_file($resolved) || !is_executable($resolved)) {
                return false;
            }

            if (!in_array(basename($resolved), $allowlist, true)) {
                return false;
            }

            foreach (self::getExecutableDirectories() as $directory) {
                $allowedDirectory = realpath($directory);
                if ($allowedDirectory !== false && rtrim(dirname($resolved), '/\\') === rtrim($allowedDirectory, '/\\')) {
                    return true;
                }
            }

            return false;
        }

        return in_array($executable, $allowlist, true);
    }

    /**
     * Tokenize a command line without interpreting shell operators.
     * Single and double quotes group characters. Backslashes are treated as
     * literal characters because no shell parser is used.
     */
    private static function tokenizeCommand(string $template): ?array
    {
        if ($template === '' || strpbrk($template, "\0\r\n;&|`$<>#") !== false) {
            return null;
        }

        $tokens = [];
        $token = '';
        $quote = null;
        $length = strlen($template);
        $inToken = false;

        for ($i = 0; $i < $length; $i++) {
            $char = $template[$i];
            if ($quote !== null) {
                if ($char === $quote) {
                    $quote = null;
                    $inToken = true;
                    continue;
                }
                $token .= $char;
                $inToken = true;
                continue;
            }

            if ($char === "'" || $char === '"') {
                $quote = $char;
                $inToken = true;
                continue;
            }

            if (ctype_space($char)) {
                if ($inToken) {
                    $tokens[] = $token;
                    $token = '';
                    $inToken = false;
                }
                continue;
            }

            $token .= $char;
            $inToken = true;
        }

        if ($quote !== null) {
            return null;
        }
        if ($inToken) {
            $tokens[] = $token;
        }

        if (count($tokens) === 0 || count(array_keys($tokens, '{file}', true)) !== 1) {
            return null;
        }

        return $tokens;
    }

    /**
     * Resolve an executable basename only from fixed system directories.
     * This avoids trusting the inherited PATH. Absolute paths are accepted
     * when they point to a regular executable file.
     */
    private static function resolveExecutablePath(string $executable): ?string
    {
        $directories = self::getExecutableDirectories();

        if (preg_match('~^(?:[A-Za-z]:[\\/]|/)~', $executable) === 1) {
            $resolved = realpath($executable);
            if ($resolved === false || !is_file($resolved) || !is_executable($resolved)) {
                return null;
            }

            $resolvedDirectory = rtrim(dirname($resolved), '/\\');
            foreach ($directories as $directory) {
                $allowedDirectory = realpath($directory);
                if ($allowedDirectory !== false && $resolvedDirectory === rtrim($allowedDirectory, '/\\')) {
                    return $resolved;
                }
            }

            return null;
        }

        if (preg_match('/^[A-Za-z0-9._-]+$/', $executable) !== 1) {
            return null;
        }

        foreach ($directories as $directory) {
            $candidate = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . $executable;
            $resolved = realpath($candidate);
            $allowedDirectory = realpath($directory);
            if (
                $resolved !== false
                && is_file($resolved)
                && is_executable($resolved)
                && $allowedDirectory !== false
                && rtrim(dirname($resolved), '/\\') === rtrim($allowedDirectory, '/\\')
            ) {
                return $resolved;
            }
        }

        return null;
    }

    /**
     * Fixed directories from which ClamAV executables may be resolved.
     * PHP_BINDIR is included because packaged PHP installations may keep
     * administrator-approved scanner helpers alongside the PHP binary.
     */
    private static function getExecutableDirectories(): array
    {
        $directories = ['/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin'];
        if (defined('PHP_BINDIR')) {
            $directories[] = PHP_BINDIR;
        }

        return array_unique($directories);
    }

}
