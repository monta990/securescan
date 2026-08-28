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
     * @var array<int, array{status: string, sha256: ?string, size: ?int}>
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
                __('SecureScan could not locate the temporary uploaded file.', 'securescan'),
                null
            );
            return;
        }

        $result = self::scan(
            $upload['path'],
            (string) $config['securescan_command'],
            false,
            (int) ($config['securescan_timeout'] ?? 30),
            (string) ($config['securescan_allowed_executables'] ?? 'clamdscan')
        );

        Audit::record('document', $result, $upload['path'], $item);

        if ($result['ok']) {
            self::getPendingScans()[$item] = [
                'status' => (string) ($result['status'] ?? 'clean'),
                'sha256' => is_file($upload['path']) ? hash_file('sha256', $upload['path']) : null,
                'size'   => is_file($upload['path']) ? filesize($upload['path']) : null,
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
            $pending['size'],
            $pending['sha256'],
            $item
        );
    }

    public static function test(string $command, int $timeout = 30, string $allowedExecutables = 'clamdscan'): array
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

            $result = self::scan($tmp, $command, true, $timeout, $allowedExecutables);
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
    private static function scan(string $file, string $template, bool $test = false, int $timeout = 30, string $allowedExecutables = 'clamdscan'): array
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

        $argv = self::buildCommandArgv($template, $file, $allowedExecutables);
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

        // ClamAV convention: 0 = clean, 1 = infected, 2+ = scan error.
        if ($exitCode === 0) {
            return [
                'ok'      => true,
                'message' => $test
                    ? __s('The antivirus responded successfully and the test file is clean.', 'securescan')
                    : '',
                'status'  => 'clean',
                'output'  => $output,
                'exit_code' => $exitCode,
            ];
        }

        if ($exitCode === 1) {
            return [
                'ok'      => false,
                'message' => __s('The antivirus detected a threat. The file was rejected.', 'securescan'),
                'status'  => 'infected',
                'output'  => $output,
                'exit_code' => $exitCode,
            ];
        }

        return [
            'ok'      => false,
            'message' => sprintf(
                __s('SecureScan could not complete the antivirus scan (code %d). The file was rejected.', 'securescan'),
                $exitCode
            ),
            'status'  => 'error',
            'output'  => $output,
            'exit_code' => $exitCode,
        ];
    }

    /**
     * Convert the administrator's ClamAV command line into a direct argv array.
     * No shell is used; the executable is resolved only from fixed system
     * directories when a basename is configured.
     */
    private static function buildCommandArgv(string $template, string $file, string $allowedExecutables): ?array
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

    public static function getTestedConfigurationHash(string $command, string $allowedExecutables): string
    {
        return hash('sha256', $command . "\0" . $allowedExecutables);
    }

    public static function validateCommand(string $command, string $allowedExecutables): ?string
    {
        if (self::buildCommandArgv($command, '/dev/null', $allowedExecutables) === null) {
            return __s('The antivirus command is invalid or the executable is not a supported ClamAV scanner.', 'securescan');
        }
        return null;
    }

    private static function isExecutableAllowed(string $executable, array $allowlist): bool
    {
        if (preg_match('/^(?:[A-Za-z]:[\\/]|\/)/', $executable) === 1) {
            return in_array(basename($executable), $allowlist, true);
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
        if (preg_match('~^(?:[A-Za-z]:[\\/]|/)~', $executable) === 1) {
            return is_file($executable) && is_executable($executable) ? $executable : null;
        }

        if (preg_match('/^[A-Za-z0-9._-]+$/', $executable) !== 1) {
            return null;
        }

        $directories = ['/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin'];
        if (defined('PHP_BINDIR')) {
            $directories[] = PHP_BINDIR;
        }

        foreach (array_unique($directories) as $directory) {
            $candidate = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . $executable;
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

}
