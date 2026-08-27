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
    private static array $pendingScans = [];

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

        $result = self::scan($upload['path'], (string) $config['securescan_command']);

        Audit::record('document', $result, $upload['path'], $item);

        if ($result['ok']) {
            self::$pendingScans[spl_object_id($item)] = [
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

        $key = spl_object_id($item);
        if (!isset(self::$pendingScans[$key])) {
            return;
        }

        $pending = self::$pendingScans[$key];
        unset(self::$pendingScans[$key]);

        Audit::recordStored(
            'document_stored',
            $pending['status'],
            $pending['size'],
            $pending['sha256'],
            $item
        );
    }

    public static function test(string $command): array
    {
        $tmp = tempnam(sys_get_temp_dir(), 'securescan_');

        if ($tmp === false) {
            return [
                'ok'      => false,
                'message' => __('Unable to create the temporary test file.', 'securescan'),
            ];
        }

        try {
            if (file_put_contents($tmp, "SecureScan antivirus test\n") === false) {
                return [
                    'ok'      => false,
                    'message' => __('Unable to write the temporary test file.', 'securescan'),
                ];
            }

            $result = self::scan($tmp, $command, true);
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
        $item->input = [];

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
    private static function scan(string $file, string $template, bool $test = false): array
    {
        if (!is_file($file) || !is_readable($file)) {
            return [
                'ok'      => false,
                'message' => __('SecureScan could not access the temporary file.', 'securescan'),
            ];
        }

        if (!function_exists('exec')) {
            return [
                'ok'      => false,
                'message' => __('SecureScan requires the PHP exec() function to be available.', 'securescan'),
            ];
        }

        if (strpos($template, '{file}') === false) {
            return [
                'ok'      => false,
                'message' => __('The antivirus command must contain the {file} placeholder.', 'securescan'),
            ];
        }

        if (!self::isSafeTemplate($template)) {
            return [
                'ok'      => false,
                'message' => __('The command contains forbidden characters or operators.', 'securescan'),
            ];
        }

        $resolvedTemplate = self::resolveExecutable($template);
        if ($resolvedTemplate === null) {
            return [
                'ok'      => false,
                'message' => __('SecureScan could not find the antivirus executable for the PHP process. Verify the command path and the web server/PHP user permissions.', 'securescan'),
                'status'  => 'error',
                'output'  => '',
                'exit_code' => 255,
            ];
        }

        $command = str_replace(
            '{file}',
            escapeshellarg($file),
            $resolvedTemplate
        );

        $output = [];
        $exitCode = 255;

        exec($command . ' 2>&1', $output, $exitCode);

        // ClamAV convention: 0 = clean, 1 = infected, 2+ = scan error.
        if ($exitCode === 0) {
            return [
                'ok'      => true,
                'message' => $test
                    ? __('The antivirus responded successfully and the test file is clean.', 'securescan')
                    : '',
                'status'  => 'clean',
                'output'  => implode("\n", $output),
                'exit_code' => $exitCode,
            ];
        }

        if ($exitCode === 1) {
            return [
                'ok'      => false,
                'message' => __('The antivirus detected a threat. The file was rejected.', 'securescan'),
                'status'  => 'infected',
                'output'  => implode("\n", $output),
                'exit_code' => $exitCode,
            ];
        }

        return [
            'ok'      => false,
            'message' => sprintf(
                __('SecureScan could not complete the antivirus scan (code %d). The file was rejected.', 'securescan'),
                $exitCode
            ),
            'status'  => 'error',
            'output'  => implode("\n", $output),
            'exit_code' => $exitCode,
        ];
    }

    /**
     * Resolve the executable independently of the restricted PATH commonly
     * inherited by PHP-FPM/Apache. The configured command itself remains
     * unchanged in GLPI; only the executable used for this invocation is
     * converted to an absolute path when it can be found.
     */
    private static function resolveExecutable(string $template): ?string
    {
        if (!preg_match('/^\s*(\S+)(.*)$/s', $template, $matches)) {
            return null;
        }

        $executable = $matches[1];
        $arguments = $matches[2];

        if ($executable === '') {
            return null;
        }

        if (str_contains($executable, '/') || str_contains($executable, '\\')) {
            return is_executable($executable) ? $executable . $arguments : null;
        }

        $path = getenv('PATH') ?: '';
        $searchPaths = array_filter(explode(PATH_SEPARATOR, $path));
        foreach (['/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin'] as $candidate) {
            if (!in_array($candidate, $searchPaths, true)) {
                $searchPaths[] = $candidate;
            }
        }

        foreach ($searchPaths as $directory) {
            $candidate = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . $executable;
            if (is_executable($candidate) && is_file($candidate)) {
                return $candidate . $arguments;
            }
        }

        return null;
    }

    private static function isSafeTemplate(string $template): bool
    {
        if (preg_match('/[;&|`$<>#\x00\r\n]/', $template)) {
            return false;
        }

        if (preg_match('/\b(?:rm|mv|cp|del|erase|format|powershell|pwsh|cmd|sh|bash)\b/i', $template)) {
            return false;
        }

        return substr_count($template, '{file}') === 1;
    }
}
