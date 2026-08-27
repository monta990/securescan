<?php

/**
 * SecureScan
 * Copyright (C) 2026 Edwin Elias Alvarez
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

namespace GlpiPlugin\Securescan;

use Throwable;

/**
 * Checks the latest published stable SecureScan release on GitHub.
 */
final class VersionChecker
{
    private const REPOSITORY = 'monta990/securescan';
    private const API_URL = 'https://api.github.com/repos/monta990/securescan/releases?per_page=20';
    private const RELEASES_URL = 'https://github.com/monta990/securescan/releases';
    private const CACHE_TTL = 21600;
    private const MAX_RESPONSE_BYTES = 65536;
    private const CONNECT_TIMEOUT = 3;
    private const TOTAL_TIMEOUT = 5;

    public static function check(): array
    {
        $installed = defined('PLUGIN_SECURESCAN_VERSION') ? PLUGIN_SECURESCAN_VERSION : '0.0.0';
        $cache = self::readCache();

        if ($cache !== null && (time() - $cache['checked_at']) < self::CACHE_TTL) {
            return self::buildResult($installed, $cache['latest_version'], $cache['release_url'], 'cached');
        }

        try {
            $release = self::fetchLatestStableRelease();
            if ($release !== null) {
                self::writeCache($release['version'], $release['release_url']);
                return self::buildResult($installed, $release['version'], $release['release_url'], 'online');
            }
        } catch (Throwable $e) {
            if (class_exists('Toolbox') && method_exists('Toolbox', 'logInFile')) {
                \Toolbox::logInFile('securescan', 'GitHub version check failed: ' . $e->getMessage());
            }
        }

        if ($cache !== null) {
            return self::buildResult($installed, $cache['latest_version'], $cache['release_url'], 'stale');
        }

        return [
            'installed_version' => $installed,
            'latest_version' => null,
            'update_available' => false,
            'release_url' => self::RELEASES_URL,
            'status' => 'unavailable',
        ];
    }

    private static function fetchLatestStableRelease(): ?array
    {
        if (!extension_loaded('curl')) {
            return null;
        }

        $ch = curl_init(self::API_URL);
        if ($ch === false) {
            return null;
        }

        $body = '';
        $tooLarge = false;

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => self::TOTAL_TIMEOUT,
            CURLOPT_HTTPHEADER => [
                'Accept: application/vnd.github+json',
                'User-Agent: SecureScan/' . (defined('PLUGIN_SECURESCAN_VERSION') ? PLUGIN_SECURESCAN_VERSION : 'unknown'),
            ],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$tooLarge): int {
                $remaining = self::MAX_RESPONSE_BYTES - strlen($body);
                if ($remaining <= 0) {
                    $tooLarge = true;
                    return 0;
                }

                if (strlen($chunk) > $remaining) {
                    $body .= substr($chunk, 0, $remaining);
                    $tooLarge = true;
                    return 0;
                }

                $body .= $chunk;
                return strlen($chunk);
            },
        ]);

        $success = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($tooLarge || $httpCode !== 200 || $body === '') {
            return null;
        }

        if ($success === false && $error !== '') {
            throw new \RuntimeException($error);
        }

        try {
            $releases = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (!is_array($releases)) {
            return null;
        }

        $latest = null;
        foreach ($releases as $release) {
            if (!is_array($release)) {
                continue;
            }
            if (($release['draft'] ?? true) || ($release['prerelease'] ?? true)) {
                continue;
            }

            $tag = isset($release['tag_name']) && is_string($release['tag_name'])
                ? trim($release['tag_name'])
                : '';
            $version = self::normalizeVersion($tag);
            if ($version === null) {
                continue;
            }

            if ($latest === null || version_compare($version, $latest['version'], '>')) {
                $latest = [
                    'version' => $version,
                    'release_url' => self::safeReleaseUrl($release['html_url'] ?? ''),
                ];
            }
        }

        return $latest;
    }

    private static function normalizeVersion(string $tag): ?string
    {
        if (preg_match('/^v?(\d+\.\d+\.\d+)$/', $tag, $matches) !== 1) {
            return null;
        }
        return $matches[1];
    }

    private static function safeReleaseUrl(string $url): string
    {
        if (preg_match('#^https://github\.com/' . preg_quote(self::REPOSITORY, '#') . '/releases/tag/v?\d+\.\d+\.\d+$#', $url) === 1) {
            return $url;
        }
        return self::RELEASES_URL;
    }

    private static function buildResult(string $installed, string $latest, string $releaseUrl, string $source): array
    {
        $updateAvailable = version_compare($latest, $installed, '>');

        return [
            'installed_version' => $installed,
            'latest_version' => $latest,
            'update_available' => $updateAvailable,
            'release_url' => $releaseUrl,
            'status' => $updateAvailable ? 'update_available' : ($source === 'stale' ? 'stale' : 'up_to_date'),
        ];
    }

    private static function cachePath(): string
    {
        return rtrim(GLPI_PLUGIN_DOC_DIR, '/\\') . '/securescan/github-version.json';
    }

    private static function readCache(): ?array
    {
        $path = self::cachePath();
        if (!is_readable($path)) {
            return null;
        }

        $data = file_get_contents($path);
        if ($data === false || strlen($data) > 4096) {
            return null;
        }

        try {
            $cache = json_decode($data, true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (!is_array($cache)) {
            return null;
        }

        $version = isset($cache['latest_version']) && is_string($cache['latest_version'])
            ? self::normalizeVersion($cache['latest_version'])
            : null;
        $checkedAt = $cache['checked_at'] ?? null;
        $url = isset($cache['release_url']) && is_string($cache['release_url'])
            ? self::safeReleaseUrl($cache['release_url'])
            : self::RELEASES_URL;

        if ($version === null || !is_int($checkedAt) || $checkedAt <= 0) {
            return null;
        }

        return [
            'latest_version' => $version,
            'checked_at' => $checkedAt,
            'release_url' => $url,
        ];
    }

    private static function writeCache(string $latestVersion, string $releaseUrl): void
    {
        $path = self::cachePath();
        $dir = dirname($path);

        if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
            return;
        }

        $payload = json_encode([
            'checked_at' => time(),
            'latest_version' => $latestVersion,
            'release_url' => self::safeReleaseUrl($releaseUrl),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
        if (file_put_contents($tmp, $payload, LOCK_EX) === false) {
            @unlink($tmp);
            return;
        }

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
        }
    }
}
