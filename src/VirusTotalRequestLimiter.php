<?php

/**
 * SecureScan VirusTotal API request and quota limiter.
 *
 * All API calls are counted against the per-minute request rate. Only calls
 * that consume API quota are added to the daily quota counter. This mirrors
 * VirusTotal's distinction between quota-exempt endpoints and rate limits.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */

namespace GlpiPlugin\Securescan;

/** Coordinates VirusTotal request-rate and daily-quota accounting. */
final class VirusTotalRequestLimiter
{
    private const STATE_FILENAME = 'virustotal-quota.json';
    private const REQUESTS_PER_MINUTE = 4;
    private const REQUESTS_PER_DAY = 500;
    private const MAX_DEFER_SECONDS = 86400;

    /**
     * Reserve one API request slot.
     *
     * Quota-exempt operations still count against the per-minute request rate,
     * but do not increase the rolling daily quota counter.
     *
     * @return array{allowed:bool,error?:string,retry_after?:int}
     */
    public static function reserve(string $directory, bool $consumeDailyQuota, ?int $now = null): array
    {
        $now ??= time();
        $path = self::statePath($directory);
        if ($path === null) {
            // VirusTotal remains authoritative if local state storage is unavailable.
            return ['allowed' => true];
        }

        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return ['allowed' => true];
        }

        $locked = false;
        try {
            if (!flock($handle, LOCK_EX)) {
                return ['allowed' => true];
            }
            $locked = true;

            $state = self::readState($handle, $now);
            $blockedUntil = max(0, (int) ($state['blocked_until'] ?? 0));
            if ($blockedUntil > $now) {
                self::writeState($handle, $state);
                return [
                    'allowed' => false,
                    'error' => 'local_rate_limit',
                    'retry_after' => max(1, $blockedUntil - $now),
                ];
            }

            $requests = $state['requests'];
            $minuteRequests = array_values(array_filter(
                $requests,
                static fn (array $request): bool => $request['time'] > ($now - 60)
            ));
            if (count($minuteRequests) >= self::REQUESTS_PER_MINUTE) {
                $oldest = min(array_column($minuteRequests, 'time'));
                self::writeState($handle, $state);
                return [
                    'allowed' => false,
                    'error' => 'local_rate_limit',
                    'retry_after' => max(1, 60 - ($now - $oldest)),
                ];
            }

            $dailyRequests = array_values(array_filter(
                $requests,
                static fn (array $request): bool => $request['quota'] && $request['time'] > ($now - 86400)
            ));
            if ($consumeDailyQuota && count($dailyRequests) >= self::REQUESTS_PER_DAY) {
                $oldest = min(array_column($dailyRequests, 'time'));
                self::writeState($handle, $state);
                return [
                    'allowed' => false,
                    'error' => 'local_daily_quota',
                    'retry_after' => max(1, 86400 - ($now - $oldest)),
                ];
            }

            $state['requests'][] = [
                'time' => $now,
                'quota' => $consumeDailyQuota,
            ];
            self::writeState($handle, $state);
            return ['allowed' => true];
        } finally {
            if ($locked) {
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
    }

    /** Pause all outbound calls after VirusTotal returns HTTP 429. */
    public static function defer(string $directory, int $seconds, ?int $now = null): void
    {
        $now ??= time();
        $seconds = max(1, min(self::MAX_DEFER_SECONDS, $seconds));
        $path = self::statePath($directory);
        if ($path === null) {
            return;
        }

        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return;
        }

        $locked = false;
        try {
            if (!flock($handle, LOCK_EX)) {
                return;
            }
            $locked = true;
            $state = self::readState($handle, $now);
            $state['blocked_until'] = max((int) ($state['blocked_until'] ?? 0), $now + $seconds);
            self::writeState($handle, $state);
        } finally {
            if ($locked) {
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
    }

    private static function statePath(string $directory): ?string
    {
        if ($directory === '' || str_contains($directory, "\0") || is_link($directory)) {
            return null;
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return null;
        }
        if (is_link($directory)) {
            return null;
        }
        @chmod($directory, 0700);
        $canonicalDirectory = realpath($directory);
        if (!is_string($canonicalDirectory)) {
            return null;
        }

        $path = $canonicalDirectory . DIRECTORY_SEPARATOR . self::STATE_FILENAME;
        return is_link($path) ? null : $path;
    }

    /**
     * @param resource $handle
     * @return array{requests:array<int,array{time:int,quota:bool}>,blocked_until:int}
     */
    private static function readState($handle, int $now): array
    {
        rewind($handle);
        $contents = stream_get_contents($handle);
        if (!is_string($contents) || $contents === '' || strlen($contents) > 1048576) {
            return ['requests' => [], 'blocked_until' => 0];
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return ['requests' => [], 'blocked_until' => 0];
        }

        // Migrate the previous timestamp-list format. Those timestamps were
        // recorded only for quota-consuming calls, so preserve them as such.
        if (!array_key_exists('requests', $decoded)) {
            $legacy = [];
            foreach ($decoded as $timestamp) {
                if (is_int($timestamp) && $timestamp > ($now - 86400) && $timestamp <= ($now + 60)) {
                    $legacy[] = ['time' => $timestamp, 'quota' => true];
                }
            }
            return ['requests' => $legacy, 'blocked_until' => 0];
        }

        $requests = [];
        if (is_array($decoded['requests'])) {
            foreach ($decoded['requests'] as $request) {
                if (!is_array($request)) {
                    continue;
                }
                $timestamp = $request['time'] ?? null;
                if (!is_int($timestamp) || $timestamp <= ($now - 86400) || $timestamp > ($now + 60)) {
                    continue;
                }
                $requests[] = [
                    'time' => $timestamp,
                    'quota' => ($request['quota'] ?? false) === true,
                ];
            }
        }

        return [
            'requests' => $requests,
            'blocked_until' => max(0, (int) ($decoded['blocked_until'] ?? 0)),
        ];
    }

    /**
     * @param resource $handle
     * @param array{requests:array<int,array{time:int,quota:bool}>,blocked_until:int} $state
     */
    private static function writeState($handle, array $state): void
    {
        rewind($handle);
        if (!ftruncate($handle, 0)) {
            return;
        }
        fwrite($handle, json_encode($state, JSON_THROW_ON_ERROR));
        fflush($handle);
        $metadata = stream_get_meta_data($handle);
        $path = $metadata['uri'] ?? null;
        if (is_string($path) && $path !== '') {
            @chmod($path, 0600);
        }
    }
}
