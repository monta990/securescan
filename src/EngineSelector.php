<?php

/**
 * Resolve the single active SecureScan engine.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */

namespace GlpiPlugin\Securescan;

/**
 * SecureScan deliberately runs one antivirus provider at a time.
 */
final class EngineSelector
{
    public const DISABLED = 'disabled';
    public const CLAMAV = 'clamav';
    public const VIRUSTOTAL = 'virustotal';
    public const CONFLICT = 'conflict';

    /**
     * Reject any persisted state that attempts to enable two providers.
     */
    public static function assertExclusive(int|bool $clamavEnabled, int|bool $virusTotalEnabled): void
    {
        if ((bool) $clamavEnabled && (bool) $virusTotalEnabled) {
            throw new \InvalidArgumentException('SecureScan supports exactly one active scan engine.');
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function resolve(array $config): string
    {
        $clamavEnabled = !empty($config['securescan_enabled']);
        $virusTotalEnabled = !empty($config['securescan_virustotal_enabled']);

        if ($clamavEnabled && $virusTotalEnabled) {
            return self::CONFLICT;
        }

        if ($clamavEnabled) {
            return self::CLAMAV;
        }

        if ($virusTotalEnabled) {
            return self::VIRUSTOTAL;
        }

        return self::DISABLED;
    }
}
