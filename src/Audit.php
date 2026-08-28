<?php

namespace GlpiPlugin\Securescan;

/**
 * SecureScan audit logging.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */
final class Audit
{
    /**
     * Record a scan without storing file contents or sensitive command output.
     */
    public static function record(string $type, array $result, string $file, ?object $item = null): void
    {
        $record = [
            'time'       => date('c'),
            'type'       => $type,
            'status'     => $result['status'] ?? ($result['ok'] ? 'clean' : 'error'),
            'exit_code'  => $result['exit_code'] ?? null,
            'size'       => is_file($file) ? filesize($file) : null,
            'sha256'     => is_file($file) ? hash_file('sha256', $file) : null,
            'temporary'  => is_file($file) ? basename($file) : null,
            'itemtype'   => $item !== null ? $item::class : null,
            'items_id'   => self::getItemId($item),
            'user_id'    => class_exists('Session') ? (int) \Session::getLoginUserID() : 0,
        ];

        self::write($record);
    }

    /**
     * Record the successful persistence of a scanned document.
     * This is intentionally separate from the pre-add/pre-update scan record
     * because GLPI does not assign the final item ID until after the pre hook.
     */
    public static function recordStored(
        string $type,
        string $status,
        ?int $size,
        ?string $sha256,
        ?object $item = null
    ): void {
        $record = [
            'time'       => date('c'),
            'type'       => $type,
            'status'     => $status,
            'exit_code'  => 0,
            'size'       => $size,
            'sha256'     => $sha256,
            'temporary'  => null,
            'itemtype'   => $item !== null ? $item::class : null,
            'items_id'   => self::getItemId($item),
            'user_id'    => class_exists('Session') ? (int) \Session::getLoginUserID() : 0,
        ];

        self::write($record);
        self::writeDocumentHistory($status, $sha256, $item);
    }

    /**
     * Add the successful scan result to the native GLPI history of the
     * document. This keeps the audit visible from the document's
     * Histórico tab while the detailed JSON evidence remains in
     * files/_log/securescan.log.
     */
    private static function writeDocumentHistory(string $status, ?string $sha256, ?object $item): void
    {
        if ($item === null || !method_exists($item, 'getID')) {
            return;
        }

        $itemsId = (int) $item->getID();
        if ($itemsId <= 0) {
            return;
        }

        $message = $status === 'clean'
            ? sprintf(
                __('SecureScan: file scanned successfully and stored. Result: clean. SHA-256: %s', 'securescan'),
                $sha256 ?? 'N/A'
            )
            : sprintf(
                __('SecureScan: file scanned and stored. Result: %s. SHA-256: %s', 'securescan'),
                $status,
                $sha256 ?? 'N/A'
            );

        // GLPI's native history API uses search option 0 plus the
        // HISTORY_LOG_SIMPLE_MESSAGE action for free-form audit messages.
        try {
            \Log::history(
                $itemsId,
                $item::class,
                [0, '', $message],
                0,
                \Log::HISTORY_LOG_SIMPLE_MESSAGE
            );
        } catch (\Throwable $e) {
            // A history-entry failure must never invalidate an already
            // stored clean document. The detailed SecureScan log remains
            // the fallback evidence.
            \Toolbox::logDebug($e);
        }
    }

    private static function getItemId(?object $item): int
    {
        if ($item === null || !isset($item->fields['id'])) {
            return 0;
        }

        return (int) $item->fields['id'];
    }

    private static function write(array $record): void
    {
        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json !== false) {
            \Toolbox::logInFile('securescan', $json . PHP_EOL, true);
        }
    }
}
