<?php

/**
 * SecureScan
 * Copyright (C) 2026 Edwin Elias Alvarez
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use Glpi\Cache\CacheManager;

function plugin_securescan_install(): bool
{
    $current = \Config::getConfigurationValues('plugin:securescan');

    $defaults = [
        'securescan_enabled' => 0,
        'securescan_command' => 'clamdscan --no-summary {file}',
        'securescan_tested_hash' => '',
    ];

    $values = [];
    foreach ($defaults as $key => $value) {
        if (!array_key_exists($key, $current)) {
            $values[$key] = $value;
        }
    }

    if ($values !== []) {
        try {
            \Config::setConfigurationValues('plugin:securescan', $values);
        } catch (\Throwable $e) {
            \Toolbox::logDebug($e);
            return false;
        }
    }

    register_shutdown_function(static function (): void {
        $cacheManager = new CacheManager();
        if (method_exists($cacheManager, 'resetAllCaches')) {
            $cacheManager->resetAllCaches();
        }
    });

    return true;
}

function plugin_securescan_uninstall(): bool
{
    $config = new \Config();
    $config->deleteByCriteria([
        'context' => 'plugin:securescan',
    ]);

    return true;
}
