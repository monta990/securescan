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

use Glpi\Plugin\Hooks;
use GlpiPlugin\Securescan\Config as SecureScanConfig;

use function Safe\define;

define('PLUGIN_SECURESCAN_VERSION', '1.0.0');
define('PLUGIN_SECURESCAN_MIN_GLPI_VERSION', '11.0.7');
define('PLUGIN_SECURESCAN_MAX_GLPI_VERSION', '12.99.99');
define('PLUGIN_SECURESCAN_MIN_PHP_VERSION', '8.2.0');

function plugin_init_securescan(): void
{
    global $PLUGIN_HOOKS;


    $PLUGIN_HOOKS[Hooks::PRE_ITEM_ADD]['securescan'] = [
        \Document::class => [
            \GlpiPlugin\Securescan\Antivirus::class,
            'preDocumentAdd',
        ],
    ];

    $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]['securescan'] = [
        \Document::class => [
            \GlpiPlugin\Securescan\Antivirus::class,
            'preDocumentUpdate',
        ],
    ];

    $PLUGIN_HOOKS[Hooks::ITEM_ADD]['securescan'] = [
        \Document::class => [
            \GlpiPlugin\Securescan\Antivirus::class,
            'postDocumentAdd',
        ],
    ];

    $PLUGIN_HOOKS[Hooks::ITEM_UPDATE]['securescan'] = [
        \Document::class => [
            \GlpiPlugin\Securescan\Antivirus::class,
            'postDocumentUpdate',
        ],
    ];

    // Native GLPI configuration tab. The class extends \Config intentionally;
    // it does not override getTable() and therefore never creates a plugin table.
    \Plugin::registerClass(SecureScanConfig::class, [
        'addtabon' => [\Config::class],
    ]);

    // Standard configuration gear from Setup > Plugins.
    if (\Session::haveRight('config', UPDATE)) {
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['securescan'] = '../../front/config.form.php?forcetab=GlpiPlugin\\Securescan\\Config$1';
    }
}

function plugin_version_securescan(): array
{
    return [
        'name'         => 'SecureScan',
        'version'      => PLUGIN_SECURESCAN_VERSION,
        'author'       => 'Edwin Elias Alvarez',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://github.com/monta990/securescan',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SECURESCAN_MIN_GLPI_VERSION,
                'max' => PLUGIN_SECURESCAN_MAX_GLPI_VERSION,
            ],
            'php' => [
                'min' => PLUGIN_SECURESCAN_MIN_PHP_VERSION,
            ],
        ],
    ];
}

function plugin_securescan_check_prerequisites(): bool
{
    return true;
}

function plugin_securescan_check_config(bool $verbose = false): bool
{
    return true;
}
