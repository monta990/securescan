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

namespace GlpiPlugin\Securescan;

use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use Session;

/**
 * SecureScan configuration itemtype.
 *
 * The class intentionally extends GLPI's native Config object so the plugin
 * configuration is exposed as a native tab under Setup > General > Config.
 * Configuration values themselves remain in glpi_configs.
 */
final class Config extends \Config
{
    public const CONTEXT = 'plugin:securescan';
    public const DEFAULT_COMMAND = 'clamdscan --no-summary {file}';

    public static function getTypeName($nb = 0)
    {
        return __('SecureScan', 'securescan');
    }

    public static function getIcon(): string
    {
        return 'ti ti-shield-check';
    }

    public static function getConfig(): array
    {
        $config = \Config::getConfigurationValues(self::CONTEXT);

        return array_merge([
            'securescan_enabled'     => 0,
            'securescan_command'     => self::DEFAULT_COMMAND,
            'securescan_tested_hash' => '',
            'securescan_timeout' => 30,
            'securescan_auto_update_check' => 0,
        ], $config);
    }

    public static function save(int $enabled, string $command, string $testedHash, int $timeout = 30, int $autoUpdateCheck = 0): void
    {
        \Config::setConfigurationValues(self::CONTEXT, [
            'securescan_enabled'     => $enabled,
            'securescan_command'     => $command,
            'securescan_tested_hash' => $testedHash,
            'securescan_timeout' => $timeout,
            'securescan_auto_update_check' => $autoUpdateCheck,
        ]);
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof \Config) {
            return self::createTabEntry(self::getTypeName());
        }

        return '';
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if ($item instanceof \Config) {
            return self::showForConfig($item, $withtemplate);
        }

        return true;
    }

    public static function showForConfig(\Config $config, $withtemplate = 0): void
    {
        if (!Session::haveRight('config', UPDATE)) {
            return;
        }

        TemplateRenderer::getInstance()->display('@securescan/config.html.twig', [
            'current_config'  => self::getConfig(),
            'can_edit'        => true,
            'version_status'  => (int) (self::getConfig()['securescan_auto_update_check'] ?? 0) === 1
                ? VersionChecker::check()
                : null,
        ]);
    }

    public static function getConfigurationUrl(): string
    {
        global $CFG_GLPI;

        $query = http_build_query([
            'forcetab' => self::class . '$1',
        ]);

        return rtrim($CFG_GLPI['root_doc'], '/') . '/front/config.form.php?' . $query;
    }
}
