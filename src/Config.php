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

        $merged = array_merge([
            'securescan_enabled'     => 0,
            'securescan_command'     => self::DEFAULT_COMMAND,
            'securescan_tested_hash' => '',
            'securescan_timeout' => 30,
            'securescan_auto_update_check' => 0,
            'securescan_virustotal_enabled' => 0,
            'securescan_virustotal_auto_upload' => 0,
            'securescan_virustotal_api_key' => '',
            'securescan_virustotal_tested_hash' => '',
        ], $config);

        // One visible engine selector is derived from the legacy storage flags.
        // If an older or manually edited config enables both, force an explicit
        // administrator choice and keep uploads fail-closed until it is saved.
        $engine = EngineSelector::resolve($merged);
        $merged['securescan_engine_conflict'] = $engine === EngineSelector::CONFLICT;
        $merged['securescan_engine'] = $engine === EngineSelector::CONFLICT
            ? EngineSelector::DISABLED
            : $engine;

        // Never expose the encrypted API key to Twig or other callers.
        $merged['securescan_virustotal_api_key_configured'] = !empty($merged['securescan_virustotal_api_key']);
        unset($merged['securescan_virustotal_api_key']);
        return $merged;
    }

    public static function save(
        int $enabled,
        string $command,
        string $testedHash,
        int $timeout = 30,
        int $autoUpdateCheck = 0,
        array $extra = []
    ): void {
        $virusTotalEnabled = array_key_exists('securescan_virustotal_enabled', $extra)
            ? (int) ((int) $extra['securescan_virustotal_enabled'] === 1)
            : 0;
        EngineSelector::assertExclusive($enabled === 1, $virusTotalEnabled === 1);

        $values = [
            'securescan_enabled'     => $enabled === 1 ? 1 : 0,
            'securescan_command'     => $command,
            'securescan_tested_hash' => $testedHash,
            'securescan_timeout' => $timeout,
            'securescan_auto_update_check' => $autoUpdateCheck,
            // Every save writes both flags explicitly so the legacy storage
            // cannot retain a second engine from an earlier configuration.
            'securescan_virustotal_enabled' => $virusTotalEnabled,
        ];

        foreach ([
            'securescan_virustotal_enabled',
            'securescan_virustotal_auto_upload',
        ] as $setting) {
            if (array_key_exists($setting, $extra)) {
                $values[$setting] = (int) ((int) $extra[$setting] === 1);
            }
        }

        if (isset($extra['securescan_virustotal_tested_hash']) && is_string($extra['securescan_virustotal_tested_hash'])) {
            $values['securescan_virustotal_tested_hash'] = $extra['securescan_virustotal_tested_hash'];
        }

        if (isset($extra['securescan_virustotal_api_key']) && is_string($extra['securescan_virustotal_api_key'])) {
            $apiKey = trim($extra['securescan_virustotal_api_key']);
            if ($apiKey !== '') {
                $values['securescan_virustotal_api_key'] = $apiKey;
            }
        }

        if (!empty($extra['securescan_virustotal_remove_key'])) {
            $values['securescan_virustotal_api_key'] = '';
            $values['securescan_virustotal_tested_hash'] = '';
        }

        \Config::setConfigurationValues(self::CONTEXT, $values);
    }

    /**
     * Read the VirusTotal API key from GLPI's encrypted configuration storage.
     * The plaintext is kept in memory only and is never exposed to templates.
     */
    public static function getVirusTotalApiKey(): string
    {
        $config = \Config::getConfigurationValues(self::CONTEXT);
        $stored = $config['securescan_virustotal_api_key'] ?? '';
        if (!is_string($stored) || $stored === '') {
            return '';
        }

        try {
            $glpiKey = new \GLPIKey();
            if (!$glpiKey->keyExists()) {
                return '';
            }
            $decrypted = $glpiKey->decrypt($stored);
            // GLPIKey may return the original ciphertext when it cannot read
            // the instance key. Never send that value to VirusTotal as a key.
            if (!is_string($decrypted) || !VirusTotal::isValidApiKeyShape($decrypted)) {
                return '';
            }

            return $decrypted;
        } catch (\Throwable $e) {
            \Toolbox::logDebug($e);
            return '';
        }
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

        $currentConfig = self::getConfig();
        $command = (string) ($currentConfig['securescan_command'] ?? self::DEFAULT_COMMAND);
        $testedHash = (string) ($currentConfig['securescan_tested_hash'] ?? '');
        $needsRetest = EngineSelector::resolve($currentConfig) === EngineSelector::CLAMAV
            && !hash_equals(Antivirus::getTestedConfigurationHash($command), $testedHash);

        TemplateRenderer::getInstance()->display('@securescan/config.html.twig', [
            'current_config' => $currentConfig,
            'can_edit'       => true,
            'needs_retest'   => $needsRetest,
            'version_status' => (int) ($currentConfig['securescan_auto_update_check'] ?? 0) === 1
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
