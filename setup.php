<?php

use Glpi\Plugin\Hooks;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use function Safe\define;

define('PLUGIN_SECURESCAN_VERSION', '0.1.25');
define('PLUGIN_SECURESCAN_MIN_GLPI_VERSION', '11.0.0');
define('PLUGIN_SECURESCAN_MAX_GLPI_VERSION', '12.99.99');
define('PLUGIN_SECURESCAN_MIN_PHP_VERSION', '8.2.0');

function plugin_init_securescan(): void
{
    global $PLUGIN_HOOKS;
    $PLUGIN_HOOKS['csrf_compliant']['securescan'] = true;
    $PLUGIN_HOOKS[Hooks::PRE_ITEM_ADD]['securescan'] = [\Document::class => [\GlpiPlugin\Securescan\Antivirus::class, 'preDocumentAdd']];
    $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]['securescan'] = [\Document::class => [\GlpiPlugin\Securescan\Antivirus::class, 'preDocumentUpdate']];
    $PLUGIN_HOOKS[Hooks::ITEM_ADD]['securescan'] = [\Document::class => [\GlpiPlugin\Securescan\Antivirus::class, 'postDocumentAdd']];
    $PLUGIN_HOOKS[Hooks::ITEM_UPDATE]['securescan'] = [\Document::class => [\GlpiPlugin\Securescan\Antivirus::class, 'postDocumentUpdate']];
    \Plugin::registerClass(SecureScanConfig::class, ['addtabon' => [\Config::class]]);
    if (\Session::haveRight('config', UPDATE)) {
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['securescan'] = '../../front/config.form.php?forcetab=GlpiPlugin\\Securescan\\Config$1';
    }
}

function plugin_version_securescan(): array
{
    return [
        'name' => 'SecureScan',
        'version' => PLUGIN_SECURESCAN_VERSION,
        'author' => 'Edwin Elias Alvarez',
        'license' => 'GPLv3+',
        'homepage' => 'https://github.com/monta990/securescan',
        'requirements' => [
            'glpi' => ['min' => PLUGIN_SECURESCAN_MIN_GLPI_VERSION, 'max' => PLUGIN_SECURESCAN_MAX_GLPI_VERSION],
            'php' => ['min' => PLUGIN_SECURESCAN_MIN_PHP_VERSION],
        ],
    ];
}

function plugin_securescan_check_prerequisites(): bool { return true; }
function plugin_securescan_check_config(bool $verbose = false): bool { return true; }
