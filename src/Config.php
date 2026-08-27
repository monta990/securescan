<?php
namespace GlpiPlugin\Securescan;
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use Session;
final class Config extends \Config
{
    public const CONTEXT = 'plugin:securescan';
    public const DEFAULT_COMMAND = 'clamdscan --no-summary {file}';
    public static function getTypeName($nb = 0) { return __('SecureScan', 'securescan'); }
    public static function getConfig(): array {
        return array_merge(['securescan_enabled'=>0,'securescan_command'=>self::DEFAULT_COMMAND,'securescan_tested_hash'=>''], \Config::getConfigurationValues(self::CONTEXT));
    }
    public static function save(int $enabled, string $command, string $testedHash): void {
        \Config::setConfigurationValues(self::CONTEXT, ['securescan_enabled'=>$enabled,'securescan_command'=>$command,'securescan_tested_hash'=>$testedHash]);
    }
    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) { return $item instanceof \Config ? self::createTabEntry(self::getTypeName()) : ''; }
    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
        return $item instanceof \Config ? self::showForConfig($item, $withtemplate) : true;
    }
    public static function showForConfig(\Config $config, $withtemplate = 0): void {
        if (!Session::haveRight('config', UPDATE)) return;
        TemplateRenderer::getInstance()->display('@securescan/config.html.twig', ['current_config'=>self::getConfig(),'can_edit'=>true]);
    }
    public static function getConfigurationUrl(): string {
        global $CFG_GLPI;
        return rtrim($CFG_GLPI['root_doc'], '/') . '/front/config.form.php?' . http_build_query(['forcetab'=>self::class.'$1']);
    }
}
