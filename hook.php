<?php
use Glpi\Cache\CacheManager;
function plugin_securescan_install(): bool {
    $current=\Config::getConfigurationValues('plugin:securescan');
    $defaults=['securescan_enabled'=>0,'securescan_command'=>'clamdscan --no-summary {file}','securescan_tested_hash'=>'']; $values=[];
    foreach($defaults as $key=>$value) if(!array_key_exists($key,$current)) $values[$key]=$value;
    if($values!==[]) { try { \Config::setConfigurationValues('plugin:securescan',$values); } catch(\Throwable $e) { \Toolbox::logDebug($e); return false; } }
    register_shutdown_function(static function(): void { $cacheManager=new CacheManager(); if(method_exists($cacheManager,'resetAllCaches')) $cacheManager->resetAllCaches(); });
    return true;
}
function plugin_securescan_uninstall(): bool { $config=new \Config(); $config->deleteByCriteria(['context'=>'plugin:securescan']); return true; }
