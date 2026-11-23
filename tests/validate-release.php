<?php
declare(strict_types=1);
$root=dirname(__DIR__);$errors=[];
$read=static function(string $p)use($root,&$errors):string{$f=$root.DIRECTORY_SEPARATOR.$p;if(!is_file($f)||!is_readable($f)){$errors[]="Missing or unreadable: {$p}";return '';} $s=file_get_contents($f);return is_string($s)?$s:'';};
$setup=$read('setup.php');$xml=$read('plugin.xml');$readme=$read('README.md');$workflow=$read('.github/workflows/ci.yml');$runner=$read('tools/run-cli-tests.sh');$package=$read('scripts/package.sh');
$version=null;if(preg_match("/define\\('PLUGIN_SECURESCAN_VERSION',\\s*'([^']+)'\\)/",$setup,$m)===1)$version=$m[1];else $errors[]='Missing PLUGIN_SECURESCAN_VERSION.';
if($version!=='2.0.0')$errors[]='Public release version must be 2.0.0.';
if(!str_contains($setup,"define('PLUGIN_SECURESCAN_MIN_GLPI_VERSION', '11.0.7')")||!str_contains($setup,"define('PLUGIN_SECURESCAN_MAX_GLPI_VERSION', '12.99.99')")||!str_contains($setup,"define('PLUGIN_SECURESCAN_MIN_PHP_VERSION', '8.2.0')"))$errors[]='GLPI/PHP compatibility mismatch.';
if(!preg_match('~<key>\\s*securescan\\s*</key>~',$xml)||!preg_match('~<state>\\s*stable\\s*</state>~',$xml)||!preg_match('~<num>\\s*2\\.0\\.0\\s*</num>~',$xml))$errors[]='plugin.xml release identity mismatch.';
if(!str_contains($xml,'<compatibility>~11.0.7</compatibility>')||!str_contains($xml,'<compatibility>~12.0.0</compatibility>')||!str_contains($xml,'/releases/download/2.0.0/securescan-2.0.0.zip'))$errors[]='plugin.xml compatibility or download URL mismatch.';
libxml_use_internal_errors(true);
$manifest=simplexml_load_string($xml, SimpleXMLElement::class, LIBXML_NONET);
libxml_clear_errors();
if($manifest===false){
    $errors[]='plugin.xml is not well-formed XML.';
}else{
    $expectedElements=['name','key','state','logo','description','homepage','download','issues','readme','authors','versions','langs','license','tags','screenshots'];
    $actualElements=[];
    foreach($manifest->children()as$element=>$value)$actualElements[]=$element;
    if($actualElements!==$expectedElements)$errors[]='plugin.xml catalog elements are missing or out of order.';
    foreach(['short','long']as$section){
        foreach(['en','es']as$lang){
            if(trim((string)($manifest->description->{$section}->{$lang}??''))==='')$errors[]="plugin.xml {$section} description missing {$lang}.";
        }
    }
    if(count($manifest->authors->author)<1)$errors[]='plugin.xml has no author.';
    if((string)$manifest->license!=='GPLv3+')$errors[]='plugin.xml license mismatch.';
    $declaredLanguages=[];
    foreach($manifest->langs->lang as $language)$declaredLanguages[]=trim((string)$language);
    sort($declaredLanguages);
    if($declaredLanguages!==['en_GB','es_MX'])$errors[]='plugin.xml language declarations mismatch.';
    foreach(['en','es']as$lang){
        if(count($manifest->tags->{$lang}->tag)<1)$errors[]="plugin.xml {$lang} tags are missing.";
    }
    if(count($manifest->screenshots->screenshot)<1)$errors[]='plugin.xml screenshot is missing.';
}
if(!str_contains($readme,'SecureScan 2.0.0')||str_contains($readme,'SecureScan 2.0.8'))$errors[]='README version does not match release.';
foreach(['setup.php','hook.php','plugin.xml','LICENSE','README.md','CHANGELOG.md','src/Antivirus.php','src/Audit.php','src/Config.php','src/EngineSelector.php','src/VirusTotal.php','src/VirusTotalRequestLimiter.php','src/Controller/VirusTotalScanController.php','templates/config.html.twig','public/js/securescan-wait.js','public/css/securescan-wait.css','locales/en_GB.po','locales/es_MX.po']as$p)$read($p);
foreach(['8.2','8.3','8.4','8.5','8.6']as$v)if(!str_contains($workflow,"'{$v}'"))$errors[]="PHP {$v} missing from workflow.";
if(!str_contains($workflow,'tools/run-cli-tests.sh')||str_contains($workflow,'continue-on-error: true'))$errors[]='CLI tests are not mandatory in workflow.';
if(!str_contains($runner,'tests/*Test.php')||!str_contains($runner,'tests/validate-release.php'))$errors[]='CLI runner does not include all regression/release checks.';
if(!str_contains($package,'plugin.xml')||!str_contains($package,'securescan-$VERSION.zip')||!str_contains($package,'unzip -t'))$errors[]='Invalid package script.';
if($errors!==[]){fwrite(STDERR,implode(PHP_EOL,array_map(static fn($e)=>'ERROR: '.$e,$errors)).PHP_EOL);exit(1);}
fwrite(STDOUT,"PASS: SecureScan 2.0.0 release metadata, compatibility, CLI matrix and package contracts.\n");
