<?php
namespace GlpiPlugin\Securescan\Controller;
use Glpi\Controller\AbstractController;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
final class ConfigSaveController extends AbstractController
{
    #[Route('/Config/Save', name:'securescan_config_save', methods:['GET','POST'])]
    public function __invoke(Request $request): Response {
        $this->checkAccess();
        if (!$request->isMethod('POST')) return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        $command=trim($request->request->getString('securescan_command'));
        $enabled=$request->request->getInt('securescan_enabled',0)===1?1:0;
        if ($command==='') { \Session::addMessageAfterRedirect(__('The antivirus command cannot be empty.','securescan'),false,ERROR); return new RedirectResponse(SecureScanConfig::getConfigurationUrl()); }
        $current=SecureScanConfig::getConfig();
        $testedHash=(string)($current['securescan_tested_hash']??'');
        $commandHash=hash('sha256',$command);
        if ($command!==(string)($current['securescan_command']??'')) $testedHash='';
        if ($enabled===1 && !hash_equals($testedHash,$commandHash)) { \Session::addMessageAfterRedirect(__('Run Test antivirus successfully for the current command before enabling scanning.','securescan'),false,ERROR); return new RedirectResponse(SecureScanConfig::getConfigurationUrl()); }
        try { SecureScanConfig::save($enabled,$command,$testedHash); $savedConfig=SecureScanConfig::getConfig(); $saved=(int)($savedConfig['securescan_enabled']??-1)===$enabled && (string)($savedConfig['securescan_command']??'')===$command && (string)($savedConfig['securescan_tested_hash']??'')===$testedHash; } catch (\Throwable $e) { \Toolbox::logDebug($e); $saved=false; }
        \Session::addMessageAfterRedirect($saved?__('SecureScan configuration saved successfully.','securescan'):__('SecureScan configuration could not be saved.','securescan'),false,$saved?INFO:ERROR);
        return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
    }
    private function checkAccess(): void { (new \Config())->checkGlobal(UPDATE); }
}
