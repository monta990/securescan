<?php

namespace GlpiPlugin\Securescan\Controller;

use GlpiPlugin\Securescan\EngineSelector;
use Glpi\Controller\AbstractController;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use GlpiPlugin\Securescan\Antivirus as SecureScan;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Save SecureScan configuration.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */
final class ConfigSaveController extends AbstractController
{
    #[Route('/Config/Save', name: 'securescan_config_save', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $this->checkAccess();

        $command = trim($request->request->getString('securescan_command'));
        $engine = $request->request->getString('securescan_engine', EngineSelector::DISABLED);
        if (!in_array($engine, [EngineSelector::DISABLED, EngineSelector::CLAMAV, EngineSelector::VIRUSTOTAL], true)) {
            $engine = EngineSelector::DISABLED;
        }
        $enabled = $engine === EngineSelector::CLAMAV ? 1 : 0;
        $timeout = max(5, min(300, $request->request->getInt('securescan_timeout', 30)));
        $storedConfig = SecureScanConfig::getConfig();
        $autoUpdateCheck = $request->request->getInt('securescan_auto_update_check', 0) === 1 ? 1 : 0;
        $virusTotalEnabled = $engine === EngineSelector::VIRUSTOTAL ? 1 : 0;
        $virusTotalAutoUpload = $request->request->getInt('securescan_virustotal_auto_upload', 0) === 1 ? 1 : 0;
        $virusTotalApiKey = trim($request->request->getString('securescan_virustotal_api_key'));
        $removeVirusTotalKey = $request->request->getInt('securescan_virustotal_remove_key', 0) === 1;
        if ($removeVirusTotalKey) {
            $virusTotalEnabled = 0;
            $virusTotalAutoUpload = 0;
        }

        if ($command === '') {
            $command = (string) ($storedConfig['securescan_command'] ?? SecureScanConfig::DEFAULT_COMMAND);
        }

        if ($removeVirusTotalKey && $virusTotalApiKey !== '') {
            \Session::addMessageAfterRedirect(
                __s('Enter a new VirusTotal API key or select remove API key, not both.', 'securescan'),
                false,
                ERROR
            );
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        if ($virusTotalApiKey !== '' && !\GlpiPlugin\Securescan\VirusTotal::isValidApiKeyShape($virusTotalApiKey)) {
            \Session::addMessageAfterRedirect(
                __s('The VirusTotal API key format is invalid.', 'securescan'),
                false,
                ERROR
            );
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        $existingVirusTotalKey = SecureScanConfig::getVirusTotalApiKey();
        $effectiveVirusTotalKey = $removeVirusTotalKey
            ? ''
            : ($virusTotalApiKey !== '' ? $virusTotalApiKey : $existingVirusTotalKey);
        $virusTotalTestedHash = (string) ($storedConfig['securescan_virustotal_tested_hash'] ?? '');
        if ($virusTotalApiKey !== '' && !hash_equals($virusTotalTestedHash, \GlpiPlugin\Securescan\VirusTotal::getTestedKeyHash($virusTotalApiKey))) {
            $virusTotalTestedHash = '';
        }
        if ($removeVirusTotalKey) {
            $virusTotalTestedHash = '';
        }
        if ($virusTotalEnabled === 1 && $effectiveVirusTotalKey === '') {
            \Session::addMessageAfterRedirect(
                __s('Configure and test a VirusTotal API key before enabling VirusTotal.', 'securescan'),
                false,
                ERROR
            );
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }
        if (
            $virusTotalEnabled === 1
            && !hash_equals($virusTotalTestedHash, \GlpiPlugin\Securescan\VirusTotal::getTestedKeyHash($effectiveVirusTotalKey))
        ) {
            \Session::addMessageAfterRedirect(
                __s('Test the current VirusTotal API key successfully before enabling VirusTotal.', 'securescan'),
                false,
                ERROR
            );
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        if ($enabled === 1) {
            $validationError = SecureScan::validateCommand($command);
            if ($validationError !== null) {
                \Session::addMessageAfterRedirect($validationError, false, ERROR);
                return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
            }
        }

        $current = $storedConfig;
        $testedHash = (string) ($current['securescan_tested_hash'] ?? '');
        $commandHash = SecureScan::getTestedConfigurationHash($command);

        if ($command !== (string) ($current['securescan_command'] ?? '')) {
            $testedHash = '';
        }

        if ($enabled === 1 && !hash_equals($testedHash, $commandHash)) {
            \Session::addMessageAfterRedirect(
                __s('Run Test selected engine successfully for the current command before enabling scanning.', 'securescan'),
                false,
                ERROR
            );

            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        try {
            SecureScanConfig::save($enabled, $command, $testedHash, $timeout, $autoUpdateCheck, [
                'securescan_virustotal_enabled' => $virusTotalEnabled,
                'securescan_virustotal_auto_upload' => $virusTotalAutoUpload,
                'securescan_virustotal_api_key' => $virusTotalApiKey,
                'securescan_virustotal_tested_hash' => $virusTotalTestedHash,
                'securescan_virustotal_remove_key' => $removeVirusTotalKey,
            ]);
            $savedConfig = SecureScanConfig::getConfig();
            $saved = (int) ($savedConfig['securescan_enabled'] ?? -1) === $enabled
                && (string) ($savedConfig['securescan_command'] ?? '') === $command
                && (string) ($savedConfig['securescan_tested_hash'] ?? '') === $testedHash
                && (int) ($savedConfig['securescan_timeout'] ?? 0) === $timeout
                && (int) ($savedConfig['securescan_auto_update_check'] ?? 0) === $autoUpdateCheck
                && (int) ($savedConfig['securescan_virustotal_enabled'] ?? 0) === $virusTotalEnabled
                && (int) ($savedConfig['securescan_virustotal_auto_upload'] ?? 0) === $virusTotalAutoUpload
                && (SecureScanConfig::getVirusTotalApiKey() !== '') === ($effectiveVirusTotalKey !== '');
        } catch (\Throwable $e) {
            \Toolbox::logDebug($e);
            $saved = false;
        }

        \Session::addMessageAfterRedirect(
            $saved
                ? __s('SecureScan configuration saved successfully.', 'securescan')
                : __s('SecureScan configuration could not be saved.', 'securescan'),
            false,
            $saved ? INFO : ERROR
        );

        return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
    }

    private function checkAccess(): void
    {
        // Config::checkGlobal() performs the standard right check and, on
        // GLPI 12, the required re-authentication for sensitive configuration.
        (new \Config())->checkGlobal(UPDATE);
    }
}
