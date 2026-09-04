<?php

namespace GlpiPlugin\Securescan\Controller;

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
        $enabled = $request->request->getInt('securescan_enabled', 0) === 1 ? 1 : 0;
        $timeout = max(5, min(300, $request->request->getInt('securescan_timeout', 30)));
        $storedConfig = SecureScanConfig::getConfig();
        $autoUpdateCheck = $request->request->getInt('securescan_auto_update_check', 0) === 1 ? 1 : 0;

        if ($command === '') {
            \Session::addMessageAfterRedirect(
                __s('The antivirus command cannot be empty.', 'securescan'),
                false,
                ERROR
            );

            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        $validationError = SecureScan::validateCommand($command);
        if ($validationError !== null) {
            \Session::addMessageAfterRedirect($validationError, false, ERROR);
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        $current = $storedConfig;
        $testedHash = (string) ($current['securescan_tested_hash'] ?? '');
        $commandHash = SecureScan::getTestedConfigurationHash($command);

        if ($command !== (string) ($current['securescan_command'] ?? '')) {
            $testedHash = '';
        }

        if ($enabled === 1 && !hash_equals($testedHash, $commandHash)) {
            \Session::addMessageAfterRedirect(
                __s('Run Test antivirus successfully for the current command before enabling scanning.', 'securescan'),
                false,
                ERROR
            );

            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        try {
            SecureScanConfig::save($enabled, $command, $testedHash, $timeout, $autoUpdateCheck);
            $savedConfig = SecureScanConfig::getConfig();
            $saved = (int) ($savedConfig['securescan_enabled'] ?? -1) === $enabled
                && (string) ($savedConfig['securescan_command'] ?? '') === $command
                && (string) ($savedConfig['securescan_tested_hash'] ?? '') === $testedHash
                && (int) ($savedConfig['securescan_timeout'] ?? 0) === $timeout
                && (int) ($savedConfig['securescan_auto_update_check'] ?? 0) === $autoUpdateCheck;
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
