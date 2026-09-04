<?php

namespace GlpiPlugin\Securescan\Controller;

use Glpi\Controller\AbstractController;
use GlpiPlugin\Securescan\Antivirus;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Test the configured antivirus command.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */
final class AntivirusTestController extends AbstractController
{
    #[Route('/Antivirus/Test', name: 'securescan_antivirus_test', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $this->checkAccess();


        $config = SecureScanConfig::getConfig();
        $command = trim($request->request->getString('securescan_command'));
        if ($command === '') {
            $command = (string) $config['securescan_command'];
        }
        $timeout = max(5, min(300, $request->request->getInt('securescan_timeout', (int) ($config['securescan_timeout'] ?? 30))));
        $result = Antivirus::test($command, $timeout);

        if ($result['ok']) {
            try {
                SecureScanConfig::save(
                    (int) ($config['securescan_enabled'] ?? 0),
                    $command,
                    Antivirus::getTestedConfigurationHash($command),
                    $timeout,
                    (int) ($config['securescan_auto_update_check'] ?? 0)
                );
                $savedConfig = SecureScanConfig::getConfig();
                $stored = (string) ($savedConfig['securescan_command'] ?? '') === $command
                    && (string) ($savedConfig['securescan_tested_hash'] ?? '') === Antivirus::getTestedConfigurationHash($command)
                    && (int) ($savedConfig['securescan_timeout'] ?? 0) === $timeout
                    && (int) ($savedConfig['securescan_auto_update_check'] ?? 0) === (int) ($config['securescan_auto_update_check'] ?? 0);
            } catch (\Throwable $e) {
                \Toolbox::logDebug($e);
                $stored = false;
            }

            if (!$stored) {
                $result['ok'] = false;
                $result['message'] = __s('The antivirus test succeeded, but SecureScan could not save the test result.', 'securescan');
            }
        }

        \Session::addMessageAfterRedirect(
            $result['message'],
            false,
            $result['ok'] ? INFO : ERROR
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
