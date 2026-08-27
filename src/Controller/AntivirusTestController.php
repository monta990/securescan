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
    #[Route('/Antivirus/Test', name: 'securescan_antivirus_test', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $this->checkAccess();

        if (!$request->isMethod('POST')) {
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        $command = trim($request->request->getString('securescan_command'));
        if ($command === '') {
            $command = (string) SecureScanConfig::getConfig()['securescan_command'];
        }

        $result = Antivirus::test($command);

        if ($result['ok']) {
            try {
                SecureScanConfig::save(
                    (int) (SecureScanConfig::getConfig()['securescan_enabled'] ?? 0),
                    $command,
                    hash('sha256', $command)
                );
                $savedConfig = SecureScanConfig::getConfig();
                $stored = (string) ($savedConfig['securescan_command'] ?? '') === $command
                    && (string) ($savedConfig['securescan_tested_hash'] ?? '') === hash('sha256', $command);
            } catch (\Throwable $e) {
                \Toolbox::logDebug($e);
                $stored = false;
            }

            if (!$stored) {
                $result['ok'] = false;
                $result['message'] = __('The antivirus test succeeded, but SecureScan could not save the test result.', 'securescan');
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
