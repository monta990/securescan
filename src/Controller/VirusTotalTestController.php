<?php

namespace GlpiPlugin\Securescan\Controller;

use Glpi\Controller\AbstractController;
use GlpiPlugin\Securescan\Antivirus;
use GlpiPlugin\Securescan\Config as SecureScanConfig;
use GlpiPlugin\Securescan\EngineSelector;
use GlpiPlugin\Securescan\VirusTotal;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Validate and securely save the VirusTotal API key.
 *
 * Copyright (C) 2026 Edwin Elias Alvarez
 * Licensed under GPLv3+.
 */
final class VirusTotalTestController extends AbstractController
{
    #[Route('/VirusTotal/Test', name: 'securescan_virustotal_test', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $this->checkAccess();

        $config = SecureScanConfig::getConfig();
        $engine = $request->request->getString(
            'securescan_engine',
            (string) ($config['securescan_engine'] ?? EngineSelector::DISABLED)
        );
        if (!in_array($engine, [EngineSelector::DISABLED, EngineSelector::CLAMAV, EngineSelector::VIRUSTOTAL], true)) {
            $engine = EngineSelector::DISABLED;
        }

        $submittedKey = trim($request->request->getString('securescan_virustotal_api_key'));
        $apiKey = $submittedKey !== '' ? $submittedKey : SecureScanConfig::getVirusTotalApiKey();
        $result = VirusTotal::testConnection($apiKey);

        if ($result['ok']) {
            $command = trim($request->request->getString('securescan_command'));
            if ($command === '') {
                $command = (string) ($config['securescan_command'] ?? SecureScanConfig::DEFAULT_COMMAND);
            }
            $timeout = max(5, min(300, $request->request->getInt('securescan_timeout', (int) ($config['securescan_timeout'] ?? 30))));

            // Activating ClamAV from this key-only test is allowed only when its
            // current command already has a valid test fingerprint. Otherwise
            // this operation stores the API key without enabling an untested engine.
            $clamavTested = hash_equals(
                Antivirus::getTestedConfigurationHash($command),
                (string) ($config['securescan_tested_hash'] ?? '')
            );
            $desiredEngine = $engine;
            if ($desiredEngine === EngineSelector::CLAMAV && !$clamavTested) {
                $desiredEngine = EngineSelector::DISABLED;
            }

            try {
                $extra = [
                    'securescan_virustotal_enabled' => $desiredEngine === EngineSelector::VIRUSTOTAL ? 1 : 0,
                    'securescan_virustotal_auto_upload' => $request->request->getInt(
                        'securescan_virustotal_auto_upload',
                        (int) ($config['securescan_virustotal_auto_upload'] ?? 0)
                    ) === 1 ? 1 : 0,
                    'securescan_virustotal_tested_hash' => VirusTotal::getTestedKeyHash($apiKey),
                ];
                if ($submittedKey !== '') {
                    $extra['securescan_virustotal_api_key'] = $submittedKey;
                }

                SecureScanConfig::save(
                    $desiredEngine === EngineSelector::CLAMAV ? 1 : 0,
                    $command,
                    (string) ($config['securescan_tested_hash'] ?? ''),
                    $timeout,
                    (int) ($config['securescan_auto_update_check'] ?? 0),
                    $extra
                );

                $savedConfig = SecureScanConfig::getConfig();
                $savedEngine = EngineSelector::resolve($savedConfig);
                if (
                    SecureScanConfig::getVirusTotalApiKey() === ''
                    || !hash_equals(
                        VirusTotal::getTestedKeyHash($apiKey),
                        (string) ($savedConfig['securescan_virustotal_tested_hash'] ?? '')
                    )
                    || $savedEngine !== $desiredEngine
                ) {
                    $result['ok'] = false;
                    $result['message'] = __s('VirusTotal was tested, but SecureScan could not save the API key and selected engine.', 'securescan');
                } elseif ($desiredEngine === EngineSelector::VIRUSTOTAL) {
                    $result['message'] = __s('VirusTotal connection succeeded. VirusTotal is now the only active engine; ClamAV is disabled.', 'securescan');
                } elseif ($desiredEngine === EngineSelector::CLAMAV) {
                    $result['message'] = __s('VirusTotal API key was verified and saved. ClamAV remains the only active engine.', 'securescan');
                } else {
                    $result['message'] = __s('VirusTotal connection succeeded and the API key was stored encrypted. No scan engine is currently enabled.', 'securescan');
                }
            } catch (\Throwable $e) {
                \Toolbox::logDebug($e);
                $result['ok'] = false;
                $result['message'] = __s('VirusTotal connection succeeded, but its configuration could not be saved.', 'securescan');
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
        (new \Config())->checkGlobal(UPDATE);
    }
}
