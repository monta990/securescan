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
 * Test and activate the single selected SecureScan engine.
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
        $engine = $request->request->getString(
            'securescan_engine',
            (string) ($config['securescan_engine'] ?? EngineSelector::DISABLED)
        );
        if (!in_array($engine, [EngineSelector::DISABLED, EngineSelector::CLAMAV, EngineSelector::VIRUSTOTAL], true)) {
            $engine = EngineSelector::DISABLED;
        }

        if ($engine === EngineSelector::DISABLED) {
            $this->notify(__s('Select ClamAV or VirusTotal as the active engine before running a test.', 'securescan'), false);
            return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
        }

        $command = trim($request->request->getString('securescan_command'));
        if ($command === '') {
            $command = (string) ($config['securescan_command'] ?? SecureScanConfig::DEFAULT_COMMAND);
        }
        $timeout = max(5, min(300, $request->request->getInt('securescan_timeout', (int) ($config['securescan_timeout'] ?? 30))));
        $autoUpdateCheck = (int) ($config['securescan_auto_update_check'] ?? 0);

        if ($engine === EngineSelector::VIRUSTOTAL) {
            $result = $this->testVirusTotal($request, $config, $command, $timeout, $autoUpdateCheck);
        } else {
            $result = Antivirus::test($command, $timeout);
            if ($result['ok']) {
                try {
                    SecureScanConfig::save(
                        1,
                        $command,
                        Antivirus::getTestedConfigurationHash($command),
                        $timeout,
                        $autoUpdateCheck,
                        ['securescan_virustotal_enabled' => 0]
                    );
                    $savedConfig = SecureScanConfig::getConfig();
                    $stored = EngineSelector::resolve($savedConfig) === EngineSelector::CLAMAV
                        && (string) ($savedConfig['securescan_command'] ?? '') === $command
                        && hash_equals(
                            Antivirus::getTestedConfigurationHash($command),
                            (string) ($savedConfig['securescan_tested_hash'] ?? '')
                        );
                } catch (\Throwable $e) {
                    \Toolbox::logDebug($e);
                    $stored = false;
                }

                if (!$stored) {
                    $result['ok'] = false;
                    $result['message'] = __s('The antivirus test succeeded, but SecureScan could not save the test result.', 'securescan');
                }
            }
        }

        $this->notify((string) ($result['message'] ?? __s('The antivirus test failed.', 'securescan')), (bool) ($result['ok'] ?? false));
        return new RedirectResponse(SecureScanConfig::getConfigurationUrl());
    }

    /**
     * Test the VirusTotal API key and make VirusTotal the only active engine.
     * The key may be entered on this form and is only persisted after a
     * successful API response.
     *
     * @param array<string, mixed> $config
     * @return array{ok: bool, message: string}
     */
    private function testVirusTotal(
        Request $request,
        array $config,
        string $command,
        int $timeout,
        int $autoUpdateCheck
    ): array {
        $submittedKey = trim($request->request->getString('securescan_virustotal_api_key'));
        $apiKey = $submittedKey !== '' ? $submittedKey : SecureScanConfig::getVirusTotalApiKey();

        $result = VirusTotal::testConnection($apiKey);
        if (!$result['ok']) {
            return $result;
        }

        try {
            $extra = [
                'securescan_virustotal_enabled' => 1,
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
                0,
                $command,
                (string) ($config['securescan_tested_hash'] ?? ''),
                $timeout,
                $autoUpdateCheck,
                $extra
            );

            $savedConfig = SecureScanConfig::getConfig();
            if (
                SecureScanConfig::getVirusTotalApiKey() === ''
                || EngineSelector::resolve($savedConfig) !== EngineSelector::VIRUSTOTAL
                || !hash_equals(
                    VirusTotal::getTestedKeyHash($apiKey),
                    (string) ($savedConfig['securescan_virustotal_tested_hash'] ?? '')
                )
            ) {
                return [
                    'ok' => false,
                    'message' => __s('VirusTotal was tested, but SecureScan could not store its key securely or activate it as the only engine.', 'securescan'),
                ];
            }

            return [
                'ok' => true,
                'message' => __s('VirusTotal test succeeded. VirusTotal is now the only active engine; ClamAV is disabled.', 'securescan'),
            ];
        } catch (\Throwable $e) {
            \Toolbox::logDebug($e);
            return [
                'ok' => false,
                'message' => __s('VirusTotal connection succeeded, but its configuration could not be saved.', 'securescan'),
            ];
        }
    }

    private function notify(string $message, bool $success): void
    {
        \Session::addMessageAfterRedirect($message, false, $success ? INFO : ERROR);
    }

    private function checkAccess(): void
    {
        // Config::checkGlobal() performs the standard right check and, on
        // GLPI 12, the required re-authentication for sensitive configuration.
        (new \Config())->checkGlobal(UPDATE);
    }
}
