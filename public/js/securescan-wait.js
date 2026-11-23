(() => {
    'use strict';

    const translations = {
        es: {
            title: 'SecureScan está verificando el archivo',
            start: 'Enviando el archivo a VirusTotal...',
            pending: 'VirusTotal continúa analizando el archivo. Esta consulta se ejecuta en segundo plano; puedes seguir usando GLPI en otras pestañas.',
            clean: 'VirusTotal terminó y el archivo está limpio. Continuando con el almacenamiento en GLPI...',
            rejected: 'VirusTotal no aprobó el archivo. GLPI no lo almacenará.',
            error: 'No fue posible verificar el archivo. GLPI no lo almacenará.',
            cancel: 'Cancelar espera',
            close: 'Cerrar',
            report: 'Consultar análisis en VirusTotal',
            file: 'Archivo',
            progress: 'Archivo {current} de {total}',
        },
        en: {
            title: 'SecureScan is checking your file',
            start: 'Submitting the file to VirusTotal...',
            pending: 'VirusTotal is still analyzing the file. Status checks run in the background; you can keep using GLPI in other tabs.',
            clean: 'VirusTotal completed the scan and the file is clean. Continuing with GLPI storage...',
            rejected: 'VirusTotal did not approve the file. GLPI will not store it.',
            error: 'The file could not be verified. GLPI will not store it.',
            cancel: 'Cancel waiting',
            close: 'Close',
            report: 'View analysis on VirusTotal',
            file: 'File',
            progress: 'File {current} of {total}',
        },
        fr: {
            title: 'SecureScan vérifie votre fichier',
            start: 'Envoi du fichier à VirusTotal...',
            pending: 'VirusTotal analyse toujours le fichier. Les vérifications s’exécutent en arrière-plan ; vous pouvez continuer à utiliser GLPI dans d’autres onglets.',
            clean: 'VirusTotal a terminé et le fichier est sain. Enregistrement dans GLPI...',
            rejected: 'VirusTotal n’a pas approuvé le fichier. GLPI ne l’enregistrera pas.',
            error: 'Le fichier n’a pas pu être vérifié. GLPI ne l’enregistrera pas.',
            cancel: 'Annuler l’attente',
            close: 'Fermer',
            report: 'Consulter l’analyse sur VirusTotal',
            file: 'Fichier',
            progress: 'Fichier {current} sur {total}',
        },
        pt: {
            title: 'O SecureScan está verificando seu arquivo',
            start: 'Enviando o arquivo para o VirusTotal...',
            pending: 'O VirusTotal ainda está analisando o arquivo. As consultas são executadas em segundo plano; você pode continuar usando o GLPI em outras abas.',
            clean: 'O VirusTotal concluiu a análise e o arquivo está limpo. Continuando o armazenamento no GLPI...',
            rejected: 'O VirusTotal não aprovou o arquivo. O GLPI não o armazenará.',
            error: 'Não foi possível verificar o arquivo. O GLPI não o armazenará.',
            cancel: 'Cancelar espera',
            close: 'Fechar',
            report: 'Consultar análise no VirusTotal',
            file: 'Arquivo',
            progress: 'Arquivo {current} de {total}',
        },
    };

    const getText = () => {
        const language = (document.documentElement.lang || 'en').toLowerCase();
        if (language.startsWith('es')) return translations.es;
        if (language.startsWith('fr')) return translations.fr;
        if (language.startsWith('pt')) return translations.pt;
        return translations.en;
    };

    const text = getText();
    const approvedForms = new WeakSet();
    const activeForms = new WeakMap();
    let overlay = null;

    const rootDoc = () => {
        const path = window.location.pathname;
        const markers = ['/front/', '/plugins/', '/marketplace/'];
        const positions = markers.map((marker) => path.indexOf(marker)).filter((position) => position >= 0);
        return positions.length > 0 ? path.slice(0, Math.min(...positions)) : '';
    };

    const endpoint = (path) => `${rootDoc()}/plugins/securescan${path}`;

    const getStagedUploads = (form) => {
        const fields = Array.from(form.querySelectorAll('input[name^="_filename"], input[name="upload_file"], select[name="upload_file"]'));
        const uploads = [];
        const seen = new Set();
        for (const field of fields) {
            const filename = (field.value || '').trim();
            if (!filename || seen.has(filename)) continue;
            seen.add(filename);
            uploads.push({
                filename,
                source: field.name === 'upload_file' ? 'upload' : 'tmp',
            });
        }
        return uploads;
    };

    const ensureOverlay = () => {
        if (overlay) return overlay;
        overlay = document.createElement('div');
        overlay.className = 'securescan-wait-overlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'securescan-wait-title');

        const panel = document.createElement('div');
        panel.className = 'securescan-wait-panel';
        const spinner = document.createElement('div');
        spinner.className = 'securescan-wait-spinner';
        spinner.setAttribute('aria-hidden', 'true');
        const heading = document.createElement('h2');
        heading.id = 'securescan-wait-title';
        heading.textContent = text.title;
        const progress = document.createElement('p');
        progress.className = 'securescan-wait-progress';
        const message = document.createElement('p');
        message.className = 'securescan-wait-message';
        const keep = document.createElement('p');
        keep.className = 'securescan-wait-keep';
        const report = document.createElement('a');
        report.className = 'securescan-wait-report';
        report.textContent = text.report;
        report.target = '_blank';
        report.rel = 'noopener noreferrer';
        report.hidden = true;
        const actions = document.createElement('div');
        actions.className = 'securescan-wait-actions';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'btn btn-outline-secondary';
        cancel.textContent = text.cancel;
        cancel.addEventListener('click', () => {
            if (activeStateValues.size === 0) {
                hideOverlay();
                return;
            }
            for (const state of activeStateValues) {
                if (state && state.cancel) state.cancel();
            }
        });
        actions.appendChild(cancel);
        panel.append(spinner, heading, progress, message, keep, report, actions);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);
        overlay._elements = { spinner, progress, message, keep, report, cancel };
        return overlay;
    };

    const activeStateValues = new Set();

    const showOverlay = () => {
        const node = ensureOverlay();
        node.classList.add('is-visible');
        node._elements.spinner.hidden = false;
        node._elements.cancel.hidden = false;
        node._elements.cancel.textContent = text.cancel;
        node._elements.report.hidden = true;
        node._elements.progress.textContent = '';
        node._elements.message.textContent = text.start;
        node._elements.keep.textContent = '';
    };

    const hideOverlay = () => {
        if (overlay) overlay.classList.remove('is-visible');
    };

    const updateOverlay = (current, total, filename, message, reportUrl) => {
        const node = ensureOverlay();
        const el = node._elements;
        el.progress.textContent = text.progress.replace('{current}', String(current)).replace('{total}', String(total)) + ` · ${text.file}: ${filename}`;
        el.message.textContent = message;
        // The status is already shown in the main message; do not repeat it.
        el.keep.textContent = '';
        if (reportUrl && /^https:\/\/www\.virustotal\.com\/gui\/file\/[a-f0-9]{64}\/detection$/.test(reportUrl)) {
            el.report.href = reportUrl;
            el.report.hidden = false;
        }
    };

    const showFailure = (message) => {
        const node = ensureOverlay();
        const el = node._elements;
        el.spinner.hidden = true;
        el.message.textContent = message || text.error;
        el.keep.textContent = '';
        el.cancel.textContent = text.close;
        el.report.hidden = !el.report.getAttribute('href');
    };

    const fetchJson = async (url, options, signal) => {
        const response = await fetch(url, {
            credentials: 'same-origin',
            cache: 'no-store',
            ...options,
            signal,
        });
        let body;
        try {
            body = await response.json();
        } catch (error) {
            throw new Error(`SecureScan HTTP ${response.status}: invalid response`);
        }
        if (!response.ok && body.status !== 'pending') {
            throw new Error(body.message || `SecureScan HTTP ${response.status}`);
        }
        return body;
    };

    const sleep = (ms, signal) => new Promise((resolve, reject) => {
        if (signal && signal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
        }
        let abortHandler = null;
        const timer = window.setTimeout(() => {
            if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
            resolve();
        }, ms);
        if (signal) {
            abortHandler = () => {
                window.clearTimeout(timer);
                reject(new DOMException('Aborted', 'AbortError'));
            };
            signal.addEventListener('abort', abortHandler, { once: true });
        }
    });

    const startOne = async (form, upload, current, total, state) => {
        const formData = new FormData();
        formData.append('filename', upload.filename);
        formData.append('source', upload.source);
        const csrf = form.querySelector('input[name="_glpi_csrf_token"]')
            || document.querySelector('input[name="_glpi_csrf_token"]');
        if (csrf && csrf.value) formData.append('_glpi_csrf_token', csrf.value);

        let result = await fetchJson(endpoint('/ajax/Scan/Start'), {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: formData,
        }, state.abort.signal);

        updateOverlay(current, total, upload.filename, result.status === 'pending' ? text.pending : text.start, result.analysis_url);
        while (result.status === 'pending') {
            // Analysis reads do not consume the original submitter's file-report
            // quota, but they remain rate-limited. The server coordinates polls
            // across sessions and supplies Retry-After when a delay is required.
            const serverDelay = Number(result.retry_after);
            const delaySeconds = Number.isFinite(serverDelay) && serverDelay > 0
                ? Math.min(600, Math.max(1, serverDelay))
                : 6;
            await sleep(delaySeconds * 1000, state.abort.signal);
            result = await fetchJson(endpoint(`/ajax/Scan/Status/${encodeURIComponent(result.token)}`), {
                method: 'GET',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            }, state.abort.signal);
            updateOverlay(current, total, upload.filename, result.status === 'pending' ? text.pending : text.clean, result.analysis_url);
        }

        if (result.status !== 'clean') {
            throw new Error(result.message || (['infected', 'suspicious'].includes(result.status) ? text.rejected : text.error));
        }
        return result;
    };

    document.addEventListener('submit', async (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;

        if (approvedForms.has(form)) {
            approvedForms.delete(form);
            return;
        }

        const uploads = getStagedUploads(form);
        if (uploads.length === 0) return;
        if (activeForms.has(form)) {
            event.preventDefault();
            event.stopImmediatePropagation();
            return;
        }

        // Prevent GLPI's original submission until every staged file has an
        // explicit clean verdict. The PHP worker is released between polls.
        event.preventDefault();
        event.stopImmediatePropagation();

        const state = {
            abort: new AbortController(),
            cancelled: false,
            cancel: () => {
                state.cancelled = true;
                state.abort.abort();
                activeForms.delete(form);
                activeStateValues.delete(state);
                hideOverlay();
            },
        };
        activeForms.set(form, state);
        activeStateValues.add(state);
        const submitter = event.submitter instanceof HTMLElement && event.submitter.form === form
            ? event.submitter
            : null;

        showOverlay();
        try {
            for (let index = 0; index < uploads.length; index++) {
                await startOne(form, uploads[index], index + 1, uploads.length, state);
            }
            if (state.cancelled) return;
            approvedForms.add(form);
            activeForms.delete(form);
            activeStateValues.delete(state);
            ensureOverlay()._elements.message.textContent = text.clean;
            ensureOverlay()._elements.spinner.hidden = true;
            window.setTimeout(() => {
                hideOverlay();
                if (typeof form.requestSubmit === 'function') {
                    if (submitter) form.requestSubmit(submitter);
                    else form.requestSubmit();
                } else {
                    form.submit();
                }
            }, 350);
        } catch (error) {
            activeForms.delete(form);
            activeStateValues.delete(state);
            if (error && error.name === 'AbortError') return;
            showFailure(error instanceof Error ? error.message : text.error);
        }
    }, true);
})();
