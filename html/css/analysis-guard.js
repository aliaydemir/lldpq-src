/*
 * analysis-guard.js — hide the admin-only "Run Analysis" button for operators.
 *
 * The button triggers an admin-only collection (e.g. /trigger-monitor on the
 * analysis pages, /trigger-transceiver on the Transceiver page); an operator
 * would only get a permission error, so it should not be shown to them.
 *
 * Flicker-free & symmetric: this script sits at end-of-body, so it runs before
 * first paint. It resolves the role from the cache written by auth.js and shows
 * the button for admins / hides it for non-admins, then confirms/refreshes from
 * /auth-api. A button that is rendered hidden by default (an admin-only action
 * using style="display:none") therefore stays hidden until the role is confirmed
 * admin, so operators never see it — while buttons that are visible by default
 * keep working on non-auth deployments (left as-is on any failure/unknown role).
 */
// Load the shared dark-themed dialogs on every analysis page so any native alert()
// (e.g. "Failed to trigger analysis", CSV export errors) is rendered in our dark UI.
(function () {
    if (window.__lldpqDialogsLoaded || window.__lldpqDialogsRequested) return;
    window.__lldpqDialogsRequested = true;
    try {
        var s = document.createElement('script');
        s.src = '/css/ui-dialogs.js';
        (document.head || document.documentElement).appendChild(s);
    } catch (e) {}
})();

(function () {
    function setHidden(hidden) {
        var b = document.getElementById('run-analysis');
        if (b) b.style.display = hidden ? 'none' : '';
    }

    // 1) Synchronous fast-path from the cached role -> no network, no flicker.
    //    Symmetric: reveal for a cached admin, hide for a cached non-admin. A
    //    default-hidden button stays hidden when there is no cached role.
    var cached = null;
    try { cached = localStorage.getItem('lldpq_role'); } catch (e) {}
    if (cached === 'admin') setHidden(false);
    else if (cached) setHidden(true);

    // 2) Confirm / refresh from the server (covers first visit or a stale cache).
    fetch('/auth-api?action=check')
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d && d.role) {
                try { localStorage.setItem('lldpq_role', d.role); } catch (e) {}
                setHidden(d.role !== 'admin');
            }
        })
        .catch(function () { /* leave the button as-is */ });
})();

/*
 * Shared monitoring-run state helpers.
 *
 * Analysis pages are last-known-good snapshots.  A trigger response only means
 * that a collection was queued; it does not mean the new report is ready.  Keep
 * the existing page layout and let page scripts wait for a new current manifest
 * instead of blindly reloading after a fixed delay.
 */
(function () {
    function noCacheUrl(path) {
        return path + (path.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now();
    }

    function parseStateMarker(text) {
        var result = {};
        String(text || '').split(/\r?\n/).forEach(function (line) {
            var index = line.indexOf('=');
            if (index > 0) result[line.slice(0, index)] = line.slice(index + 1);
        });
        return result;
    }

    async function readPipelineState() {
        var observedAt = Date.now() / 1000;
        var marker = null;
        var manifest = null;
        try {
            var markerResponse = await fetch(noCacheUrl('/monitor-results/.lldpq-stale'), {
                cache: 'no-store'
            });
            if (markerResponse.ok) marker = parseStateMarker(await markerResponse.text());
        } catch (error) {}
        try {
            var manifestResponse = await fetch(noCacheUrl('/monitor-results/.lldpq-current.json'), {
                cache: 'no-store'
            });
            if (manifestResponse.ok) manifest = await manifestResponse.json();
        } catch (error) {}
        return { marker: marker, manifest: manifest, observedAt: observedAt };
    }

    var analysisScopes = {
        bgp: true,
        duplicate: true,
        flap: true,
        optical: true,
        ber: true,
        'pfc-ecn': true,
        hardware: true,
        logs: true
    };

    function requireAnalysisScope(scope) {
        scope = String(scope || '');
        if (!analysisScopes[scope]) throw new Error('Unsupported analysis scope: ' + scope);
        return scope;
    }

    async function readScopedAnalysisState(scope) {
        scope = requireAnalysisScope(scope);
        var observedAt = Date.now() / 1000;
        var response;
        try {
            response = await fetch(noCacheUrl(
                '/monitor-results/.analysis-state/' + scope + '.status'
            ), { cache: 'no-store' });
        } catch (error) {
            // A short network interruption should not turn an in-flight run
            // into a false failure. Keep polling, while retaining the error for
            // diagnostics and eventual timeout reporting.
            return {
                scope: scope,
                marker: null,
                observedAt: observedAt,
                error: error
            };
        }
        // The marker is created when the daemon accepts the request. A 404
        // before that point is an expected pending state, never success.
        if (response.status === 404) {
            return { scope: scope, marker: null, observedAt: observedAt };
        }
        // Authentication, permission, and server errors are durable protocol
        // failures. Surface them now instead of making the user wait 15 minutes.
        if (!response.ok) {
            throw new Error('Could not read ' + scope + ' analysis state (HTTP ' +
                response.status + ')');
        }
        return {
            scope: scope,
            marker: parseStateMarker(await response.text()),
            observedAt: observedAt
        };
    }

    function manifestIdentity(manifest) {
        if (!manifest || typeof manifest !== 'object') return '';
        return String(manifest.pipeline_id || manifest.completed_at || '');
    }

    function markerIdentity(marker) {
        if (!marker || typeof marker !== 'object') return '';
        return [marker.status || '', marker.timestamp || '', marker.reason || ''].join('|');
    }

    function delay(milliseconds) {
        return new Promise(function (resolve) { setTimeout(resolve, milliseconds); });
    }

    async function waitForScopedAnalysisCompletion(scope, pipelineId, timeoutMs, pollMs) {
        scope = requireAnalysisScope(scope);
        pipelineId = String(pipelineId || '');
        if (!pipelineId) throw new Error('Scoped analysis request identity is missing');

        var startedAt = Date.now();
        var lastReadError = null;
        while (Date.now() - startedAt < timeoutMs) {
            var state = await readScopedAnalysisState(scope);
            if (state.error) lastReadError = state.error;
            var marker = state.marker;
            var markerPipelineId = String((marker && marker.pipeline_id) || '');

            // Persistent markers also describe previous runs. Only the marker
            // carrying this trigger's opaque identity may complete or fail it.
            if (marker && markerPipelineId === pipelineId) {
                if (String(marker.scope || '') !== scope) {
                    throw new Error('Analysis state scope does not match the request');
                }
                if (marker.status === 'current') return marker;
                if (marker.status === 'stale') {
                    throw new Error(marker.reason || (scope + ' analysis failed'));
                }
                if (marker.status !== 'collecting') {
                    throw new Error('Unknown ' + scope + ' analysis state: ' +
                        String(marker.status || 'missing'));
                }
            }

            await delay(pollMs);
        }

        var message = scope + ' analysis did not complete before the timeout';
        if (lastReadError && lastReadError.message) {
            message += ' (' + lastReadError.message + ')';
        }
        throw new Error(message);
    }

    window.lldpqReadPipelineState = readPipelineState;
    window.lldpqCapturePipelineState = readPipelineState;
    window.lldpqReadScopedAnalysisState = readScopedAnalysisState;
    window.lldpqCaptureAnalysisState = readScopedAnalysisState;
    window.waitForLldpqAnalysisCompletion = async function (baseline, options) {
        options = options || {};
        var timeoutMs = Number(options.timeoutMs) || 15 * 60 * 1000;
        var pollMs = Math.max(Number(options.pollMs) || 2000, 500);
        if (options.scope) {
            return waitForScopedAnalysisCompletion(
                options.scope, options.pipelineId, timeoutMs, pollMs
            );
        }
        var startedAt = Date.now();
        var baselineIdentity = manifestIdentity(baseline && baseline.manifest);
        var baselineMarkerIdentity = markerIdentity(baseline && baseline.marker);
        var baselineMarkerStatus = baseline && baseline.marker && baseline.marker.status;
        var baselineObservedAt = Number(baseline && baseline.observedAt) || (Date.now() / 1000);
        var requestedPipelineId = String(options.pipelineId || '');
        var sawCollection = false;

        while (Date.now() - startedAt < timeoutMs) {
            var state = await readPipelineState();
            var markerStatus = state.marker && state.marker.status;
            var currentMarkerIdentity = markerIdentity(state.marker);
            var markerChanged = currentMarkerIdentity !== baselineMarkerIdentity;
            var markerPipelineId = String((state.marker && state.marker.pipeline_id) || '');
            var markerBelongsToRequest = requestedPipelineId && markerPipelineId === requestedPipelineId;
            if (markerStatus === 'collecting' &&
                    (markerBelongsToRequest ||
                     (!requestedPipelineId && markerChanged && baselineMarkerStatus !== 'collecting'))) {
                sawCollection = true;
            }
            // A stale marker that already existed before the click describes
            // the previous failed run.  Ignore that exact marker until this
            // trigger starts or publishes a different failure marker.
            if (markerStatus === 'stale' &&
                    (markerBelongsToRequest ||
                     (!requestedPipelineId && sawCollection && markerChanged))) {
                throw new Error((state.marker && state.marker.reason) || 'Monitoring run failed');
            }

            var currentIdentity = manifestIdentity(state.manifest);
            var manifestCurrent = state.manifest &&
                state.manifest.status === 'current' &&
                state.manifest.pipeline_complete === true;
            var isNewManifest = currentIdentity && currentIdentity !== baselineIdentity;
            var manifestStartedAt = Number(state.manifest && state.manifest.pipeline_started_at) || 0;
            var manifestBelongsToRequest = requestedPipelineId && currentIdentity === requestedPipelineId;
            var fallbackManifestIsNewRun = !requestedPipelineId && isNewManifest &&
                manifestStartedAt >= Math.floor(baselineObservedAt) && sawCollection;
            if (!markerStatus && manifestCurrent &&
                    (manifestBelongsToRequest || fallbackManifestIsNewRun)) {
                return state.manifest;
            }
            await delay(pollMs);
        }
        throw new Error('Monitoring run did not complete before the timeout');
    };

    var analysisPages = {
        'bgp-analysis.html': { scope: 'bgp', label: 'BGP' },
        'duplicate-analysis.html': { scope: 'duplicate', label: 'duplicate IP/MAC' },
        'link-flap-analysis.html': { scope: 'flap', label: 'link flap' },
        'optical-analysis.html': { scope: 'optical', label: 'optical' },
        'ber-analysis.html': { scope: 'ber', label: 'BER' },
        'pfc-ecn-analysis.html': { scope: 'pfc-ecn', label: 'PFC/ECN' },
        'hardware-analysis.html': { scope: 'hardware', label: 'hardware' },
        'log-analysis.html': { scope: 'logs', label: 'system log' }
    };

    function currentAnalysisPage() {
        var pathname = String(window.location && window.location.pathname || '');
        var filename = pathname.split('/').pop();
        var config = analysisPages[filename];
        if (!config) return null;
        return {
            scope: config.scope,
            label: config.label
        };
    }

    function createAnalysisNotification(config) {
        var previous = document.getElementById('lldpq-analysis-notification');
        if (previous) previous.remove();

        var notification = document.createElement('div');
        notification.id = 'lldpq-analysis-notification';
        notification.setAttribute('role', 'status');
        notification.setAttribute('aria-live', 'polite');
        notification.style.cssText = [
            'position:fixed',
            'top:20px',
            'right:20px',
            'background:#2d2d2d',
            'color:#d4d4d4',
            'padding:15px 20px',
            'border-radius:8px',
            'border-left:4px solid #76b900',
            'box-shadow:0 4px 12px rgba(0,0,0,.4)',
            'z-index:10000',
            'font-size:13px',
            'line-height:1.45',
            'max-width:380px'
        ].join(';');

        var title = document.createElement('strong');
        title.style.color = '#76b900';
        title.textContent = '\u2705 Monitor Analysis Started';
        var message = document.createElement('div');
        message.textContent = 'The ' + config.label +
            ' analysis is running in the background.';
        var detail = document.createElement('small');
        detail.style.color = '#aaa';
        detail.textContent = 'This analysis screen will refresh when its new results are published.';
        notification.appendChild(title);
        notification.appendChild(document.createElement('br'));
        notification.appendChild(message);
        notification.appendChild(detail);
        document.body.appendChild(notification);
        return notification;
    }

    function ensureAnalysisRunnerStyle() {
        if (document.getElementById('lldpq-analysis-runner-style')) return;
        var style = document.createElement('style');
        style.id = 'lldpq-analysis-runner-style';
        style.textContent =
            '@keyframes lldpq-analysis-spin{to{transform:rotate(360deg)}}';
        (document.head || document.documentElement).appendChild(style);
    }

    function setAnalysisButtonRunning(button, running, originalHtml) {
        if (!button) return;
        button.disabled = running;
        if (running) {
            ensureAnalysisRunnerStyle();
            button.setAttribute('aria-busy', 'true');
            button.innerHTML =
                '<svg width="14" height="14" viewBox="0 0 24 24" ' +
                'fill="currentColor" style="animation:lldpq-analysis-spin 1s linear infinite">' +
                '<path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22' +
                'A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 ' +
                '20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 ' +
                '12,4Z"/></svg> Running...';
        } else {
            button.removeAttribute('aria-busy');
            button.innerHTML = originalHtml;
        }
    }

    async function executeScopedPageAnalysis(config, button, originalHtml) {
        var notification = null;
        try {
            var response = await fetch(
                '/trigger-monitor?scope=' + encodeURIComponent(config.scope),
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                }
            );
            var data = await response.json();
            if (!response.ok || !data || data.status !== 'success' ||
                    !data.trigger_id || data.scope !== config.scope) {
                throw new Error((data && (data.message || data.error)) ||
                    'Failed to trigger analysis');
            }

            notification = createAnalysisNotification(config);
            await window.waitForLldpqAnalysisCompletion(null, {
                scope: config.scope,
                pipelineId: data.trigger_id
            });

            // Analysis reports run inside the content iframe. Reload this
            // browsing context only; never reload the LLDPq navigation shell.
            var refreshUrl = new URL(window.location.href);
            refreshUrl.searchParams.set('_analysis_refresh', String(Date.now()));
            window.location.replace(refreshUrl.href);
        } catch (error) {
            if (notification) notification.remove();
            setAnalysisButtonRunning(button, false, originalHtml);
            alert('Analysis did not complete: ' + (error.message || error));
            throw error;
        }
    }

    function runCurrentPageAnalysis() {
        var config = currentAnalysisPage();
        if (!config) return Promise.reject(new Error('Unsupported analysis page'));
        if (window.__lldpqAnalysisRunPromise) return window.__lldpqAnalysisRunPromise;

        var button = document.getElementById('run-analysis');
        if (!button) return Promise.reject(new Error('Run Analysis button is missing'));
        var originalHtml = button.innerHTML;
        setAnalysisButtonRunning(button, true, originalHtml);

        var promise = executeScopedPageAnalysis(config, button, originalHtml);
        window.__lldpqAnalysisRunPromise = promise;
        promise.catch(function () {}).finally(function () {
            window.__lldpqAnalysisRunPromise = null;
        });
        return promise;
    }

    var pageConfig = currentAnalysisPage();
    if (pageConfig) {
        window.__lldpqScopedRunnerVersion = 2;
        window.lldpqRunScopedAnalysis = runCurrentPageAnalysis;
        // Every generated page already uses onclick="runAnalysis()". Replacing
        // that global here gives old preserved reports the same behavior as
        // newly generated ones and removes eight divergent UI implementations.
        window.runAnalysis = runCurrentPageAnalysis;
        document.body.setAttribute('data-analysis-scope', pageConfig.scope);
    }

    // Preserve the current visual structure: reuse the existing timestamp line
    // to state that its snapshot is LKG while a run is collecting or stale.
    readPipelineState().then(function (state) {
        var status = state.marker && state.marker.status;
        if (status !== 'collecting' && status !== 'stale') return;
        var timestamp = document.querySelector('.last-updated');
        if (!timestamp) return;
        var suffix = status === 'collecting'
            ? ' — collection in progress; showing previous report'
            : ' — latest collection failed; showing previous report';
        if (timestamp.textContent.indexOf(suffix) === -1) timestamp.textContent += suffix;
        document.body.setAttribute('data-pipeline-status', status);
    }).catch(function () {});

    function enableKeyboardActivation(element) {
        if (element.hasAttribute('tabindex')) return;
        element.setAttribute('tabindex', '0');
        if (!element.hasAttribute('role')) element.setAttribute('role', 'button');
        element.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                element.click();
            }
        });
    }

    // Accessibility metadata only; no CSS or layout changes.
    document.querySelectorAll('.sortable, .summary-card[onclick]').forEach(enableKeyboardActivation);
    document.querySelectorAll('.sortable').forEach(function (header) {
        header.setAttribute('aria-sort', 'none');
        header.addEventListener('click', function () {
            document.querySelectorAll('.sortable').forEach(function (item) {
                item.setAttribute('aria-sort', 'none');
            });
            header.setAttribute(
                'aria-sort',
                header.classList.contains('desc') ? 'descending' : 'ascending'
            );
        });
    });
    document.querySelectorAll('.threshold-modal, .evpn-modal').forEach(function (modal) {
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
    });
})();
