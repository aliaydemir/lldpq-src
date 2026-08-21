/* job-poll.js - shared background-job tracking for the Assets and LLDP pages.
 *
 * Both pages POST a trigger request that returns an opaque token, then poll
 * the matching status file (GET ?token=...) until the daemon confirms the
 * outcome. This module owns the state machine and timers: queued /
 * queue-delayed / queue-stalled / running / worker-stalled / failure /
 * success, the poll cadence, the sessionStorage re-track contract, and the
 * generation counter that cancels callbacks from older tokens. Each page
 * supplies its own UI (button states, notifications, dismiss action, reload
 * behavior) through callbacks. Completion is tied to the token returned by
 * the server; elapsed time is never treated as success.
 */
(function () {
    'use strict';

    if (window.LLDPqJobPoll) return;

    const TOKEN_RE = /^[a-f0-9]{32}$/;

    const DEFAULT_THRESHOLDS = Object.freeze({
        queueDelayedAfterS: 120,    // queued past this: worker likely busy, not dead
        queueStalledAfterS: 1800,   // queued past this: treat the worker as stalled
        runStalledAfterS: 3600,     // running without a status update: stalled
        retryOverdueAfterS: 300     // scheduled retry this overdue: stalled
    });

    function create(config) {
        const triggerUrl = config.triggerUrl;
        const storageKey = config.storageKey;
        const jobLabel = config.jobLabel;
        const jobNotFoundMessage = config.jobNotFoundMessage;
        const waitingReason = config.waitingReason;
        const thresholds = Object.assign({}, DEFAULT_THRESHOLDS, config.thresholds || {});
        const callbacks = config.callbacks || {};

        let activeToken = null;
        let generation = 0;
        let pollTimer = null;

        function setStoredToken(token) {
            try {
                if (token) sessionStorage.setItem(storageKey, token);
                else sessionStorage.removeItem(storageKey);
            } catch (_) {
                // Private-storage restrictions must not break the live poll.
            }
        }

        function getStoredToken() {
            try {
                return sessionStorage.getItem(storageKey) || '';
            } catch (_) {
                return '';
            }
        }

        function schedulePoll(token, gen, delayMs) {
            if (token !== activeToken || gen !== generation) return;
            if (pollTimer) clearTimeout(pollTimer);
            pollTimer = setTimeout(() => poll(token, gen), delayMs);
        }

        async function poll(token, gen) {
            if (token !== activeToken || gen !== generation) return;
            try {
                const response = await fetch(`${triggerUrl}?token=${encodeURIComponent(token)}`, {
                    method: 'GET',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'application/json',
                        'Cache-Control': 'no-cache'
                    }
                });
                const data = await response.json();
                if (callbacks.onAuthRejected &&
                    (response.status === 401 || response.status === 403) &&
                    data && data.success === false) {
                    // auth-guard rejected the session. Polling with a dead
                    // session can never succeed; stop instead of retrying.
                    // The stored token survives so a re-login can re-track.
                    activeToken = null;
                    generation += 1;
                    callbacks.onAuthRejected(data);
                    return;
                }
                if (data.status === 'error' && data.message === jobNotFoundMessage) {
                    // A persisted session token may outlive the server-side TTL
                    // or a restored installation.  This one response is
                    // terminal for that token; network/auth/transient status
                    // errors below remain retriable.
                    setStoredToken('');
                    activeToken = null;
                    generation += 1;
                    callbacks.onJobMissing(data);
                    return;
                }
                if (!response.ok || data.status === 'error') {
                    throw new Error(data.error || data.message || `Status request failed (${response.status})`);
                }
                if (data.token !== token || token !== activeToken || gen !== generation) {
                    return; // Never let an older/different request act on this page.
                }

                const reason = data.reason || waitingReason;
                if (data.status === 'success') {
                    // Clear the stored token before the page reloads its
                    // report, so a failed refresh can never re-trigger a
                    // completed job loop.
                    setStoredToken('');
                    callbacks.onSuccess(data);
                    return;
                }
                const nowSeconds = Math.floor(Date.now() / 1000);
                const statusAge = data.updated_at ? nowSeconds - data.updated_at : 0;
                const retryOverdue = data.status === 'failure' && data.retry_scheduled &&
                    data.next_retry_at && nowSeconds - data.next_retry_at > thresholds.retryOverdueAfterS;
                const queueStalled = data.status === 'queued' && statusAge > thresholds.queueStalledAfterS;
                const queueDelayed = data.status === 'queued' && statusAge > thresholds.queueDelayedAfterS &&
                    !queueStalled;
                const workerStalled = (data.status === 'running' && statusAge > thresholds.runStalledAfterS) ||
                    queueStalled || retryOverdue;
                if (queueDelayed) {
                    // lldpq-trigger serializes LLDP and Assets work.  An
                    // earlier request may therefore keep a healthy token
                    // queued for more than two minutes; delay alone is not a
                    // job failure.
                    callbacks.onQueueDelayed(reason, data);
                    schedulePoll(token, gen, 15000);
                    return;
                }
                if (workerStalled) {
                    // A dead worker can leave a token queued/running
                    // indefinitely. The page should enable retry and offer an
                    // explicit escape from tracking so its trigger button can
                    // never be disabled permanently.
                    callbacks.onStalled(reason, data);
                    schedulePoll(token, gen, 15000);
                    return;
                }
                if (data.status === 'running') {
                    callbacks.onRunning(reason, data);
                    schedulePoll(token, gen, 2000);
                    return;
                }
                if (data.status === 'queued') {
                    callbacks.onQueued(reason, data);
                    const queuedDelay = data.next_retry_at
                        ? Math.max(2000, Math.min(10000, data.next_retry_at * 1000 - Date.now() + 500))
                        : 2000;
                    schedulePoll(token, gen, queuedDelay);
                    return;
                }
                if (data.status === 'failure') {
                    callbacks.onFailure(reason, data);
                    if (data.retry_scheduled) {
                        const retryDelay = data.next_retry_at
                            ? Math.max(5000, Math.min(30000, data.next_retry_at * 1000 - Date.now() + 1000))
                            : 10000;
                        schedulePoll(token, gen, retryDelay);
                    } else {
                        setStoredToken('');
                        activeToken = null;
                    }
                    return;
                }
                throw new Error(`Unknown ${jobLabel} job state: ${data.status}`);
            } catch (error) {
                if (token !== activeToken || gen !== generation) return;
                callbacks.onPollError(error);
                schedulePoll(token, gen, 5000);
            }
        }

        function track(token) {
            if (!TOKEN_RE.test(token)) return false;
            activeToken = token;
            generation += 1;
            const gen = generation;
            setStoredToken(token);
            callbacks.onTracked();
            schedulePoll(token, gen, 250);
            return true;
        }

        async function submit() {
            // Cancel/ignore all callbacks associated with an older token.
            generation += 1;
            activeToken = null;
            if (pollTimer) clearTimeout(pollTimer);
            callbacks.onSubmitStart();
            try {
                const response = await fetch(triggerUrl, {
                    method: 'POST',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache'
                    }
                });
                const data = await response.json();
                if (!response.ok || data.status !== 'started' ||
                    !TOKEN_RE.test(data.token || '')) {
                    throw new Error(data.error || data.message || 'Trigger failed');
                }
                callbacks.onSubmitted(data.token);
                track(data.token);
            } catch (error) {
                setStoredToken('');
                callbacks.onSubmitError(error);
            }
        }

        function dismiss() {
            generation += 1;
            activeToken = null;
            if (pollTimer) {
                clearTimeout(pollTimer);
                pollTimer = null;
            }
            setStoredToken('');
            callbacks.onDismissed();
        }

        function stopTracking() {
            // Silent reset used by success handlers that keep the page alive
            // (in-place report reload): stray poll callbacks for the completed
            // token must be ignored without touching the stored token or UI.
            activeToken = null;
            generation += 1;
        }

        function retrackStored() {
            const pendingToken = getStoredToken();
            if (TOKEN_RE.test(pendingToken)) track(pendingToken);
        }

        return { submit, track, dismiss, stopTracking, retrackStored };
    }

    window.LLDPqJobPoll = { create };
}());
