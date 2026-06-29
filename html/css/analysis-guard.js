/*
 * analysis-guard.js — shared guard for the analysis report pages.
 *
 * The "Run Analysis" button triggers /trigger-monitor, which is admin-only
 * (a full fabric-wide collection). Operators would just get "Failed to trigger
 * analysis", so hide the button for them. Read-only: only toggles visibility.
 *
 * No redirect side-effects (unlike auth.js check()): on any failure / unknown
 * role the button is left as-is, so non-auth deployments keep working.
 */
(function () {
    function guard() {
        fetch('/auth-api?action=check')
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (d && d.role && d.role !== 'admin') {
                    var b = document.getElementById('run-analysis');
                    if (b) b.style.display = 'none';
                }
            })
            .catch(function () { /* leave the button as-is */ });
    }
    if (document.readyState !== 'loading') guard();
    else document.addEventListener('DOMContentLoaded', guard);
})();
