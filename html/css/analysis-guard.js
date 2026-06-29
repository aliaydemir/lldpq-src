/*
 * analysis-guard.js — hide the admin-only "Run Analysis" button for operators.
 *
 * The button triggers /trigger-monitor (a full fabric-wide collection) which is
 * admin-only; an operator would only get "Failed to trigger analysis", so the
 * button should not be shown to them.
 *
 * Flicker-free: this script sits at end-of-body, so it runs before first paint.
 * It first hides synchronously using the role cached by auth.js (written when the
 * app shell ran its auth check), so operators never see the button flash. It then
 * confirms/refreshes the role from /auth-api. Read-only and side-effect free:
 * no redirect, and on any failure / unknown role the button is left as-is, so
 * non-auth deployments keep working.
 */
(function () {
    function setHidden(hidden) {
        var b = document.getElementById('run-analysis');
        if (b) b.style.display = hidden ? 'none' : '';
    }

    // 1) Synchronous fast-path from the cached role -> no network, no flicker.
    var cached = null;
    try { cached = localStorage.getItem('lldpq_role'); } catch (e) {}
    if (cached && cached !== 'admin') setHidden(true);

    // 2) Confirm / refresh from the server (covers first visit or a stale cache).
    fetch('/auth-api?action=check')
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d && d.role) {
                try { localStorage.setItem('lldpq_role', d.role); } catch (e) {}
                if (d.role !== 'admin') setHidden(true);
            }
        })
        .catch(function () { /* leave the button as-is */ });
})();
