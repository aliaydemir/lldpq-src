/*
 * LLDPq shared dark-themed dialogs — replaces native browser alert()/confirm()/prompt().
 *
 * Self-contained: injects its own CSS and exposes global helpers under unique lldpq*
 * names so it never collides with any page-specific showToast / showConfirmModal.
 *
 *   lldpqToast(message, type[, timeoutMs])      — non-blocking notification (success|error|info|warning)
 *   lldpqConfirm(title, htmlMessage, onConfirm[, opts])  — dark confirm modal (Cancel / action)
 *   lldpqPrompt(title, label, defaultVal, onSubmit[, opts]) — dark single-line text-input modal
 *   lldpqInfo(title, htmlMessage[, opts])       — dark info modal (single OK button)
 *
 * It also overrides window.alert so any remaining native alert() call is rendered in
 * our dark theme instead of the OS popup: single-line -> toast, multi-line -> info modal.
 * Type is inferred from the message (validation/error keywords checked before success ones).
 * confirm()/prompt() are NOT overridden (they return values synchronously) — those call
 * sites are converted to lldpqConfirm/lldpqPrompt explicitly.
 */
(function () {
    if (window.__lldpqDialogsLoaded) return;
    window.__lldpqDialogsLoaded = true;

    var CSS = [
        '.lldpq-toast-wrap{position:fixed;bottom:20px;right:20px;z-index:2147483000;display:flex;flex-direction:column;gap:10px;align-items:flex-end;pointer-events:none;}',
        '.lldpq-toast{pointer-events:auto;padding:12px 18px;border-radius:6px;font-size:13px;font-family:inherit;line-height:1.45;max-width:420px;box-shadow:0 6px 24px rgba(0,0,0,.4);opacity:0;transform:translateX(120%);transition:opacity .25s ease,transform .25s ease;white-space:pre-line;}',
        '.lldpq-toast.show{opacity:1;transform:translateX(0);}',
        '.lldpq-toast-success{background:#1b5e20;color:#c8e6c9;border:1px solid #2e7d32;}',
        '.lldpq-toast-error{background:#4a1515;color:#ffcdd2;border:1px solid #c62828;}',
        '.lldpq-toast-info{background:#0d3b66;color:#bbdefb;border:1px solid #1565c0;}',
        '.lldpq-toast-warning{background:#5a4300;color:#ffe0a3;border:1px solid #b58100;}',
        '.lldpq-modal{display:none;position:fixed;inset:0;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:2147483001;justify-content:center;align-items:center;font-family:inherit;}',
        '.lldpq-modal.visible{display:flex;}',
        '.lldpq-modal-box{background:#2d2d2d;border-radius:8px;width:440px;max-width:92%;box-shadow:0 10px 40px rgba(0,0,0,.5);overflow:hidden;}',
        '.lldpq-modal-head{padding:14px 20px;display:flex;justify-content:space-between;align-items:center;}',
        '.lldpq-modal-head.danger{background:linear-gradient(135deg,#c53030 0%,#9b2c2c 100%);}',
        '.lldpq-modal-head.info{background:linear-gradient(135deg,#1565c0 0%,#0d3b66 100%);}',
        '.lldpq-modal-head h3{margin:0;color:#fff;font-size:16px;font-weight:600;}',
        '.lldpq-modal-x{background:none;border:none;color:#fff;font-size:24px;line-height:1;cursor:pointer;opacity:.8;padding:0;}',
        '.lldpq-modal-x:hover{opacity:1;}',
        '.lldpq-modal-body{padding:22px 20px;}',
        '.lldpq-modal-body p{color:#ccc;line-height:1.6;margin:0;text-align:center;white-space:pre-line;word-break:break-word;}',
        '.lldpq-modal-body label{display:block;color:#aaa;font-size:12px;margin-bottom:6px;}',
        '.lldpq-modal-in{width:100%;box-sizing:border-box;background:#1a1a1a;border:1px solid #3c3c3c;border-radius:4px;color:#fff;padding:10px 12px;font-size:14px;font-family:inherit;}',
        '.lldpq-modal-in:focus{outline:none;border-color:#76b900;}',
        '.lldpq-modal-in:-webkit-autofill,.lldpq-modal-in:-webkit-autofill:hover,.lldpq-modal-in:-webkit-autofill:focus{-webkit-box-shadow:0 0 0 1000px #1a1a1a inset !important;-webkit-text-fill-color:#fff !important;caret-color:#fff !important;}',
        '.lldpq-modal-foot{padding:14px 20px;display:flex;justify-content:flex-end;gap:10px;background:#252526;border-top:1px solid #3c3c3c;}',
        '.lldpq-btn{border:none;padding:9px 20px;border-radius:4px;cursor:pointer;font-size:13px;font-family:inherit;}',
        '.lldpq-btn-cancel{background:#3c3c3c;color:#d4d4d4;}',
        '.lldpq-btn-cancel:hover{background:#4a4a4a;}',
        '.lldpq-btn-danger{background:#c53030;color:#fff;}',
        '.lldpq-btn-danger:hover{background:#e53e3e;}',
        '.lldpq-btn-primary{background:#76b900;color:#0a0a0a;font-weight:600;}',
        '.lldpq-btn-primary:hover{background:#8fd400;}'
    ].join('');

    function injectCSS() {
        if (document.getElementById('lldpq-dialogs-css')) return;
        var s = document.createElement('style');
        s.id = 'lldpq-dialogs-css';
        s.textContent = CSS;
        (document.head || document.documentElement).appendChild(s);
    }

    // ------------------------------------------------------------ toast
    function toastWrap() {
        var w = document.getElementById('lldpq-toast-wrap');
        if (!w) {
            w = document.createElement('div');
            w.id = 'lldpq-toast-wrap';
            w.className = 'lldpq-toast-wrap';
            document.body.appendChild(w);
        }
        return w;
    }
    window.lldpqToast = function (message, type, timeout) {
        injectCSS();
        type = type || 'info';
        timeout = timeout || 4000;
        var el = document.createElement('div');
        el.className = 'lldpq-toast lldpq-toast-' + type;
        el.textContent = (message == null) ? '' : String(message);
        toastWrap().appendChild(el);
        requestAnimationFrame(function () { el.classList.add('show'); });
        setTimeout(function () {
            el.classList.remove('show');
            setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 300);
        }, timeout);
    };

    // ------------------------------------------------------------ modal (shared singleton)
    var _modal, _head, _title, _body, _foot, _onEsc, _pendingCancel;
    function ensureModal() {
        injectCSS();
        if (_modal) return;
        _modal = document.createElement('div');
        _modal.className = 'lldpq-modal';
        _modal.innerHTML =
            '<div class="lldpq-modal-box">' +
              '<div class="lldpq-modal-head"><h3></h3><button class="lldpq-modal-x" type="button">&times;</button></div>' +
              '<div class="lldpq-modal-body"></div>' +
              '<div class="lldpq-modal-foot"></div>' +
            '</div>';
        document.body.appendChild(_modal);
        _head = _modal.querySelector('.lldpq-modal-head');
        _title = _modal.querySelector('.lldpq-modal-head h3');
        _body = _modal.querySelector('.lldpq-modal-body');
        _foot = _modal.querySelector('.lldpq-modal-foot');
        _modal.querySelector('.lldpq-modal-x').addEventListener('click', closeModal);
        _modal.addEventListener('click', function (e) { if (e.target === _modal) closeModal(); });
    }
    function closeModal() {
        if (_modal) _modal.classList.remove('visible');
        if (_onEsc) { document.removeEventListener('keydown', _onEsc); _onEsc = null; }
        // If a dialog registered a cancel handler (e.g. prompt), fire it once on dismiss.
        var c = _pendingCancel; _pendingCancel = null;
        if (typeof c === 'function') c();
    }
    function openModal(kind) {
        _head.className = 'lldpq-modal-head ' + (kind || 'info');
        _modal.classList.add('visible');
        _onEsc = function (e) { if (e.key === 'Escape') closeModal(); };
        document.addEventListener('keydown', _onEsc);
    }
    function mkBtn(text, cls, fn) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'lldpq-btn ' + cls;
        b.textContent = text;
        b.addEventListener('click', fn);
        return b;
    }

    window.lldpqConfirm = function (title, message, onConfirm, opts) {
        opts = opts || {};
        ensureModal();
        _title.textContent = title || 'Confirm';
        _body.innerHTML = '<p>' + (message == null ? '' : message) + '</p>';
        var t = (title || '').toLowerCase(), action = opts.confirmText;
        if (!action) {
            action = t.indexOf('delete') >= 0 ? 'Delete'
                   : t.indexOf('remove') >= 0 ? 'Remove'
                   : t.indexOf('stop') >= 0 ? 'Stop'
                   : t.indexOf('discard') >= 0 ? 'Discard'
                   : t.indexOf('generate') >= 0 ? 'Generate'
                   : 'Confirm';
        }
        var danger = (opts.danger !== false);
        _foot.innerHTML = '';
        _foot.appendChild(mkBtn(opts.cancelText || 'Cancel', 'lldpq-btn-cancel', closeModal));
        var ok = mkBtn(action, danger ? 'lldpq-btn-danger' : 'lldpq-btn-primary', function () {
            closeModal();
            if (typeof onConfirm === 'function') onConfirm();
        });
        _foot.appendChild(ok);
        openModal(danger ? 'danger' : 'info');
        setTimeout(function () { ok.focus(); }, 30);
    };

    window.lldpqInfo = function (title, message, opts) {
        opts = opts || {};
        ensureModal();
        _title.textContent = title || 'Notice';
        _body.innerHTML = '<p>' + (message == null ? '' : message) + '</p>';
        _foot.innerHTML = '';
        var ok = mkBtn(opts.okText || 'OK', 'lldpq-btn-primary', closeModal);
        _foot.appendChild(ok);
        openModal('info');
        setTimeout(function () { ok.focus(); }, 30);
    };

    window.lldpqPrompt = function (title, label, defaultValue, onSubmit, opts) {
        opts = opts || {};
        ensureModal();
        _title.textContent = title || 'Input';
        _body.innerHTML = '';
        if (label) { var l = document.createElement('label'); l.textContent = label; _body.appendChild(l); }
        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'lldpq-modal-in';
        input.value = (defaultValue == null) ? '' : defaultValue;
        input.setAttribute('autocomplete', 'off');
        _body.appendChild(input);
        var done = false;
        function submit() {
            if (done) return; done = true;
            var v = input.value.trim();
            _pendingCancel = null;
            closeModal();
            if (v && typeof onSubmit === 'function') onSubmit(v);
            else if (!v && typeof opts.onCancel === 'function') opts.onCancel();
        }
        // Dismiss via X / backdrop / Esc / Cancel button -> treat as cancel.
        _pendingCancel = function () { if (!done) { done = true; if (typeof opts.onCancel === 'function') opts.onCancel(); } };
        _foot.innerHTML = '';
        _foot.appendChild(mkBtn(opts.cancelText || 'Cancel', 'lldpq-btn-cancel', closeModal));
        _foot.appendChild(mkBtn(opts.okText || 'OK', 'lldpq-btn-primary', submit));
        openModal('info');
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); submit(); }
        });
        setTimeout(function () { input.focus(); input.select(); }, 30);
    };

    // ------------------------------------------------------------ native alert() -> dark UI
    var _errRe = /(error|fail|invalid|required|must |cannot|unable|maximum|minimum|no data|not found|denied|forbidden|please select|please enter|at least|only|already exists)/;
    var _okRe = /(success|created|updated|deleted|removed|applied|saved|added|assigned|enabled|disabled|complete|done)/;
    function inferType(m) {
        var s = m.toLowerCase();
        if (_errRe.test(s)) return 'error';
        if (_okRe.test(s)) return 'success';
        return 'info';
    }
    window.alert = function (message) {
        var m = (message == null) ? '' : String(message);
        var type = inferType(m);
        if (m.indexOf('\n') >= 0) {
            var title = (type === 'error') ? 'Error' : (type === 'success' ? 'Done' : 'Notice');
            lldpqInfo(title, m.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>'));
        } else {
            lldpqToast(m, type);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectCSS);
    } else {
        injectCSS();
    }
})();
