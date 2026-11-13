// Login page: an accepted login whose session cookie the browser did not keep.
//
// A browser that signed in over HTTPS holds a Secure session cookie and drops
// the cookie of a later login over http:// to the same host. The login was
// accepted, the page went to "/" and the login page came back without a word.
// The page now asks the session check before it leaves. The real page script
// is run in node:vm.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const page = read('html/login.html');
const script = page.slice(page.lastIndexOf('<script>') + '<script>'.length, page.lastIndexOf('</script>'));

// The page with the given replies; `check` answers the session check that
// follows an accepted login (the check at page load always says "no session").
function loginPage({ login, check, protocol = 'http:' }) {
    const elements = {};
    const element = id => elements[id] ||= {
        value: '', checked: false, disabled: false, textContent: '', shown: false,
        classList: { add() { elements[id].shown = true; }, remove() { elements[id].shown = false; } },
    };
    const location = { protocol, href: protocol + '//lldpq.test/login.html' };
    const requests = [];
    let checks = 0;
    const window = { location };
    window.top = window;
    const context = vm.createContext({
        window, encodeURIComponent,
        document: { getElementById: element },
        fetch: async (url, options = {}) => {
            requests.push({ url, cache: options.cache });
            if (url === '/auth-api?action=login') return { json: async () => login };
            assert.equal(url, '/auth-api?action=check');
            if (checks++ === 0) return { json: async () => ({ authenticated: false }) };
            if (check instanceof Error) throw check;
            return { json: async () => check };
        },
    });
    vm.runInContext(script, context);
    return { context, element, location, requests };
}

async function signIn(options) {
    const p = loginPage(options);
    await new Promise(resolve => setImmediate(resolve));
    p.element('username').value = 'admin';
    p.element('password').value = 'invented';
    await p.context.handleLogin({ preventDefault() {} });
    return p;
}

test('an accepted login whose cookie was kept goes to the application', async () => {
    const p = await signIn({ login: { success: true }, check: { authenticated: true } });
    assert.equal(p.location.href, '/');
    assert.equal(p.element('error-message').shown, false);
    // The check after the login must not be answered from a cache
    assert.deepEqual(p.requests.at(-1), { url: '/auth-api?action=check', cache: 'no-store' });
});

test('an accepted login over http:// whose cookie was dropped stays and says why', async () => {
    const p = await signIn({ login: { success: true }, check: { authenticated: false } });
    assert.equal(p.location.href, 'http://lldpq.test/login.html');
    const message = p.element('error-message');
    assert.equal(message.shown, true);
    assert.match(message.textContent, /^Signed in, but this browser did not keep the session cookie\. /);
    assert.match(message.textContent, /use the https:\/\/ address, or delete the lldpq_session cookie of this host/);
    assert.equal(p.element('login-btn').disabled, false);
    assert.equal(p.element('login-btn').textContent, 'Sign In');
    // The cookie the message names is the one the login sets
    assert.match(read('html/auth-api.sh'), /Set-Cookie: lldpq_session=/);
});

test('the same over https:// does not point at an HTTPS session', async () => {
    const p = await signIn({ login: { success: true }, check: { authenticated: false }, protocol: 'https:' });
    assert.equal(p.location.href, 'https://lldpq.test/login.html');
    const message = p.element('error-message');
    assert.equal(message.shown, true);
    assert.equal(message.textContent,
        'Signed in, but this browser did not keep the session cookie. Allow cookies for this host and sign in again.');
});

test('a session check that cannot be made leaves the page as before', async () => {
    const p = await signIn({ login: { success: true }, check: new Error('network down') });
    assert.equal(p.location.href, '/');
    assert.equal(p.element('error-message').shown, false);
});

test('a refused login shows the error of the reply and asks nothing else', async () => {
    const p = await signIn({ login: { success: false, error: 'Too many login attempts' } });
    assert.equal(p.location.href, 'http://lldpq.test/login.html');
    assert.equal(p.element('error-message').textContent, 'Too many login attempts');
    assert.deepEqual(p.requests.map(request => request.url),
        ['/auth-api?action=check', '/auth-api?action=login']);
});
