// The "Update Available" popup must not hand a Docker operator one command.
//
// It used to show `curl ... | docker load && docker compose up -d`. On a
// container created with `docker run`, the documented way on a Cumulus
// switch, that loads the new image and leaves the old container running.
// showUpdateInfo() is cut out of index.html and run against a stub page: for
// a Docker deployment the popup has to point at the update steps of the
// Docker guide, to be run on the host, and offer no command to copy; for a
// native installation it has to be what it was.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page = fs.readFileSync(new URL('../html/index.html', import.meta.url), 'utf8');
const start = page.indexOf('async function showUpdateInfo()');
const source = page.slice(start, page.indexOf('function updGoToUpdate()', start));
const GUIDE = 'https://github.com/aliaydemir/lldpq-src/blob/main/DOCKER.md#updating';

async function popup({ docker, admin = true }) {
    assert.ok(start > 0, 'showUpdateInfo() is missing from index.html');
    const created = [];
    const context = vm.createContext({
        fetch: async () => ({ json: async () => ({ docker }) }),
        window: { LLDPqAuth: { isAdmin: () => admin } },
        LLDPqAuth: { isAdmin: () => admin },
        localVersion: '4.2.4', remoteVersion: '4.3.0',
        document: {
            createElement() { const element = { style: {} }; created.push(element); return element; },
            body: { appendChild() {} },
        },
    });
    vm.runInContext(source, context);
    await context.showUpdateInfo();
    assert.equal(created.length, 1);
    const html = created[0].innerHTML;
    return { html, command: html.match(/<pre id="upd-cmd"[^>]*>([^<]*)<\/pre>/)[1] };
}

test('Docker deployment: the popup points at the guide, to be followed on the host', async () => {
    const { html, command } = await popup({ docker: true });
    assert.equal(command, GUIDE);
    assert.doesNotMatch(html, /docker load|docker compose|gunzip/);
    assert.match(html, /Update on the <b[^>]*>host<\/b> with the steps under <b[^>]*>Updating<\/b> in DOCKER\.md/);
    assert.match(html, /<code>docker run<\/code>/);
    assert.match(html, /loading the new image alone leaves the old container running/);
    // A container cannot update itself: no button that starts the native update.
    assert.doesNotMatch(html, /updGoToUpdate/);
    assert.match(html, /v4\.2\.4/);
    assert.match(html, /v4\.3\.0/);
});

test('native installation: the popup is unchanged', async () => {
    const { html, command } = await popup({ docker: false });
    assert.equal(command, 'cd ~/lldpq-src\ngit pull\n./install.sh');
    assert.match(html, /Setup &rarr; Update LLDPq/);
    assert.match(html, /updGoToUpdate\(\)/);
    assert.doesNotMatch(html, /DOCKER\.md/);
});
