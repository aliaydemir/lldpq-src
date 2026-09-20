import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../html/css/job-poll.js', import.meta.url), 'utf8');
const A = 'a'.repeat(32);
const B = 'b'.repeat(32);
function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}
function response(data, status = 200) {
    return { ok: status >= 200 && status < 300, status, json: async () => data };
}
function harness(overrides = {}) {
    const storage = new Map();
    const timers = new Map();
    const requests = [];
    const events = [];
    let timerId = 0;
    const callbacks = new Proxy({}, { get: (_, key) => (...args) => {
        events.push([key, ...args]);
        if (overrides[key]) overrides[key](...args);
    } });
    const context = {
        window: {},
        sessionStorage: {
            setItem: (key, value) => storage.set(key, value),
            getItem: key => storage.get(key),
            removeItem: key => storage.delete(key),
        },
        setTimeout: fn => { timers.set(++timerId, fn); return timerId; },
        clearTimeout: id => timers.delete(id),
        fetch: (url, options) => {
            const pending = deferred();
            requests.push({ url, options, ...pending });
            return pending.promise;
        },
    };
    vm.runInNewContext(source, context);
    const tracker = context.window.LLDPqJobPoll.create({
        triggerUrl: '/trigger', storageKey: 'pending', jobLabel: 'Assets',
        jobNotFoundMessage: 'Job not found', waitingReason: 'Waiting', callbacks,
    });
    function pollNext() {
        const [id, fn] = timers.entries().next().value;
        timers.delete(id);
        return fn();
    }
    return { tracker, storage, events, requests, pollNext };
}

const staleResponses = [
    ['missing', response({ status: 'error', message: 'Job not found' }, 404)],
    ['auth 401', response({ success: false }, 401)],
    ['auth 403', response({ success: false }, 403)],
    ['server error', response({ status: 'error', error: 'Busy' }, 500)],
    ['success', response({ status: 'success', token: A })],
    ['failure', response({ status: 'failure', token: A })],
    ['malformed JSON', { ok: false, status: 502, json: async () => { throw Error('Invalid JSON'); } }],
];
for (const [label, reply] of staleResponses) {
    test(`stale poll ${label} leaves the new token and callbacks intact`, async () => {
        const h = harness();
        h.tracker.track(A);
        const oldPoll = h.pollNext();
        h.tracker.track(B);
        const before = h.events.length;
        h.requests[0].resolve(reply);
        await oldPoll;
        assert.equal(h.storage.get('pending'), B);
        assert.equal(h.events.length, before);
        const newPoll = h.pollNext();
        assert.equal(h.requests.length, 2);
        assert.match(h.requests[1].url, new RegExp(B));
        h.requests[1].resolve(response({ status: 'running', token: B }));
        await newPoll;
        assert.equal(h.events.at(-1)[0], 'onRunning');
    });
}

test('generation is checked after delayed JSON parsing, even for the same token', async () => {
    const h = harness();
    const body = deferred();
    h.tracker.track(A);
    const oldPoll = h.pollNext();
    h.requests[0].resolve({ status: 404, ok: false, json: () => body.promise });
    await Promise.resolve();
    h.tracker.dismiss();
    h.tracker.track(A);
    const before = h.events.length;
    body.resolve({ status: 'error', message: 'Job not found' });
    await oldPoll;
    assert.equal(h.storage.get('pending'), A);
    assert.equal(h.events.length, before);
});

for (const fail of [false, true]) {
    test(`superseded submit ${fail ? 'failure' : 'success'} cannot replace new tracking`, async () => {
        const h = harness();
        const oldSubmit = h.tracker.submit();
        const newSubmit = h.tracker.submit();
        h.requests[1].resolve(response({ status: 'started', token: B }));
        await newSubmit;
        const before = h.events.length;
        if (fail) h.requests[0].reject(Error('Network failed'));
        else h.requests[0].resolve(response({ status: 'started', token: A }));
        await oldSubmit;
        assert.equal(h.storage.get('pending'), B);
        assert.equal(h.events.length, before);
        const poll = h.pollNext();
        h.requests[2].resolve(response({ token: B, status: 'success' }));
        await poll;
        assert.equal(h.events.at(-1)[0], 'onSuccess');
    });
}

test('dismissed submit cannot resurrect tracking', async () => {
    const h = harness();
    const submit = h.tracker.submit();
    h.tracker.dismiss();
    const before = h.events.length;
    h.requests[0].resolve(response({ status: 'started', token: A }));
    await submit;
    assert.equal(h.storage.has('pending'), false);
    assert.equal(h.events.length, before);
});

test('a terminal failure callback can immediately track a replacement job', async () => {
    const h = harness({ onFailure: () => h.tracker.track(B) });
    h.tracker.track(A);
    const poll = h.pollNext();
    h.requests[0].resolve(response({ status: 'failure', token: A }));
    await poll;
    assert.equal(h.storage.get('pending'), B);
    const nextPoll = h.pollNext();
    assert.match(h.requests[1].url, new RegExp(B));
    h.requests[1].resolve(response({ status: 'running', token: B }));
    await nextPoll;
    assert.equal(h.events.at(-1)[0], 'onRunning');
});

test('onSubmitted can dismiss without submit re-starting the job', async () => {
    const h = harness({ onSubmitted: () => h.tracker.dismiss() });
    const submit = h.tracker.submit();
    h.requests[0].resolve(response({ status: 'started', token: A }));
    await submit;
    assert.equal(h.storage.has('pending'), false);
    assert.equal(h.events.at(-1)[0], 'onDismissed');
});

for (const [label, reply, callback, stored] of [
    ['missing', staleResponses[0][1], 'onJobMissing', false],
    ['auth', staleResponses[1][1], 'onAuthRejected', true],
    ['success', response({ status: 'success', token: A }), 'onSuccess', false],
]) {
    test(`current ${label} response still performs its terminal action`, async () => {
        const h = harness();
        h.tracker.track(A);
        const poll = h.pollNext();
        h.requests[0].resolve(reply);
        await poll;
        assert.equal(h.events.at(-1)[0], callback);
        assert.equal(h.storage.has('pending'), stored);
    });
}
