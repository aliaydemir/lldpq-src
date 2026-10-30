import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../html/fabric-migration.html', import.meta.url), 'utf8');
function fragment(start, end) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }
test('bounce and selected plan are submitted once and stay fixed through confirmation', async () => {
    const submissions = [], saved = [];
    let confirm;
    const checkbox = {checked: true};
    const context = vm.createContext({
        appliedPlan: {id: 'plan-1', changes: {leaf1: {applied: [{name: 'swp1'}]}}},
        $: () => checkbox, planDevices: () => ['leaf1'],
        confirmAsync: () => new Promise(resolve => {confirm = resolve;}),
        clearTerm() {}, termAppend() {}, showLoading() {},
        ansibleApiCall: async (...args) => { submissions.push(args); return {started: true, job_id: 'job-1'}; },
        localStorage: {setItem: (...args) => saved.push(args)}, DEPLOY_JOB_KEY: 'job',
        pollDeployStatus: async (...args) => {assert.equal(args.length, 1); assert.equal(args[0], 'job-1');}
    });
    vm.runInContext(fragment('    async function runDeploy()', '    // ---------- Step 5:'), context);
    const deploying = context.runDeploy();
    context.appliedPlan = {id: 'plan-2', changes: {leaf2: {applied: [{name: 'swp2'}]}}};
    checkbox.checked = false;
    confirm(true);
    await deploying;
    assert.equal(submissions.length, 1);
    assert.deepEqual(JSON.parse(JSON.stringify(submissions[0])), ['deploy', 'leaf1', {bounce_plan: 'plan-1'}]);
    assert.equal(JSON.parse(saved[0][1]).plan.id, 'plan-1');
});
test('deploy posts the bounce plan together with the host list', async () => {
    const calls = [];
    const context = vm.createContext({URLSearchParams, fetch: async (...args) => {
        calls.push(args); return {json: async () => ({started: true})};
    }});
    vm.runInContext(fragment('    async function ansibleApiCall(', '    async function runGenerate('), context);
    await context.ansibleApiCall('deploy', 'leaf1', {bounce_plan: 'plan-1'});
    assert.equal(calls.length, 1);
    assert.equal(calls[0][1].method, 'POST');
    assert.deepEqual(JSON.parse(calls[0][1].body), {host: 'leaf1', bounce_plan: 'plan-1'});
});
