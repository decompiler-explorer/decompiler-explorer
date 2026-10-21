// Run with: node --test tests/js/upload.test.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function fixture({valid = true, response, failure, fetchResponse} = {}) {
    const handlers = {};
    const calls = {fetch: 0, alerts: [], history: [], validity: 0};
    const state = {text: 'previous decompilation'};
    const button = {hidden: false, addEventListener() {}};
    const form = {checkValidity: () => valid,
        reportValidity: () => calls.validity++};
    const elements = {
        decompilers_json: {textContent: JSON.stringify({demo: {featured: true}})},
        binary_upload_form: form,
        file: {addEventListener: (event, callback) => handlers[event] = callback},
        samples: {value: '', children: [], childElementCount: 0, addEventListener() {}},
    };
    const document = {
        getElementById: id => elements[id] || null,
        getElementsByClassName: name => {
            if (name === 'decompiler_output') return [{id: 'demo'}];
            if (name === 'decompiler_rerun') return [{id: 'rerun_demo', ...button}];
            return [];
        },
        querySelector: selector => selector.includes('csrf') ? {value: 'csrf'} : {},
    };
    const editor = {setReadOnly() {}, setHighlightActiveLine() {},
        setHighlightGutterLine() {}, resize() {},
        session: {setMode() {}, selection: {on() {}},
            getDocument: () => ({setValue: text => state.text = text})}};
    const context = vm.createContext({document, ace: {config: {set() {}}, edit: () => editor},
        location: {origin: 'https://example.test', pathname: '/', hash: '',
            toString: () => 'https://example.test/'},
        URL, URLSearchParams, console: {error() {}},
        setTimeout() {}, clearTimeout() {}, FormData: class {},
        alert: error => calls.alerts.push(String(error)),
        fetch: async () => {
            calls.fetch++;
            if (fetchResponse) return await fetchResponse(calls.fetch);
            if (failure) throw failure;
            return await response;
        },
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../static/js/index.js'), 'utf8'), context);
    context.recordHistory = id => calls.history.push(id);
    vm.runInContext(`resultUrl = 'old-results';
        addHistoryEntry = recordHistory;
        loadResults = () => {};
    `, context);
    return {calls, state, select: files => handlers.change({preventDefault() {}, target: {files}}),
        url: () => vm.runInContext('resultUrl', context)};
}

const settle = () => new Promise(resolve => setImmediate(resolve));
const selected = [{}];

test('canceling selection keeps the previous results and URL', async () => {
    const f = fixture();
    f.select([]);
    await settle();
    assert.equal(f.calls.fetch, 0);
    assert.equal(f.state.text, 'previous decompilation');
    assert.equal(f.url(), 'old-results');
});

test('invalid form keeps results and reports validity', async () => {
    const f = fixture({valid: false});
    f.select(selected);
    await settle();
    assert.equal(f.calls.fetch, 0);
    assert.equal(f.calls.validity, 1);
    assert.equal(f.state.text, 'previous decompilation');
});

for (const status of [413, 429, 500]) {
    test(`HTTP ${status} keeps previous results`, async () => {
        const f = fixture({response: {ok: false, status,
            json: async () => ({detail: 'rate limited'})}});
        f.select(selected);
        await settle();
        assert.equal(f.calls.fetch, 1);
        assert.equal(f.calls.alerts.length, 1);
        assert.equal(f.state.text, 'previous decompilation');
        assert.equal(f.url(), 'old-results');
        assert.deepEqual(f.calls.history, []);
    });
}

test('network failure keeps previous results', async () => {
    const f = fixture({failure: new Error('offline')});
    f.select(selected);
    await settle();
    assert.equal(f.state.text, 'previous decompilation');
    assert.equal(f.url(), 'old-results');
    assert.equal(f.calls.alerts.length, 1);
});

test('results change only after the successful response is decoded', async () => {
    let finish;
    const decoded = new Promise(resolve => finish = resolve);
    const f = fixture({response: {ok: true, json: () => decoded}});
    f.select(selected);
    await settle();
    assert.equal(f.state.text, 'previous decompilation');
    assert.equal(f.url(), 'old-results');
    finish({id: 'new-binary'});
    await settle();
    assert.equal(f.state.text, '');
    assert.equal(f.url(), 'https://example.test/api/binaries/new-binary/decompilations/');
    assert.deepEqual(f.calls.history, ['new-binary']);
});

test('invalid JSON keeps previous results', async () => {
    const f = fixture({response: {ok: true, json: async () => {throw new Error('invalid JSON');}}});
    f.select(selected);
    await settle();
    assert.equal(f.state.text, 'previous decompilation');
    assert.equal(f.url(), 'old-results');
    assert.equal(f.calls.alerts.length, 1);
});

test('older successful upload cannot replace the newest completed upload', async () => {
    let finishFirst;
    const first = new Promise(resolve => finishFirst = resolve);
    const f = fixture({fetchResponse: index => index === 1 ? first :
        {ok: true, json: async () => ({id: 'newest'})}});
    f.select(selected);
    f.select(selected);
    await settle();
    assert.equal(f.url(), 'https://example.test/api/binaries/newest/decompilations/');
    finishFirst({ok: true, json: async () => ({id: 'stale'})});
    await settle();
    assert.equal(f.url(), 'https://example.test/api/binaries/newest/decompilations/');
    assert.deepEqual(f.calls.history, ['newest']);
});

test('outdated failure cannot show an alert after a newer success', async () => {
    let rejectFirst;
    const first = new Promise((_, reject) => rejectFirst = reject);
    const f = fixture({fetchResponse: index => index === 1 ? first :
        {ok: true, json: async () => ({id: 'newest'})}});
    f.select(selected);
    f.select(selected);
    await settle();
    rejectFirst(new Error('stale network failure'));
    await settle();
    assert.deepEqual(f.calls.alerts, []);
    assert.deepEqual(f.calls.history, ['newest']);
});

test('old completion cannot overwrite existing results when newest upload fails', async () => {
    let finishFirst;
    const first = new Promise(resolve => finishFirst = resolve);
    const f = fixture({fetchResponse: index => index === 1 ? first :
        {ok: false, status: 500}});
    f.select(selected);
    f.select(selected);
    await settle();
    finishFirst({ok: true, json: async () => ({id: 'stale'})});
    await settle();
    assert.equal(f.url(), 'old-results');
    assert.equal(f.state.text, 'previous decompilation');
    assert.deepEqual(f.calls.history, []);
    assert.equal(f.calls.alerts.length, 1);
});

test('successful HTTP response without binary ID preserves previous results', async () => {
    const f = fixture({response: {ok: true, json: async () => ({})}});
    f.select(selected);
    await settle();
    assert.equal(f.url(), 'old-results');
    assert.equal(f.state.text, 'previous decompilation');
    assert.equal(f.calls.alerts.length, 1);
});
