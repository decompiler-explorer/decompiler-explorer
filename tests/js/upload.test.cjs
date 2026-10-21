// Run with: node --test tests/js/upload.test.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function fixture({valid = true, response, failure} = {}) {
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
