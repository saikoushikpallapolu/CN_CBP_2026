const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

// Execute the shipped scripts with a minimal DOM and a controlled animation clock.
// This is a controller integration test, not a substitute for visual browser QA.
function workspace(result, {reduced = false, failure} = {}) {
  const elements = new Map(), pending = new Map(), requests = [];
  let frameID = 0;
  function element(id = '') {
    return {id, value: '', textContent: '', hidden: false, disabled: false,
      style: {}, dataset: {}, children: [], listeners: {},
      classList: {toggle() {}, add() {}, remove() {}},
      setAttribute() {}, append(...items) { this.children.push(...items); },
      replaceChildren(...items) { this.children = items; },
      get firstChild() { return this.children[0]; },
      querySelector(selector) { return this[selector] ||= element(); },
      addEventListener(type, listener) { this.listeners[type] = listener; },
      click() { return this.listeners.click?.({target: this}); },
      getBoundingClientRect() { return {width: 800, height: 276, left: 0, top: 0}; },
      getContext() { return new Proxy({}, {get: (_, key) => key === 'createLinearGradient'
        ? () => ({addColorStop() {}}) : () => {}}); }
    };
  }
  const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
  for (const [, id] of html.matchAll(/\bid="([^"]+)"/g)) elements.set(id, element(id));
  elements.get('sensor-address').value = '192.0.2.10';
  elements.get('sensor-scenario').value = 'mixed';
  const document = {hidden: false, activeElement: {tagName: 'BODY'},
    getElementById: id => elements.get(id), createElement: () => element(),
    querySelectorAll: () => [], addEventListener() {}};
  const context = vm.createContext({document, URL, console, Intl, Date,
    sessionStorage: {getItem() {return '';}, setItem() {}},
    matchMedia: () => ({matches: reduced}), ResizeObserver: class {observe() {}},
    devicePixelRatio: 1, performance: {now: () => 1},
    requestAnimationFrame: fn => { pending.set(++frameID, fn); return frameID; },
    cancelAnimationFrame: id => pending.delete(id),
    fetch: async (url, options) => {
      requests.push({url, options});
      if (url === '/api/health') return new Promise(() => {});
      assert.equal(url, '/api/simulate');
      return {ok: !failure, status: failure ? 422 : 200,
        json: async () => failure ? {detail: failure} : result};
    }});
  context.window = context;
  for (const file of ['stream-core.js', 'stream.js', 'app.js'])
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../frontend', file), 'utf8'), context, {filename: file});
  return {elements, requests, context,
    advance(time) {const callbacks = [...pending.values()]; pending.clear(); callbacks.forEach(fn => fn(time));},
    read(code) { return vm.runInContext(code, context); }};
}

const result = {
  filename: 'virtual-mixed.pcap', simulation: {address: '192.0.2.10'},
  counts: {benign: 0, botnet: 0, ddos: 1, unknown: 0}, model_available: true,
  telemetry: {analysis_ms: 10, packet_count: 2, flow_count: 1, packets_per_second: 200},
  coverage: {analyzed_ip_packets: 2},
  timeline: {start: 10, end: 20, bins: [{timestamp: 10, count: 1, bytes: 60}, {timestamp: 20, count: 1, bytes: 60}]},
  flows: [{id: 1, prediction: 'ddos', source: '10.0.0.1', destination: '10.0.0.2',
    sport: 80, dport: 90, protocol: 'TCP', packets: 2, confidence: .99, ready_timestamp: 20}]
};

test('Connect sensor starts animation and reveals final API counts', async () => {
  const app = workspace(result);
  await app.elements.get('sensor-connect').click();
  assert.equal(app.requests.filter(r => r.url === '/api/simulate').length, 1);
  assert.equal(app.read('streamPlayer.playing'), true, app.elements.get('notice').textContent);
  assert.equal(app.elements.get('stream-empty').hidden, true);
  for (let t = 1; t < 31000; t += 100) app.advance(t);
  assert.equal(app.elements.get('metric-packets').textContent, '2');
  assert.equal(app.elements.get('metric-threats').textContent, '1');
  assert.equal(app.elements.get('stream-state').textContent, 'Replay complete');
  assert.equal(app.read('streamPlayer.playing'), false);
});

test('failed connection shows its error and enables retry', async () => {
  const app = workspace(result, {failure: 'Reference capture unavailable'});
  await app.elements.get('sensor-connect').click();
  assert.equal(app.elements.get('notice').textContent, 'Reference capture unavailable');
  assert.equal(app.elements.get('sensor-connect').disabled, false);
  assert.equal(app.read('streamPlayer.playing'), false);
  assert.match(app.elements.get('sensor-status').textContent, /Reference capture unavailable/);
});

test('explicit Connect starts playback with reduced motion enabled', async () => {
  const app = workspace(result, {reduced: true});
  await app.elements.get('sensor-connect').click();
  assert.equal(app.read('streamPlayer.playing'), true);
  assert.equal(app.elements.get('stream-state').textContent, 'Replaying');
  assert.equal(app.elements.get('sensor-connect').disabled, false);
  app.advance(1); app.advance(101);
  assert.ok(app.read('streamPlayer.position') > 0);
});

test('pause, backward seek, restart, loop and reset stay synchronized', async () => {
  const app = workspace(result, {reduced: true});
  await app.elements.get('sensor-connect').click();
  app.elements.get('stream-play').click();
  assert.equal(app.read('streamPlayer.playing'), false);
  app.read('streamPlayer.seek(1)');
  assert.equal(app.elements.get('metric-threats').textContent, '1');
  app.read('streamPlayer.seek(0)');
  assert.equal(app.elements.get('metric-threats').textContent, '0');
  assert.equal(app.elements.get('flows').children.length, 0);
  app.elements.get('stream-restart').click();
  assert.equal(app.read('streamPlayer.playing'), true);
  app.elements.get('stream-loop').checked = true;
  app.read('streamPlayer.seek(1)'); app.advance(1);
  assert.equal(app.read('streamPlayer.position'), 0);
  assert.equal(app.elements.get('metric-threats').textContent, '0');
  app.read('reset()');
  assert.equal(app.read('streamPlayer.playing'), false);
  assert.equal(app.elements.get('stream-state').textContent, 'Waiting');
  assert.equal(app.elements.get('stream-position').textContent, '0.0 / 30 s');
  assert.equal(app.elements.get('sensor-status').hidden, true);
});

test('uploaded captures with reduced motion wait for explicit Play', () => {
  const app = workspace(result, {reduced: true});
  app.context.capture = result;
  app.read('showResult(capture)');
  assert.equal(app.read('streamPlayer.playing'), false);
  app.elements.get('stream-play').click();
  assert.equal(app.read('streamPlayer.playing'), true);
});

test('real GPU response renders through Connect and conserves all results',
  {skip: !process.env.TRAFFICSCAN_REPLAY_RESULT}, async () => {
  const actual = JSON.parse(fs.readFileSync(process.env.TRAFFICSCAN_REPLAY_RESULT, 'utf8'));
  const app = workspace(actual);
  await app.elements.get('sensor-connect').click();
  assert.equal(app.read('streamPlayer.playing'), true, app.elements.get('sensor-status').textContent);
  for (let t = 1; t < 31000; t += 100) app.advance(t);
  assert.deepEqual(JSON.parse(app.read('JSON.stringify(state.visible.counts)')), actual.counts);
  assert.equal(app.read('state.visible.packets'), actual.telemetry.packet_count);
  assert.equal(app.read('state.visible.flows.length'), actual.telemetry.flow_count);
});
