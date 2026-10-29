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
      get lastChild() { return this.children.at(-1); },
      querySelector(selector) { return this[selector] ||= element(); },
      addEventListener(type, listener) { this.listeners[type] = listener; },
      click() { return this.listeners.click?.({target: this}); },
      showModal() { this.open = true; }, close() { this.open = false; },
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
  packet_log: {version: 1, rows: [[1,10,60,'10.0.0.1',80,'10.0.0.2',90,'TCP',1], [2,20,60,'10.0.0.1',80,'10.0.0.2',90,'TCP',1]]},
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

test('packet log follows playback, filters threats, and clears future events on rewind', async () => {
  const app = workspace(result);
  await app.elements.get('sensor-connect').click();
  app.read('streamPlayer.seek(.5)');
  assert.equal(app.read('state.visible.log.length'), 1);
  assert.equal(app.elements.get('packet-log').children.length, 1);
  assert.equal(app.elements.get('packet-log').children[0].children[1].textContent, 'PACKET');
  app.read('streamPlayer.seek(1)');
  assert.equal(app.elements.get('packet-log').children.length, 3);
  assert.equal(app.elements.get('packet-log').children[0].children[1].textContent, 'THREAT');
  app.elements.get('log-filter').value = 'threat';
  app.elements.get('log-filter').listeners.change();
  assert.equal(app.elements.get('packet-log').children.length, 1);
  app.read('streamPlayer.seek(0)');
  assert.equal(app.read('state.visible.log.length'), 0);
  assert.equal(app.elements.get('log-export').disabled, true);
});

test('model screen foregrounds paired measurements without claiming universal superiority', () => {
  const app = workspace(result);
  app.context.health = {report: {gates: {accuracy: true}}, runtime_report: {
    accuracy: .98654, macro_f1: .88377, test_samples: 7209,
    timings: {pytorch_cpu: {batch64_p50_ms: 12.955, batch64_p95_ms: 13.816},
      tensorrt: {batch64_p50_ms: .581, batch64_p95_ms: .779}}}};
  app.read('state.health = health; renderModel()');
  const highlights = app.elements.get('model').children[0].children;
  assert.equal(highlights[0].children[1].textContent, '22.3×');
  assert.equal(highlights[1].children[1].textContent, '12.374 ms');
  assert.equal(highlights[2].children[1].textContent, '98.65%');
  assert.equal(app.elements.has('view-demo'), false);
  app.context.health.runtime_report = null;
  app.read('renderModel()');
  assert.equal(app.elements.get('model').children[0].children[0].children[1].textContent, 'Not measured');
});

test('log pagination retains every event and dropdown requests its selected sequence', async () => {
  const many = {...result, packet_log: {rows: Array.from({length: 600}, (_,i) => [i+1,10+i/60,60,'10.0.0.1',80,'10.0.0.2',90,'TCP',1])}};
  const app = workspace(many);
  app.elements.get('sensor-scenario').value = 'botnet';
  await app.elements.get('sensor-connect').click();
  assert.equal(JSON.parse(app.requests.find(r => r.url === '/api/simulate').options.body).scenario, 'botnet');
  app.read('streamPlayer.seek(1)');
  assert.equal(app.read('state.visible.log.length'), 601);
  assert.equal(app.elements.get('packet-log').children.length, 200);
  app.elements.get('log-older').click(); app.elements.get('log-older').click(); app.elements.get('log-older').click();
  assert.equal(app.elements.get('packet-log').children.length, 1);
  assert.equal(app.elements.get('log-older').disabled, true);
  app.elements.get('log-latest').click();
  assert.equal(app.read('state.logPage'), 0);
  app.read('download = value => { globalThis.exportedLog = value; }');
  app.elements.get('log-export').click();
  assert.equal(app.read('exportedLog.events.length'), 601);
  app.read('streamPlayer.seek(0)'); app.elements.get('log-export').click();
  assert.equal(app.read('exportedLog.events.length'), 0);
});

test('pause-on-threat stops exactly at the verdict and resumes past it', async () => {
  const data={...result,flows:[{...result.flows[0],ready_timestamp:15}]};
  const app=workspace(data);
  app.elements.get('pause-threat').checked=true;
  await app.elements.get('sensor-connect').click();
  for(let time=1;time<20000;time+=100) app.advance(time);
  assert.equal(app.read('streamPlayer.position'),.5);
  assert.equal(app.read('streamPlayer.playing'),false);
  assert.equal(app.elements.get('stream-state').textContent,'Paused on threat');
  app.elements.get('stream-play').click();
  app.advance(21001);app.advance(21101);
  assert.ok(app.read('streamPlayer.position')>.5);
});

test('real GPU response renders through Connect and conserves all results',
  {skip: !process.env.TRAFFICSCAN_REPLAY_RESULT}, async () => {
  const actual = JSON.parse(fs.readFileSync(process.env.TRAFFICSCAN_REPLAY_RESULT, 'utf8'));
  const app = workspace(actual);
  app.elements.get('response-mode').value = 'simulate';
  await app.elements.get('sensor-connect').click();
  assert.equal(app.read('streamPlayer.playing'), true, app.elements.get('sensor-status').textContent);
  for (let t = 1; t < 31000; t += 100) app.advance(t);
  assert.deepEqual(JSON.parse(app.read('JSON.stringify(state.visible.counts)')), actual.counts);
  assert.equal(app.read('state.visible.packets'), actual.telemetry.packet_count);
  assert.equal(app.read('state.visible.flows.length'), actual.telemetry.flow_count);
  const expectedBlocks = actual.flows.filter(f => f.response?.simulate === 'would_block').length;
  assert.equal(app.read('state.visible.response.blockedFlows'), expectedBlocks);
  if (actual.simulation?.synthetic_continuation_packets && expectedBlocks)
    assert.ok(app.read('state.visible.response.dropped') > 0);
  app.elements.get('response-mode').value = 'monitor';
  app.elements.get('response-mode').listeners.change();
  assert.equal(app.read('state.visible.response.dropped'), 0);
  app.context.selectedFlow = actual.flows[0]; app.read('inspectFlow(selectedFlow)');
  assert.equal(app.elements.get('detail').open, true);
  if (process.env.TRAFFICSCAN_REPLAY_HEALTH) {
    app.context.realHealth = JSON.parse(fs.readFileSync(process.env.TRAFFICSCAN_REPLAY_HEALTH,'utf8'));
    app.read('state.health = realHealth; renderModel()');
    assert.ok(app.elements.get('model').children.some(child => child.children.some(item => item.textContent === 'Behavioral detection · advisory only')));
  }
});
