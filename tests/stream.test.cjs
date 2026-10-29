const {test} = require('node:test');
const assert = require('node:assert/strict');
const replay = require('../frontend/stream-core.js');
const result = {
  filename: 'real.pcap',
  timeline: {start: 10, end: 20, bins: [{timestamp:10,count:2,bytes:120},{timestamp:15,count:3,bytes:180},{timestamp:20,count:4,bytes:240}]},
  flows: [
    {id:1,source:'10.0.0.1',destination:'10.0.0.2',prediction:'benign',timestamp:10,ready_timestamp:15,packets:2,bytes:120,packet_timeline:[[10,60],[15,60]]},
    {id:2,source:'10.0.0.3',destination:'10.0.0.4',prediction:'ddos',timestamp:15,ready_timestamp:20,packets:2,bytes:120,packet_timeline:[[15,60],[20,60]]}
  ]
};
test('no packet or verdict appears before its replay position', () => {
  const model = replay.prepare(result);
  assert.equal(replay.snapshot(model,0).packets,0);
  assert.equal(replay.snapshot(model,.3).flows.length,0);
  assert.equal(replay.snapshot(model,.5).packets,5);
  assert.deepEqual(replay.snapshot(model,.5).counts,{benign:1,botnet:0,ddos:0,unknown:0});
  const end = replay.snapshot(model,1);
  assert.equal(end.packets,9); assert.equal(end.counts.ddos,1); assert.equal(end.bytes,540);
});
test('seeking backwards clears future detections and replay is deterministic', () => {
  const model = replay.prepare(result);
  replay.snapshot(model,1);
  assert.equal(replay.snapshot(model,.2).counts.ddos,0);
  assert.deepEqual(replay.snapshot(model,.5),replay.snapshot(model,.5));
});
test('IP focus filters both endpoints and reports represented coverage', () => {
  const model = replay.prepare(result,'10.0.0.4');
  assert.equal(model.scope,'Represented flow packets');
  assert.equal(replay.snapshot(model,1).packets,2);
  assert.equal(replay.snapshot(model,1).flows[0].id,2);
  assert.throws(()=>replay.prepare(result,'10.0.0.99'),/no supported flows/);
  assert.throws(()=>replay.normalizeIP('10.0.0.999'),/valid/);
  assert.throws(()=>replay.normalizeIP('https://example.com'),/valid/);
  assert.equal(replay.normalizeIP('2001:0db8:0:0:0:0:0:1'),'2001:db8::1');
});
test('virtual sensor IP is a display label and never removes reference flows', () => {
  const model = replay.prepare({...result,simulation:{address:'192.0.2.10'}},'192.0.2.10');
  assert.equal(replay.snapshot(model,1).packets,9);
  assert.equal(replay.snapshot(model,1).flows.length,2);
});
test('old history and zero-duration captures remain finite', () => {
  const {timeline,...old} = result;
  const model = replay.prepare(old);
  assert.equal(model.scope,'Represented flow packets');
  assert.equal(replay.snapshot(model,1).packets,4);
  const same = {...result,timeline:{start:10,end:10,bins:[{timestamp:10,count:3,bytes:30}]},flows:[{...result.flows[0],ready_timestamp:10}]};
  assert.equal(replay.snapshot(replay.prepare(same),1).captureTimestamp,10);
});
test('host focus retains an idle/capture-end wait before a partial verdict', () => {
  const delayed = {...result,flows:[{...result.flows[0],ready_timestamp:30}]};
  const model = replay.prepare(delayed,'10.0.0.1');
  assert.equal(model.end,30);
  assert.equal(replay.snapshot(model,.5).flows.length,0);
  assert.equal(replay.snapshot(model,1).flows.length,1);
});
