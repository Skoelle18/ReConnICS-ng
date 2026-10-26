// The Engines / "Powered by" screen, the source badges and the tool evidence on an edge.
// The engine rows below are hand-written in the shape GET /api/v1/engines sends (com.pcap.tools.Engines.report); no tool is run.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, field } = require('./support/fixtures');

const ENGINES = [
  { id: 'zeek', name: 'Zeek', url: 'https://zeek.org', licence: 'BSD-3-Clause', kind: 'engine', optional: true, role: 'primary engine', status: { state: 'found', via: 'docker', version: 'zeek version 8.0.1', detail: 'image reconics-zeek' } },
  { id: 'suricata', name: 'Suricata', url: 'https://suricata.io', licence: 'GPL-2.0', kind: 'engine', optional: true, role: 'alerts', status: { state: 'not-installed', via: '', version: '', detail: 'not on PATH and no reconics-tools Docker image' } },
  { id: 'manuf', name: 'Wireshark manuf', url: 'https://www.wireshark.org', licence: 'GPL-2.0-or-later (data file)', kind: 'data', optional: true, role: 'MAC makers', status: { state: 'not-installed' } },
  { id: 'grassmarlin', name: 'GRASSMARLIN', url: 'https://github.com/nsacyber/GRASSMARLIN', licence: 'see repository', kind: 'reference', optional: true, role: 'lineage', status: { state: 'reference' } },
];

const SUMMARY = (tools) => ({ frames: 10, malformed: 0, protocols: {}, identityFields: 0, devices: 1, tools });

test('the Engines screen lists every component with its state and licence', async () => {
  const routes = defaultRoutes();
  routes['GET engines'] = ENGINES;
  const app = await loadApp({ routes, hash: '#/engines' });
  try {
    const text = app.text();
    assert.match(text, /Zeek/);
    assert.match(text, /zeek version 8\.0\.1/);
    assert.match(text, /Suricata[\s\S]*not installed/, 'a missing tool is shown as not installed, not hidden');
    assert.match(text, /GPL-2\.0/);
    assert.match(text, /GRASSMARLIN/);
    assert.ok(app.$('#tree a[href="#/engines"]'), 'a system tree entry');
    assert.equal(app.$('#tree a[href="#/engines"]').classList.contains('selected'), true);
  } finally { app.close(); }
});

test('the Engines screen still renders when the server has no engines route', async () => {
  const app = await loadApp({ routes: defaultRoutes(), hash: '#/engines' });
  try { assert.match(app.text(), /Engines/); } finally { app.close(); }
});

test('a finished capture shows which engines ran for it', async () => {
  const caps = [{ id: 'c1', file: 'a.pcap', state: 'done', size: 10, at: '2026-10-01T00:00:00Z', by: 'x', sha256: 'a'.repeat(64),
    diff: { new: 1, changed: 0, notSeen: 0 }, summary: SUMMARY([
      { id: 'zeek', name: 'Zeek', state: 'ran', via: 'docker', version: '8.0.1' },
      { id: 'suricata', name: 'Suricata', state: 'not-installed', detail: 'not on PATH' }]) }];
  const app = await loadApp({ routes: defaultRoutes({ captures: caps }), hash: '#/captures' });
  try {
    app.window.eval("S.openCap = 'c1'; render();");
    await settle();
    const text = app.text();
    assert.match(text, /Engines for this capture/);
    assert.match(text, /Zeek · 8\.0\.1 · ran/);
    assert.match(text, /Suricata · not installed/);
  } finally { app.close(); }
});

test('an edge shows nDPI as classified-not-decoded and Suricata alerts as evidence', async () => {
  const flows = [{ client: '10.0.1.50', server: '10.0.1.60', protocol: 'unknown', port: '4840/tcp', transport: 'tcp', messages: 4,
    labels: {}, source: 'zeek+tshark', communityIds: ['1:abcd1234abcd1234='],
    classifiedBy: [{ tool: 'ndpi', version: '4.2', protocol: 'OPC-UA', confidence: 'MEDIUM', basis: 'dpi' }],
    alerts: [{ tool: 'suricata', version: '7.0.10', kind: 'alert', sid: 2000001, signature: 'TEST rule', severity: 2, count: 3 }] }];
  const app = await loadApp({ routes: defaultRoutes({ flows }), hash: '#/graph' });
  try {
    const key = app.get('flowKey(S.flows[0])');
    app.window.location.hash = '#/edge/' + encodeURIComponent(key);
    await settle();
    const text = app.text();
    assert.match(text, /classified, not decoded: OPC-UA\?/);
    assert.match(text, /nDPI 4\.2/);
    assert.match(text, /TEST rule \(sid 2000001\) x3/);
    assert.match(text, /not a decoded protocol and not proof of an attack/);
    assert.match(text, /Community ID 1:abcd1234abcd1234=/);
  } finally { app.close(); }
});

test('a rejected ICS decode is shown on the edge with its reason, as unknown', async () => {
  const flows = [{ client: '192.168.10.200', server: '192.168.10.106', protocol: 'unknown', port: '443/tcp', transport: 'tcp', messages: 1959, labels: {}, portHint: 'https',
    note: 'ICS decode rejected: 5 messages decoded as Modbus on 443/tcp, all of them exceptions; no industrial protocol uses this port and nDPI 4.2.0 names the conversation TLS.',
    classifiedBy: [{ tool: 'ndpi', version: '4.2.0', protocol: 'TLS', confidence: 'LOW', basis: 'dpi' }] }];
  const app = await loadApp({ routes: defaultRoutes({ flows }), hash: '#/graph' });
  try {
    app.window.location.hash = '#/edge/' + encodeURIComponent(app.get('flowKey(S.flows[0])'));
    await settle();
    const text = app.text();
    assert.match(text, /ICS decode rejected[\s\S]*5 messages decoded as Modbus on 443\/tcp, all of them exceptions/);
    assert.match(text, /classified, not decoded: TLS\?/);
  } finally { app.close(); }
});

test('attribute evidence gets a badge for the open-source tool named in it', async () => {
  const app = await loadApp({ routes: defaultRoutes() });
  try {
    const tags = app.window.eval("sourceTags('MAC OUI 00:1b:c5 block /36 (Wireshark manuf); NIC maker') .concat(sourceTags('p0f 3.09b passive OS fingerprint'), sourceTags('Zeek modbus.log'))");
    assert.deepEqual([...tags], ['Wireshark', 'p0f', 'Zeek']);
  } finally { app.close(); }
});

test('asset alerts row only appears when a tool wrote alerts', async () => {
  const inv = require('./support/fixtures').exampleInventory();
  inv.assets[0].alerts = field(['TEST rule'], 'MEDIUM', 'Suricata 7.0.10 eve.json alerts');
  const app = await loadApp({ routes: defaultRoutes({ inventory: inv }), hash: '#/asset/' + encodeURIComponent(inv.assets[0].id) });
  try { assert.match(app.text(), /Suricata alerts[\s\S]*TEST rule/); } finally { app.close(); }
  const app2 = await loadApp({ routes: defaultRoutes(), hash: '#/asset/' + encodeURIComponent(inv.assets[1].id) });
  try { assert.doesNotMatch(app2.text(), /Suricata alerts/); } finally { app2.close(); }
});
