// The edge panel on the Modbus/DNP3 additions: operation unit and outcome, and the port-inferred hint on an undecoded edge.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes } = require('./support/fixtures');

const FLOWS = [
  { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', transport: 'tcp', messages: 30, source: 'zeek',
    labels: { 'Modbus FC3': 20, 'Modbus FC3 exception: illegal data address': 2 },
    operations: [
      { function: 'FC3 read holding registers', access: 'read', unit: 7, address: 10, quantity: 2, count: 20,
        statuses: { ok: 18, 'exception: illegal data address': 2 } },
      { function: '<img src=x onerror="window.__pwned=1">', access: 'control', object: 'Control Relay Output Block', count: 1,
        statuses: { '<b>status: not supported</b>': 1 } },
    ] },
  { client: '10.0.1.50', server: '10.0.1.60', protocol: 'unknown', port: '502/tcp', transport: 'tcp', messages: 12, labels: {}, portHint: 'modbus', source: 'zeek' },
  { client: '10.0.1.50', server: '10.0.1.10', protocol: 'unknown', port: '9999/tcp', transport: 'tcp', messages: 3, labels: {}, source: 'zeek' },
];

test('operation outcomes and port hints', async (t) => {
  await t.test('an operation row shows its unit and how the calls ended; markup in an outcome stays text', async () => {
    const app = await loadApp({ routes: defaultRoutes({ flows: FLOWS }), hash: '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.40>modbus>502/tcp') });
    try {
      await settle();
      const rows = app.$$('#main .trow.g-op:not(.thead)');
      assert.equal(rows.length, 2);
      assert.match(rows[0].textContent, /FC3 read holding registers.*unit 7.*ok ×18.*exception: illegal data address ×2/);
      assert.equal(rows[0].querySelectorAll('.badge.warn').length, 1, 'only the non-ok outcome is flagged');
      assert.match(rows[1].textContent, /<b>status: not supported<\/b> ×1/);
      assert.equal(app.$$('#main .trow b').length, 0, 'no element was created from the outcome text');
      assert.equal(app.$$('#main img').length, 0);
      assert.equal(app.window.__pwned, undefined);
      assert.match(app.text(), /Modbus FC3 exception: illegal data address ×2/);
    } finally { app.close(); }
  });

  await t.test('an undecoded edge on an industrial port says the protocol is port-inferred; a plain one does not', async () => {
    const app = await loadApp({ routes: defaultRoutes({ flows: FLOWS }), hash: '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.60>unknown>502/tcp') });
    try {
      await settle();
      assert.match(app.text(), /Unknown/);
      assert.match(app.text(), /port-inferred: Modbus\?/);
      assert.match(app.text(), /Port 502\/tcp is usually Modbus, but no Modbus message was decoded/);
      await app.go('#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.10>unknown>9999/tcp'));
      assert.doesNotMatch(app.text(), /port-inferred/);
      assert.match(app.text(), /Carried but not decoded/);
    } finally { app.close(); }
  });

  await t.test('the graph label of an undecoded edge carries the hint', async () => {
    const app = await loadApp({ routes: defaultRoutes({ flows: FLOWS }), hash: '#/graph' });
    try {
      await settle();
      const labels = app.$$('#graph .edge.flow text').map((e) => e.textContent);
      assert.ok(labels.includes('502/tcp (Modbus?)'), labels.join('|'));
      assert.ok(labels.includes('9999/tcp'), labels.join('|'));
    } finally { app.close(); }
  });
});
