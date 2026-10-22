// What each screen shows for a given server state.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field } = require('./support/fixtures');

test('the graph replaces the row-based asset inventory', async (t) => {
  await t.test('there is no inventory table: #/inventory opens the graph, and nothing offers a table view', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/inventory' });
    try {
      assert.equal(app.get('route()').name, 'graph', 'an old bookmark lands on the graph');
      assert.equal(app.$('#main').hidden, true);
      assert.equal(app.$$('.trow.g-inv, .trow.g-flow').length, 0);
      assert.equal(app.$('[data-nav="inventory"]'), null, 'no menu entry');
      assert.equal(app.$('#tb-table'), null, 'no toolbar button');
      assert.equal(app.$$('#graph .node').filter((n) => !n.classList.contains('adv')).length, 10, 'every asset is a node');
      assert.doesNotMatch(app.document.body.innerHTML, /href="#\/inventory"/, 'no link anywhere points at the removed screen');
    } finally { app.close(); }
  });

  await t.test('the overview ranks assets fix-first in the server order and links to the graph', async () => {
    const inv = exampleInventory();
    const rank = inv.assets.map((a) => a.id).reverse();
    const app = await loadApp({ routes: defaultRoutes({ inventory: inv, rank }), hash: '#/overview' });
    try {
      const first = app.$$('#main a.rv')[0];
      assert.match(first.textContent, /10\.0\.2\.1/, 'first row follows rank[0]');
      assert.equal(app.$$('#main a.btn').find((a) => a.textContent === 'Open the graph').getAttribute('href'), '#/graph');
    } finally { app.close(); }
  });

  await t.test('a match level chosen on the overview is applied to the graph', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/overview' });
    try {
      app.$$('#main a').find((a) => /EXACT/.test(a.textContent) && a.getAttribute('href') === '#/graph').click();
      await settle();
      assert.equal(app.get('route()').name, 'graph');
      assert.equal(app.get('S').level, 'EXACT');
      assert.equal(app.$$('#graph .node').filter((n) => !n.classList.contains('dim') && !n.classList.contains('adv')).length, 1);
    } finally { app.close(); }
  });

  await t.test('an empty site tells the user to queue a capture', async () => {
    const routes = defaultRoutes();
    routes['GET inventory'] = { inventory: { assets: [] }, rank: [], site: {} };
    const app = await loadApp({ routes, hash: '#/overview' });
    try {
      assert.match(app.text(), /No assets yet\. Queue a capture/);
    } finally { app.close(); }
  });
});

test('advisory index warnings', async (t) => {
  await t.test('an UNVERIFIED index shows a red banner', async () => {
    const routes = defaultRoutes({ index: { verified: false, generated: '2026-10-01T00:00:00Z' } });
    const app = await loadApp({ routes });
    try {
      assert.match(app.text('#banner'), /UNVERIFIED/);
      assert.ok(app.$('#banner .banner.bad'));
      assert.ok(app.$('#idx-badge').classList.contains('bad'));
    } finally { app.close(); }
  });

  await t.test('a stale index shows the server warning', async () => {
    const routes = defaultRoutes({ index: { verified: true, generated: '2025-01-01T00:00:00Z', warning: 'Index is 290 days old' } });
    const app = await loadApp({ routes });
    try {
      assert.match(app.text('#banner'), /290 days old/);
      assert.ok(app.$('#idx-badge').classList.contains('warn'));
    } finally { app.close(); }
  });
});

test('advisory wording never claims a device is safe', async (t) => {
  await t.test('NONE result says "not a clean bill of health"', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.10' });
    try {
      app.$$('#main button.tab').find((b) => /^Advisories/.test(b.textContent)).click();
      await settle();
      assert.match(app.text(), /No matching advisory in index/);
      assert.match(app.text(), /not a clean bill of health/);
    } finally { app.close(); }
  });

  await t.test('advisories screen lists the matched advisory with its KEV badge', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/advisories' });
    try {
      assert.match(app.text(), /TEST-ADVISORY-0001/);
      assert.ok(app.$('#main .badge.kev'));
    } finally { app.close(); }
  });
});

test('other screens', async (t) => {
  await t.test('unknown asset id shows a not-found message, not a crash', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.9.9.9' });
    try {
      assert.match(app.text(), /No asset 10\.9\.9\.9 in the current inventory/);
    } finally { app.close(); }
  });

  await t.test('review queue lists low-confidence identities', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/review' });
    try {
      const low = app.$$('#main .card').find((c) => /Low-confidence identity/.test(c.textContent));
      assert.ok(low, 'low-confidence group is shown');
      assert.match(low.textContent, /10\.0\.1\.20/);
      assert.match(low.textContent, /10\.0\.1\.50/);
    } finally { app.close(); }
  });

  await t.test('a failed capture shows its exit code and the conversion hint', async () => {
    const captures = [{ id: 'c1', file: 'bad.cap', size: 1024, at: '2026-10-18T10:00:00Z', by: 'Vineeth', state: 'failed', exit: 4,
      error: 'unsupported capture format', sha256: 'a'.repeat(64) }];
    const app = await loadApp({ routes: defaultRoutes({ captures }), hash: '#/captures' });
    try {
      assert.match(app.text(), /Exit 4/);
      app.$$('#main button').find((b) => b.textContent === 'Details').click();
      await settle();
      assert.match(app.text(), /editcap -F pcap/);
    } finally { app.close(); }
  });

  await t.test('a merged capture lists the devices it contributed and can be hidden from view', async () => {
    const captures = [{ id: 'c1', file: 'cell1.pcap', size: 900, at: '2026-10-18T10:00:00Z', by: 'Vineeth', state: 'done',
      sha256: 'c'.repeat(64), summary: { frames: 10, malformed: 0, protocols: { modbus: 1 }, identityFields: 1, devices: 2 }, diff: { new: 2, changed: 0, notSeen: 0 } }];
    const captureAssets = { c1: ['10.0.1.40', '10.0.1.50'] };
    const app = await loadApp({ routes: defaultRoutes({ captures, captureAssets }), hash: '#/captures' });
    try {
      assert.match(app.text(), /2 devices/);
      app.$$('#main button').find((b) => b.textContent === 'Hide').click();
      await settle();
      assert.match(app.text(), /Hidden/, 'the row says it is hidden');
      assert.ok(app.$$('#main button').find((b) => b.textContent === 'Show'), 'and offers to show it again');
      app.$$('#main button').find((b) => b.textContent === 'Details').click();
      await settle();
      assert.match(app.text(), /Devices contributed by this capture/);
      assert.match(app.text(), /10\.0\.1\.40/);
      app.$$('#main button').find((b) => b.textContent === 'Show only on graph').click();
      await settle();
      assert.equal(app.window.location.hash, '#/graph');
      assert.equal(app.get('S.search'), 'capture:c1');
    } finally { app.close(); }
  });

  await t.test('a posted-via-API capture shows its source instead of frame counts', async () => {
    const captures = [{ id: 'c1', file: 'posted via API', kind: 'posted', size: 900, at: '2026-10-18T10:00:00Z', by: 'Probe', state: 'done',
      sha256: 'b'.repeat(64), summary: { frames: 0, malformed: 0, protocols: {}, identityFields: 0, devices: 3 }, diff: { new: 3, changed: 0, notSeen: 0 } }];
    const app = await loadApp({ routes: defaultRoutes({ captures }), hash: '#/captures' });
    try {
      app.$$('#main button').find((b) => b.textContent === 'Details').click();
      await settle();
      assert.match(app.text(), /posted to the ingest API/);
      assert.doesNotMatch(app.text(), /Frames processed/);
    } finally { app.close(); }
  });
});

test('identity rows on the asset screen', async (t) => {
  const row = (app, label) => app.$$('#main .g-attr').find((r) => r.textContent.startsWith(label));

  await t.test('serial number and device type have their own rows', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.10%2Fslot0' });
    try {
      assert.match(row(app, 'Serial number').textContent, /\S/);
      assert.doesNotMatch(row(app, 'Serial number').textContent, /Not filled|No identity message/);
      assert.match(row(app, 'Device type').textContent, /cip:0x/);
    } finally { app.close(); }
  });

  await t.test('an asset with no identity attributes says what would fill them, not a bare "Not filled"', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.60' });
    try {
      for (const l of ['Manufacturer', 'Model', 'OS / firmware', 'Serial number', 'Device type'])
        assert.match(row(app, l).textContent, /No identity message observed \(needs Modbus FC43 \/ ENIP ListIdentity \/ S7 SZL\)/, l);
      assert.match(row(app, 'Physical location').textContent, /Not filled/, 'human fields keep the plain wording');
    } finally { app.close(); }
  });

  await t.test('a MAC-derived vendor is shown but does not count as an identity message', async () => {
    const inventory = exampleInventory();
    inventory.assets.find((a) => a.id === '10.0.1.60').vendor_oui = field('Siemens AG', 'LOW', 'MAC OUI 00:1b:1b (IEEE MA-L); NIC maker, may differ from device maker');
    const app = await loadApp({ routes: defaultRoutes({ inventory }), hash: '#/asset/10.0.1.60' });
    try {
      assert.match(row(app, 'Manufacturer').textContent, /Siemens AG.*LOW.*MAC OUI/);
      assert.match(row(app, 'Model').textContent, /No identity message observed/);
    } finally { app.close(); }
  });
});

test('asset history', async (t) => {
  await t.test('lists capture-driven field changes next to human edits', async () => {
    const changes = [
      { at: '2026-10-19T10:00:00Z', actor: 'R. Analyst', asset: '10.0.1.40', field: 'firmware', from: '20.011', to: '24.011', source: 'capture c0002' },
      { at: '2026-10-19T09:00:00Z', actor: 'S. Owner', asset: '10.0.1.40', field: 'criticality', from: '', to: 'high', source: 'human' },
      { at: '2026-10-19T10:00:00Z', actor: 'R. Analyst', asset: '10.0.1.10', field: 'firmware', from: '1', to: '2', source: 'capture c0002' }];
    const app = await loadApp({ routes: defaultRoutes({ changes }), hash: '#/asset/10.0.1.40' });
    try {
      assert.match(app.text(), /History \(2\)/);
      app.$$('#main button.tab').find((b) => /^History/.test(b.textContent)).click();
      await settle();
      assert.match(app.text(), /firmware: 20\.011 → 24\.011/);
      assert.match(app.text(), /capture c0002/);
      assert.match(app.text(), /criticality: ∅ → high/);
      assert.doesNotMatch(app.text(), /firmware: 1 → 2/, 'a change to another asset is not shown');
    } finally { app.close(); }
  });
});
