// What each screen shows for a given server state.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle, waitFor } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field } = require('./support/fixtures');

test('reference console shell and navigation', async (t) => {
  await t.test('the graph opens inside the persistent three-pane console shell', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      assert.equal(app.get('route()').name, 'graph');
      assert.equal(app.$('#main').hidden, true);
      assert.ok(app.$('#top'), 'top bar');
      assert.ok(app.$('#tree'), 'persistent site tree');
      assert.ok(app.$('#stage'), 'graph stage');
      assert.ok(app.$('#modes [data-mode="inventory"]'), 'inventory mode is available');
      assert.ok(app.$('#modes [data-mode="findings"]'), 'findings mode is available');
      assert.ok(app.$('#modes [data-mode="data"]'), 'data mode is available');
      assert.equal(app.$('#modes [data-mode="graph"]').classList.contains('on'), true);
      assert.equal(app.$$('#graph .node').filter((n) => !n.classList.contains('adv')).length, 10, 'every asset is a node');
      assert.ok(app.$('#top-search input#q'));
      assert.ok(app.$('#top-upload'));
      assert.equal(app.$('#tree [data-level="4"]').textContent.trim(), '◉Level 4 · External');
      assert.equal(app.$('#nav'), null);
      assert.equal(app.$('#menu-btn'), null);
      assert.equal(app.$('#rawq-btn'), null);
      assert.equal(app.$('#rawq-body'), null);
      app.$('#mobile-menu').click();
      assert.ok(app.$('#tree').classList.contains('mobile-open'));
      app.document.dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      assert.equal(app.$('#tree').classList.contains('mobile-open'), false);
    } finally { app.close(); }
  });

  await t.test('Purdue tree filters are independent of advisory match levels', async () => {
    const app = await loadApp({ routes: defaultRoutes() });
    try {
      const row = app.$('#tree [data-level="2"]');
      row.click(); await settle();
      assert.equal(app.get('S.purdueFilter'), '2');
      assert.equal(app.get('S.level'), 'ALL');
      assert.equal(row.classList.contains('selected'), true);
      const client = app.$('#graph .node[data-id="10.0.1.50"]');
      assert.ok(client && !client.classList.contains('dim'), 'the Level 2 inferred client remains visible');
      const plc = app.$('#graph .node[data-id="10.0.1.40"]');
      assert.ok(plc.classList.contains('dim'), 'Level 1 PLC is outside the selected Purdue level');
      app.$('#btn-filter').click();
      const reset = app.$$('#pop-filter button').find((b) => b.textContent === 'Reset view');
      reset.click(); await settle();
      assert.equal(app.get('S.purdueFilter'), null);
      assert.equal(row.classList.contains('selected'), false);
      assert.ok(!app.$('#graph .node[data-id="10.0.1.40"]').classList.contains('dim'));
    } finally { app.close(); }
  });

  await t.test('the tree Export row opens the same multi-format export popover', async () => {
    const app = await loadApp({ routes: defaultRoutes() });
    try {
      app.$('#tree-export').click();
      assert.equal(app.$('#pop-export').hidden, false);
      assert.equal(app.$('#tb-export').getAttribute('aria-expanded'), 'true');
      assert.equal(app.$('#tree-export').getAttribute('aria-expanded'), 'true');
      assert.deepEqual(app.$$('#pop-export a').map((a) => a.textContent), ['inventory.csv', 'inventory.json', 'report.html']);
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
      await waitFor(() => app.$$('#graph .node').filter((n) => !n.classList.contains('dim') && !n.classList.contains('adv')).length === 1,
        'the graph applies the advisory match filter');
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

test('inventory screen', async (t) => {
  await t.test('lists real assets and groups by MAC with inference notes', async () => {
    const inv = exampleInventory();
    inv.assets.find((a) => a.id === '10.0.1.10').mac = field('02:1d:9c:c1:00:10');
    const mac = '02:1d:9c:c1:00:10';
    const app = await loadApp({ routes: defaultRoutes({ inventory: inv, macs: [{ mac, kind: 'host', ips: ['10.0.1.10'], ipCount: 1, notes: ['Multiple IPs can indicate a router or NAT interface.'] }] }), hash: '#/inventory' });
    try {
      assert.equal(app.get('route()').name, 'inventory');
      assert.match(app.text('#main'), /Inventory/);
      assert.ok(app.$('#main .inventory-table'));
      assert.match(app.text('#main'), /10\.0\.1\.40/);
      app.$('#main .inventory-group-toggle input').click();
      await settle();
      assert.match(app.text('#main'), /Group by MAC/);
      assert.match(app.text('#main'), /router or NAT inference/);
      assert.match(app.text('#main'), /locally administered MAC/);
      assert.ok(app.$$('#main .mac-group').length > 0);
    } finally { app.close(); }
  });

  await t.test('bulk edits use one audited PATCH per selected asset', async () => {
    const writes = [];
    const routes = defaultRoutes();
    routes['PATCH assets/10.0.1.40'] = (req) => { writes.push(req); return { changes: [{ field: 'zone' }] }; };
    routes['PATCH assets/10.0.1.50'] = (req) => { writes.push(req); return { changes: [{ field: 'zone' }] }; };
    const app = await loadApp({ routes, hash: '#/inventory', storage: { actor: 'V. Analyst' } });
    try {
      for (const id of ['10.0.1.40', '10.0.1.50']) {
        app.$(`#main [aria-label="Select ${id}"]`).checked = true;
        app.$(`#main [aria-label="Select ${id}"]`).dispatchEvent(new app.window.Event('change', { bubbles: true }));
      }
      const fieldSel = app.$('#main .bulk-edit select');
      fieldSel.value = 'zone'; fieldSel.dispatchEvent(new app.window.Event('change', { bubbles: true }));
      const value = app.$('#main .bulk-edit input[aria-label="Bulk edit value"]');
      value.value = 'North cell'; value.dispatchEvent(new app.window.Event('input', { bubbles: true }));
      app.$('#main .bulk-edit button[type="submit"]').click();
      await settle();
      assert.equal(writes.length, 2);
      assert.ok(writes.every((w) => w.headers['X-Actor'] === 'V. Analyst'));
      assert.ok(writes.every((w) => JSON.parse(w.body).zone === 'North cell'));
      assert.match(app.text('#toast'), /2 assets updated and logged/);
    } finally { app.close(); }
  });
});

test('graph controls and inspector', async (t) => {
  await t.test('always-visible protocol and layout chips complement the counted filter panel', async () => {
    const inv = exampleInventory();
    const id = inv.assets[0].id;
    const app = await loadApp({ routes: defaultRoutes({ inventory: inv, site: { [id]: { lifecycle: 'Decommissioned' } } }) });
    try {
      assert.deepEqual(app.$$('#graph-chips button').map((b) => b.textContent), ['Modbus', 'DNP3', 'ENIP', 'S7', 'SNMP', 'ICMP', 'Unknown']);
      assert.deepEqual(app.$$('#graph-layout button').map((b) => b.textContent), ['KEV only', 'Force', 'Purdue']);
      app.$('#btn-filter').click();
      await settle();
      assert.match(app.text('#hidden-facet'), /Decommissioned hosts: 1.*hidden, kept in the inventory/);
      const show = app.$$('#hidden-facet .row').find((r) => /Decommissioned hosts/.test(r.textContent)).querySelector('button');
      assert.ok(show);
      show.click(); await settle();
      assert.equal(app.get('S.hideDecommissioned'), false);
      assert.ok(app.$$('#graph .node').some((n) => n.dataset.id === id));
    } finally { app.close(); }
  });

  await t.test('asset details open as a docked, accessible inspector', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.40' });
    try {
      assert.equal(app.$('#main').className, 'panel');
      assert.equal(app.$('#main').parentElement.id, 'workspace');
      assert.equal(app.$('#main .close').getAttribute('aria-label'), 'Close and return to the graph');
      const copy = app.$('#main .copy-link');
      assert.equal(copy.getAttribute('aria-label'), 'Copy link to this item');
      copy.click(); await settle();
      assert.match(app.text('#toast'), /#\/asset\/10\.0\.1\.40/);
      assert.match(app.text('#main'), /CISA high-priority attributes/);
      assert.match(app.text('#main'), /Confidence/);
      assert.match(app.text('#main'), /Site fields/);
      assert.ok(app.$$('#main button.tab').some((b) => /^Conversations/.test(b.textContent)));
      const validate = app.$$('#main button').find((b) => /Mark validated/.test(b.textContent));
      assert.equal(validate.disabled, true, 'a collector cannot validate');
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

  await t.test('findings tabs filter advisories and review records', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/findings' });
    try {
      assert.ok(app.$('#main .screen-tabs'));
      assert.match(app.text(), /TEST-ADVISORY-0001/);
      const search = app.$('#main input[type="search"]');
      search.value = 'no-such-advisory'; search.dispatchEvent(new app.window.Event('input', { bubbles: true }));
      assert.doesNotMatch(app.text(), /TEST-ADVISORY-0001/);
      app.$$('#main .screen-tabs a')[1].click();
      assert.match(app.text(), /Review queue/);
      assert.match(app.text(), /Last reviewed: Never/);
      assert.equal(app.$$('#main button').find((b) => /Confirm all/.test(b.textContent)).disabled, true, 'Collector cannot confirm');
    } finally { app.close(); }
  });

  await t.test('a Validator can confirm pending assets through audited asset PATCHes', async () => {
    const base = defaultRoutes();
    const ids = base['GET inventory'].inventory.assets.map((a) => a.id);
    const routes = { ...base, ...Object.fromEntries(ids.map((id) => ['PATCH assets/' + id, () => ({ changes: [{ field: 'validated', to: 'true' }] })])) };
    const app = await loadApp({ routes, hash: '#/review', storage: { actor: 'R. Analyst', role: 'validator' } });
    try {
      const confirm = app.$$('#main button').find((b) => /Confirm all/.test(b.textContent));
      assert.equal(confirm.disabled, false);
      confirm.click(); await settle();
      const writes = app.calls.filter((c) => c.method === 'PATCH' && c.headers['X-Actor'] === 'R. Analyst' && c.headers['X-Role'] === 'validator');
      assert.ok(writes.length > 0);
      assert.ok(writes.every((c) => JSON.parse(c.body).validated === true));
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

  await t.test('"Remove assets" on a merged capture asks first, then deletes it and reports what stayed', async () => {
    const captures = [{ id: 'c1', file: 'cell1.pcap', size: 900, at: '2026-10-18T10:00:00Z', by: 'Vineeth', state: 'done',
      sha256: 'c'.repeat(64), summary: { frames: 10, malformed: 0, protocols: { modbus: 1 }, identityFields: 1, devices: 2 }, diff: { new: 2, changed: 0, notSeen: 0 } }];
    const routes = defaultRoutes({ captures, captureAssets: { c1: ['10.0.1.40', '10.0.1.50'] } });
    routes['DELETE captures/c1'] = { removed: 'c1', file: 'cell1.pcap', assetsDropped: 1, assetsKeptSeenElsewhere: 1, assetsKeptWithEdits: 0 };
    const app = await loadApp({ routes, hash: '#/captures' });
    try {
      const btn = () => app.$$('#main button').find((b) => b.textContent === 'Remove assets');
      let asked = '';
      app.window.confirm = (m) => { asked = m; return false; };
      btn().click();
      await settle();
      assert.match(asked, /2 devices.*also seen in another capture stay.*human edits/s);
      assert.equal(app.calls.filter((c) => c.method === 'DELETE').length, 0, 'declining deletes nothing');
      app.window.confirm = () => true;
      btn().click();
      await settle();
      assert.equal(app.calls.filter((c) => c.method === 'DELETE').length, 1);
      assert.match(app.text('#toast'), /1 dropped, 1 kept \(seen in other captures\), 0 kept \(human edits\)/);
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
