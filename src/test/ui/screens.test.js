// What each screen shows for a given server state.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory } = require('./support/fixtures');

/** Inventory table rows, without the header row. */
const rows = (app) => app.$$('#main .trow.g-inv:not(.thead)');

test('inventory screen', async (t) => {
  await t.test('lists every asset in the server ranking order', async () => {
    const inv = exampleInventory();
    const rank = inv.assets.map((a) => a.id).reverse();
    const app = await loadApp({ routes: defaultRoutes({ inventory: inv, rank }), hash: '#/inventory' });
    try {
      assert.equal(rows(app).length, 10);
      assert.match(rows(app)[0].textContent, /10\.0\.2\.1/, 'first row follows rank[0]');
      assert.match(app.text(), /Showing 10 of 10 assets/);
    } finally { app.close(); }
  });

  await t.test('search box filters by vendor', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/inventory' });
    try {
      const q = app.$('#q');
      q.value = 'siemens';
      q.dispatchEvent(new app.window.Event('input'));
      await settle();
      assert.equal(rows(app).length, 1);
      assert.match(rows(app)[0].textContent, /6ES7 515/);
    } finally { app.close(); }
  });

  await t.test('match-level and KEV chips filter the table', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/inventory' });
    try {
      app.$$('#main button.chip').find((b) => b.textContent === 'EXACT').click();
      await settle();
      assert.equal(rows(app).length, 1);

      app.$$('#main button.chip').find((b) => b.textContent === 'All levels').click();
      app.$$('#main button.chip').find((b) => b.textContent === 'KEV only').click();
      await settle();
      assert.equal(rows(app).length, 1);
      assert.match(rows(app)[0].textContent, /KEV/);
    } finally { app.close(); }
  });

  await t.test('empty inventory tells the user to queue a capture', async () => {
    const routes = defaultRoutes();
    routes['GET inventory'] = { inventory: { assets: [] }, rank: [], site: {} };
    const app = await loadApp({ routes, hash: '#/inventory' });
    try {
      assert.match(app.text(), /No assets yet\. Queue a capture\./);
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
});
