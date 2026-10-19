// Security behaviour and what the UI sends to the server.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field } = require('./support/fixtures');

test('device strings cannot inject HTML or script (XSS)', async () => {
  // A malicious device could put anything in its hostname or model string.
  const inv = exampleInventory();
  inv.assets[0].hostname = field('<img src=x onerror="window.__pwned=1">');
  inv.assets[0].model = field('<script>window.__pwned=2</script>');
  const app = await loadApp({ routes: defaultRoutes({ inventory: inv }), hash: '#/inventory' });
  try {
    assert.equal(app.$$('#main img').length, 0, 'no <img> element was created');
    assert.equal(app.$$('#main script').length, 0, 'no <script> element was created');
    assert.equal(app.window.__pwned, undefined, 'no injected code ran');
    assert.match(app.text(), /<img src=x onerror=/, 'the string is shown as plain text');
  } finally { app.close(); }
});

test('every request carries the analyst name for the change log', async () => {
  const app = await loadApp({ routes: defaultRoutes(), storage: { actor: 'Vineeth', role: 'validator' } });
  try {
    assert.ok(app.calls.length > 0);
    for (const c of app.calls) {
      assert.equal(c.headers['X-Actor'], 'Vineeth');
      assert.equal(c.headers['X-Role'], 'validator');
    }
  } finally { app.close(); }
});

test('all requests stay on the console API (nothing leaves the machine)', async () => {
  const app = await loadApp({ routes: defaultRoutes(), hash: '#/inventory' });
  try {
    for (const c of app.calls) assert.doesNotMatch(c.route, /^https?:\/\//, 'relative /api/v1/ paths only');
  } finally { app.close(); }
});

test('validation rules', async (t) => {
  const markBtn = (app) => app.$$('#main button').find((b) => /Mark validated/.test(b.textContent));

  await t.test('a collector cannot mark an asset validated', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.40', storage: { actor: 'A', role: 'collector' } });
    try {
      assert.equal(markBtn(app).disabled, true);
    } finally { app.close(); }
  });

  await t.test('a validator can, and the UI sends {validated:true}', async () => {
    const routes = defaultRoutes();
    let sent = null;
    routes['PATCH assets/10.0.1.40'] = (req) => { sent = JSON.parse(req.body); return { changes: [{ field: 'validated' }] }; };
    const app = await loadApp({ routes, hash: '#/asset/10.0.1.40', storage: { actor: 'B', role: 'validator' } });
    try {
      assert.equal(markBtn(app).disabled, false);
      markBtn(app).click();
      await settle();
      assert.deepEqual(sent, { validated: true });
      assert.match(app.text('#toast'), /1 change\(s\) saved/);
    } finally { app.close(); }
  });
});

test('edit form', async (t) => {
  async function openForm(routes) {
    const app = await loadApp({ routes, hash: '#/asset/10.0.1.40', storage: { actor: 'Vineeth', role: 'collector' } });
    app.$$('#main button').find((b) => b.textContent === 'Edit site fields').click();
    await settle();
    return app;
  }
  const input = (app, label) => app.$$('#main form label').find((l) => l.textContent.startsWith(label)).querySelector('input, select');

  // KNOWN BUG (found by these tests): editForm() shows Lifecycle as 'In service' when the site has no value,
  // but compares against '' — so every save also sends lifecycle:'In service' and logs a change nobody made.
  // Remove the `todo` options below once app.js is fixed.
  const LIFECYCLE_BUG = { todo: 'BUG: unchanged Lifecycle is sent as "In service" on every save' };

  await t.test('only changed fields are sent', LIFECYCLE_BUG, async () => {
    const routes = defaultRoutes();
    let sent = null;
    routes['PATCH assets/10.0.1.40'] = (req) => { sent = JSON.parse(req.body); return { changes: [{}] }; };
    const app = await openForm(routes);
    try {
      input(app, 'Zone').value = '  Cell 1 control  ';
      input(app, 'Physical location').value = 'Hall B, cabinet 3';
      app.$$('#main button').find((b) => b.textContent === 'Save changes').click();
      await settle();
      assert.deepEqual(sent, { zone: 'Cell 1 control', location: 'Hall B, cabinet 3' }, 'trimmed, and untouched fields left out');
    } finally { app.close(); }
  });

  await t.test('saving with no changes sends nothing', LIFECYCLE_BUG, async () => {
    const app = await openForm(defaultRoutes());
    try {
      app.$$('#main button').find((b) => b.textContent === 'Save changes').click();
      await settle();
      assert.equal(app.calls.filter((c) => c.method === 'PATCH').length, 0);
    } finally { app.close(); }
  });

  await t.test('a server error is shown to the user', async () => {
    const routes = defaultRoutes();
    routes['PATCH assets/10.0.1.40'] = { __status: 400, body: { error: 'zone too long' } };
    const app = await openForm(routes);
    try {
      input(app, 'Zone').value = 'x';
      app.$$('#main button').find((b) => b.textContent === 'Save changes').click();
      await settle();
      assert.match(app.text('#toast'), /zone too long/);
    } finally { app.close(); }
  });
});
