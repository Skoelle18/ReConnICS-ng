// The console keeps itself current: background polling, paused in a hidden tab, no re-render when nothing changed or while editing.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, waitFor, settle } = require('./support/load-app');
const { defaultRoutes } = require('./support/fixtures');

const cap = (id, state = 'done') => ({ id, file: id + '.pcap', state, size: 1000, at: '2026-10-21T10:00:00Z', by: 'plant-feed', sha256: 'ab'.repeat(32) });
const setHidden = (app, hidden) => {              // jsdom reports every document as hidden; make it visible like a real tab
  Object.defineProperty(app.document, 'hidden', { configurable: true, get: () => hidden });
  app.document.dispatchEvent(new app.window.Event('visibilitychange'));
};
const stop = async (app) => { setHidden(app, true); await settle(); app.close(); };   // no poll may fire into a closed window
const n = (app) => app.calls.filter((c) => c.route === 'inventory').length;

test('background refresh', async (t) => {
  await t.test('a capture uploaded by another process appears without a click, and only then does the page re-render', async () => {
    let captures = [];
    const routes = { ...defaultRoutes(), 'GET captures': () => captures };
    const app = await loadApp({ routes, hash: '#/captures' });
    try {
      app.get('POLL').idle = 20;
      setHidden(app, false);
      const main = app.$('#main > *');
      await waitFor(() => n(app) >= 4, 'no background polling');
      assert.ok(main.isConnected, 'nothing changed: the DOM was left alone');
      captures = [cap('cell2-before')];
      await waitFor(() => app.text().includes('cell2-before'), 'new capture never showed up');
      assert.ok(!main.isConnected, 'the changed data re-rendered the page');
    } finally { await stop(app); }
  });

  await t.test('polls faster while a capture is running, stops in a hidden tab, resumes on visibilitychange', async () => {
    const routes = { ...defaultRoutes(), 'GET captures': [cap('a', 'running')] };
    const app = await loadApp({ routes, hash: '#/captures' });
    try {
      Object.assign(app.get('POLL'), { idle: 5000, busy: 20 });
      setHidden(app, false);
      await waitFor(() => n(app) >= 4, 'busy poll did not run at the short interval');
      setHidden(app, true);
      await settle();
      const frozen = n(app);
      await new Promise((r) => setTimeout(r, 120));
      assert.equal(n(app), frozen, 'a hidden tab does not poll');
      setHidden(app, false);
      await waitFor(() => n(app) > frozen, 'did not resume');
    } finally { await stop(app); }
  });

  await t.test('never re-renders under the user while editing', async () => {
    let captures = [];
    const routes = { ...defaultRoutes(), 'GET captures': () => captures };
    const app = await loadApp({ routes, hash: '#/overview' });
    try {
      app.get('POLL').idle = 20;
      app.get('S').editing = true;
      setHidden(app, false);
      const main = app.$('#main > *');
      captures = [cap('late', 'running')];
      await waitFor(() => app.$('#tree-capture-count').textContent === '1', 'chrome (capture count) still updates');
      assert.ok(main.isConnected, 'the main pane was not replaced');
    } finally { await stop(app); }
  });

  await t.test('a failing background poll stays silent', async () => {
    let down = false;
    const routes = { ...defaultRoutes(), 'GET inventory': () => (down ? { __status: 500, body: { error: 'x' } } : defaultRoutes()['GET inventory']) };
    const app = await loadApp({ routes, hash: '#/overview', storage: { actor: 'tester' } });
    try {
      app.get('POLL').idle = 20;
      setHidden(app, false);
      down = true;
      const before = n(app);
      await waitFor(() => n(app) >= before + 3);
      assert.equal(app.text('#toast'), '');
    } finally { await stop(app); }
  });
});
