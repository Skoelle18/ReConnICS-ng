// The graph view: assets as nodes, observed conversations as labelled directed edges, advisories as linked nodes.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field } = require('./support/fixtures');

const nodes = (app) => app.$$('#graph .node');
const edges = (app) => app.$$('#graph .edge');
const node = (app, id) => app.$(`#graph .node[data-id="${id}"]`);

test('graph', async (t) => {
  await t.test('every asset is a focusable, labelled node; every conversation a labelled directed edge', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      assert.equal(app.$('#main').hidden, true, 'the graph route shows no sheet');
      const assets = nodes(app).filter((n) => !n.classList.contains('adv'));
      assert.equal(assets.length, 10);
      for (const n of nodes(app)) {
        assert.equal(n.getAttribute('tabindex'), '0');
        assert.equal(n.getAttribute('role'), 'button');
        assert.ok(n.getAttribute('aria-label').length > 10, 'accessible name');
      }
      assert.match(node(app, '10.0.1.40').getAttribute('aria-label'), /PLC.*advisory match EXACT.*KEV at model/);
      const flow = edges(app).filter((e) => e.classList.contains('flow'));
      assert.equal(flow.length, 4);
      assert.ok(flow.every((e) => e.querySelector('path[marker-end]')), 'arrowheads: edges are directed');
      const labels = flow.map((e) => e.querySelector('text').textContent);
      assert.ok(labels.includes('Modbus FC43/14 request +2'), labels.join('|'));
      assert.ok(labels.includes('ENIP ListIdentity'), 'protocol prefix added to a bare ListIdentity');
      assert.ok(labels.includes('S7 SZL read request'));
      assert.match(flow[0].getAttribute('aria-label'), /from .*\(10\.0\.1\.50\) to .*\(10\.0\.1\.40\): modbus 502\/tcp.*12 messages/);
    } finally { app.close(); }
  });

  await t.test('two conversations between one pair are drawn as different arcs', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const { edges: es } = app.get('graphModel()');
      const pair = es.filter((e) => e.kind === 'flow' && e.to === '10.0.1.40' && e.from === '10.0.1.50');
      assert.equal(pair.length, 2);
      const ds = edges(app).filter((e) => /^Conversation from .*\(10\.0\.1\.50\) to .*\(10\.0\.1\.40\)/.test(e.getAttribute('aria-label'))).map((e) => e.querySelector('path').getAttribute('d'));
      assert.equal(ds.length, 2);
      assert.notEqual(ds[0], ds[1]);
    } finally { app.close(); }
  });

  await t.test('gateway units and slots hang off their parent; advisories hang off matched assets', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const { edges: es, nodes: ns } = app.get('graphModel()');
      assert.ok(es.some((e) => e.kind === 'unit' && e.from === '10.0.1.30' && e.to === '10.0.1.30/u3'));
      assert.ok(es.some((e) => e.kind === 'unit' && e.from === '10.0.1.10' && e.to === '10.0.1.10/slot0'));
      assert.ok(ns.some((n) => n.id === 'adv:TEST-ADVISORY-0001'));
      assert.ok(es.some((e) => e.kind === 'adv' && e.from === '10.0.1.40' && e.label === 'EXACT'));
      assert.match(node(app, 'adv:TEST-ADVISORY-0001').getAttribute('aria-label'), /KEV listed.*affects 1 asset/);
    } finally { app.close(); }
  });

  await t.test('clicking a node opens the details side panel; keyboard Enter does too', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      node(app, '10.0.1.40').dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      await settle();
      assert.equal(app.window.location.hash, '#/asset/10.0.1.40');
      assert.equal(app.$('#main').className, 'panel');
      assert.match(app.text(), /CISA high-priority attributes/);
      assert.ok(node(app, '10.0.1.40').classList.contains('sel'));
      assert.ok(node(app, '10.0.1.20').classList.contains('dim') === false, 'a neighbour stays lit');
      assert.ok(node(app, '10.0.1.60').classList.contains('dim'), 'unrelated assets dim');
      node(app, '10.0.1.50').dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      await settle();
      assert.equal(app.window.location.hash, '#/asset/10.0.1.50');
    } finally { app.close(); }
  });

  await t.test('the panel lists the asset\'s conversations as evidence', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.40' });
    try {
      assert.match(app.text(), /Conversations \(3\)/);
      app.$$('#main button.tab').find((b) => /^Conversations/.test(b.textContent)).click();
      await settle();
      assert.match(app.text(), /from.*10\.0\.1\.50.*modbus 502\/tcp.*12 messages/);
      assert.match(app.text(), /Modbus FC43\/14 request ×4/);
    } finally { app.close(); }
  });

  await t.test('the inventory table lists the same conversations (table fallback)', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/inventory' });
    try {
      const rows = app.$$('#main .trow.g-flow:not(.thead)');
      assert.equal(rows.length, 4);
      assert.match(rows[0].textContent, /10\.0\.1\.50.*10\.0\.1\.40.*modbus 502\/tcp.*FC43\/14 request ×4/);
    } finally { app.close(); }
  });

  await t.test('filters dim the graph and the query box understands level:, kev and proto:', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const q = app.$('#q');
      q.value = 'level:exact';
      q.dispatchEvent(new app.window.Event('input'));
      await settle();
      assert.equal(nodes(app).filter((n) => !n.classList.contains('dim') && !n.classList.contains('adv')).length, 1);
      assert.equal(app.window.location.hash, '#/graph', 'filtering does not leave the graph');
      q.value = 'proto:modbus kev';
      q.dispatchEvent(new app.window.Event('input'));
      await settle();
      assert.equal(app.get('assets().filter(matches).length'), 0, 'KEV and modbus together match nothing in the fixture');
      q.value = '';
      q.dispatchEvent(new app.window.Event('input'));
      await settle();
      assert.equal(nodes(app).filter((n) => n.classList.contains('dim')).length, 0);
    } finally { app.close(); }
  });

  await t.test('path button highlights the shortest conversation path, or says there is none', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      app.$('#start').value = '10.0.1.50';
      app.$('#target').value = '10.0.1.10/slot0';
      app.$('#btn-go').click();
      await settle();
      assert.deepEqual([...app.get('S').path.nodes], ['10.0.1.50', '10.0.1.10', '10.0.1.10/slot0']);
      assert.equal(edges(app).filter((e) => e.classList.contains('hot')).length, 2);
      assert.match(app.text('#toast'), /2 hops/);
      app.$('#target').value = '10.0.2.1';
      app.$('#btn-go').click();
      await settle();
      assert.equal(app.get('S').path, null);
      assert.match(app.text('#toast'), /No observed conversation path/);
      app.$('#btn-back').click();
      await settle();
      assert.equal(app.$('#start').value, '');
    } finally { app.close(); }
  });

  await t.test('colour by advisory risk recolours the nodes', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const disc = () => node(app, '10.0.1.40').querySelector('.disc').getAttribute('fill');
      const role = disc();
      app.get('S').color = 'risk';
      app.get('render()');
      assert.notEqual(disc(), role);
      assert.equal(disc(), app.get('LEVEL_COLOR').EXACT);
    } finally { app.close(); }
  });

  await t.test('an empty inventory shows the drop hint, not an empty void', async () => {
    const routes = defaultRoutes();
    routes['GET inventory'] = { inventory: { assets: [] }, rank: [], site: {} };
    const app = await loadApp({ routes, hash: '#/graph' });
    try {
      assert.equal(app.$('#graph-empty').hidden, false);
      assert.equal(nodes(app).length, 0);
    } finally { app.close(); }
  });

  await t.test('device strings are text in the graph, never markup', async () => {
    const inv = exampleInventory();
    inv.assets[0].hostname = field('<img src=x onerror="window.__pwned=1">');
    const flows = [{ client: '10.0.1.50', server: '10.0.1.10', protocol: 'modbus', port: '502/tcp', messages: 1, labels: { '<svg onload="window.__pwned=2">': 1 } }];
    const app = await loadApp({ routes: defaultRoutes({ inventory: inv, flows }), hash: '#/graph' });
    try {
      assert.equal(app.window.__pwned, undefined);
      assert.equal(app.$$('#graph img, #graph svg svg, #graph script').length, 0);
      assert.match(app.$$('#graph .elabel').map((l) => l.textContent).join('|'), /<svg onload=/);
      assert.match(node(app, '10.0.1.10').getAttribute('aria-label'), /<img src=x/);
    } finally { app.close(); }
  });

  await t.test('zoom controls change the viewport and 0 / home fit it', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const k = () => app.get('GR').view.k;
      const fit = k();
      app.$('#z-in').click();
      assert.ok(k() > fit);
      app.$('#z-out').click(); app.$('#z-out').click();
      assert.ok(k() < fit);
      app.$('#z-fit').click();
      assert.equal(k(), fit);
      assert.match(app.$('#viewport').getAttribute('transform'), /scale/);
    } finally { app.close(); }
  });

  await t.test('toolbar popovers open one at a time and Escape closes them', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      app.$('#tb-info').click();
      assert.equal(app.$('#pop-info').hidden, false);
      app.$('#tb-export').click();
      assert.equal(app.$('#pop-info').hidden, true);
      assert.equal(app.$('#pop-export').hidden, false);
      assert.equal(app.$('#tb-export').getAttribute('aria-expanded'), 'true');
      app.document.dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Escape' }));
      assert.equal(app.$('#pop-export').hidden, true);
    } finally { app.close(); }
  });

  await t.test('the filter popover drives the same filters as the inventory chips', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      app.$$('#pop-filter button').find((b) => b.textContent === 'KEV only').click();
      await settle();
      assert.equal(app.get('S').kevOnly, true);
      assert.equal(app.$$('#pop-filter button').find((b) => b.textContent === 'KEV only').getAttribute('aria-pressed'), 'true');
      assert.equal(nodes(app).filter((n) => !n.classList.contains('dim') && !n.classList.contains('adv')).length, 1);
    } finally { app.close(); }
  });

  await t.test('importing from the toolbar queues the chosen PCAPs', async () => {
    const routes = defaultRoutes();
    let sent = null;
    routes['POST captures'] = (req) => { sent = req; return { id: 'c1', file: 'x.pcap' }; };
    const app = await loadApp({ routes, hash: '#/graph' });
    try {
      await app.get('upload')([{ name: 'x.pcap' }]);
      assert.equal(sent.headers['Content-Type'], 'application/octet-stream');
      assert.match(sent.route, /^captures\?name=x\.pcap$/);
    } finally { app.close(); }
  });
});
