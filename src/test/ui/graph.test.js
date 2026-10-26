// The graph view: assets as nodes, observed conversations as labelled directed edges, advisories as linked nodes.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field, RICH_FLOWS } = require('./support/fixtures');

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

  await t.test('many conversations between one pair merge into one edge that opens the client', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ client: '10.0.1.50', server: '10.0.1.40', protocol: 'unknown', port: (4000 + i) + '/udp', messages: 3 }));
    const app = await loadApp({ routes: defaultRoutes({ flows: many }), hash: '#/graph' });
    try {
      const { edges: es } = app.get('graphModel()');
      const flow = es.filter((e) => e.kind === 'flow');
      assert.equal(flow.length, 1);
      assert.equal(flow[0].label, '5 threads');
      assert.equal(flow[0].n, 15);
    } finally { app.close(); }
  });

  await t.test('regression: Details on a merged busy-pair edge opens its panel (it used to link to #/edge/null: "No such conversation")', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ client: '10.0.1.50', server: '10.0.1.40', protocol: i < 3 ? 'modbus' : 'unknown', port: (500 + i) + '/tcp', messages: 3 + i,
      labels: i < 3 ? { ['Modbus FC' + i]: 2, 'Modbus FC17 exception': 1 } : {}, operations: i === 0 ? [{ function: 'FC0 x', access: 'read', count: 2 }] : [] }));
    const app = await loadApp({ routes: defaultRoutes({ flows: many }), hash: '#/asset/10.0.1.50' });
    try {
      app.$$('#main button.tab').find((b) => /^Talks to/.test(b.textContent)).click();
      await settle();
      const details = app.$$('#main a.btn').filter((a) => a.textContent === 'Details');
      assert.equal(details.length, 1, 'one merged card');
      assert.doesNotMatch(details[0].getAttribute('href'), /null|undefined/);
      assert.match(app.text(), /Modbus FC17 exception ×3/, 'the card lists every message kind');
      await app.go(details[0].getAttribute('href'));
      assert.doesNotMatch(app.text(), /No such conversation/);
      assert.match(app.text(), /5 threads/);
      assert.match(app.text(), /Modbus FC17 exception ×3/, 'the panel shows the same kinds as the card');
      assert.match(app.text(), /FC0 x/, 'merged operations are listed too');
      assert.equal(app.$$('#main a.btn').filter((a) => a.textContent === 'Details').length, 5, 'each member conversation links to its own panel');
      await app.go(app.$$('#main a.btn').filter((a) => a.textContent === 'Details')[0].getAttribute('href'));
      assert.doesNotMatch(app.text(), /No such conversation/);
      app.window.location.hash = '#/graph';
      await settle();
      app.$$('#graph .edge.flow')[0].dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      await settle();
      assert.match(app.window.location.hash, /^#\/edge\/pair%3A/, 'clicking the merged edge opens the same panel');
    } finally { app.close(); }
  });

  await t.test('link distance grows with the messages a pair exchanges, up to a cap, still one spring per pair', async () => {
    const flows = [
      { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', messages: 2, labels: { 'Modbus FC3': 2 } },
      { client: '10.0.1.20', server: '10.0.1.10', protocol: 'modbus', port: '502/tcp', messages: 1000000, labels: { 'Modbus FC3': 1000000 } },
    ];
    const app = await loadApp({ routes: defaultRoutes({ flows }), hash: '#/graph' });
    try {
      assert.equal(app.get('linkStretch(0)'), 1, 'no traffic: the base spacing');
      assert.ok(app.get('linkStretch(150)') > app.get('linkStretch(10)'), 'more messages, more distance');
      assert.equal(app.get('linkStretch(1e12)'), app.get('LINK_MAX'), 'capped');
      const d = (a, b) => app.get(`Math.hypot(GR.pos.get('${a}').x - GR.pos.get('${b}').x, GR.pos.get('${a}').y - GR.pos.get('${b}').y)`);
      const quiet = d('10.0.1.50', '10.0.1.40'), busy = d('10.0.1.20', '10.0.1.10');
      assert.ok(busy > quiet * 1.5, `busy pair ${busy.toFixed(0)} px vs quiet pair ${quiet.toFixed(0)} px`);
      assert.ok(busy < app.get('K') * app.get('LINK_MAX') * 1.3, 'and the cap keeps it readable');
      assert.equal(app.get('springsOf(graphModel().edges, new Map(graphModel().nodes.map((n, i) => [n.id, i]))).size'),
        new Set(app.get('graphModel().edges').map((e) => [e.from, e.to].sort().join())).size, 'one spring per pair');
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

  await t.test('clicking a node floats its panel beside it, several at once; a second click closes it; dock moves it to the route', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      node(app, '10.0.1.40').dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      node(app, '10.0.1.50').dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      await settle();
      assert.equal(app.window.location.hash, '#/graph', 'floating does not navigate');
      assert.deepEqual(app.$$('#floats .float').map((f) => f.dataset.id), ['10.0.1.40', '10.0.1.50']);
      assert.match(app.text('#floats'), /CISA high-priority attributes/);
      assert.match(app.$('#floats .float').style.transform, /translate\(.*\) scale\(/, 'placed against its node');
      node(app, '10.0.1.50').dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      assert.equal(app.$$('#floats .float').length, 1);
      app.$('#floats .float-dock').click(); await settle();
      assert.equal(app.window.location.hash, '#/asset/10.0.1.40');
      assert.equal(app.$$('#floats .float').length, 0, 'one panel docks at a time');
      assert.equal(app.$('#main').className, 'panel');
    } finally { app.close(); }
  });

  await t.test('the panel lists the asset\'s conversations as evidence', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/asset/10.0.1.40' });
    try {
      assert.match(app.text(), /Talks to \(2\)/, 'two devices talk to it, over three conversations');
      app.$$('#main button.tab').find((b) => /^Talks to/.test(b.textContent)).click();
      await settle();
      assert.match(app.text(), /from.*10\.0\.1\.50.*modbus 502\/tcp.*12 messages/);
      assert.match(app.text(), /Modbus FC43\/14 request ×4/);
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

  await t.test('pcap: and capture: match the capture that contributed an asset and its edges', async () => {
    const captureAssets = { c0001: ['10.0.1.40', '10.0.1.50'], c0002: ['10.0.1.10', '10.0.1.50'] };
    const captures = [
      { id: 'c0001', file: 'cell1.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T10:00:00Z', sha256: 'a'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
      { id: 'c0002', file: 'cell2.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T11:00:00Z', sha256: 'b'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
    ];
    const flows = [
      { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', messages: 2, labels: {}, captures: ['c0001'] },
      { client: '10.0.1.50', server: '10.0.1.10', protocol: 'ethernet-ip', port: '44818/tcp', messages: 1, labels: {}, captures: ['c0002'] },
    ];
    const app = await loadApp({ routes: defaultRoutes({ captureAssets, captures, flows }), hash: '#/graph' });
    try {
      const ask = async (q) => { app.$('#q').value = q; app.$('#q').dispatchEvent(new app.window.Event('input')); await settle(); };
      await ask('pcap:cell1');
      assert.equal(app.get('assets().filter(matches).map((a) => a.id).sort().join(",")'), '10.0.1.40,10.0.1.50', 'file-name substring matches both devices the capture saw');
      assert.equal(edges(app).filter((e) => e.classList.contains('flow') && !e.classList.contains('dim')).map((e) => [...e.classList].find((c) => c.startsWith('p-'))).join(','), 'p-modbus',
        'the conversation from another capture is dimmed too');
      await ask('capture:c0002');
      assert.equal(app.get('assets().filter(matches).map((a) => a.id).sort().join(",")'), '10.0.1.10,10.0.1.50');
      assert.equal(app.get('parseQuery("capture:c0002").capture'), 'c0002');
    } finally { app.close(); }
  });

  await t.test('the inventory lists what the graph shows, and the hidden captures survive a reload', async () => {
    const captureAssets = { c0001: ['10.0.1.40', '10.0.1.20'], c0002: ['10.0.1.10', '10.0.1.40'] };
    const captures = [
      { id: 'c0001', file: 'cell1.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T10:00:00Z', sha256: 'a'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
      { id: 'c0002', file: 'cell2.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T11:00:00Z', sha256: 'b'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
    ];
    const first = await loadApp({ routes: defaultRoutes({ captureAssets, captures }), hash: '#/inventory' });
    let saved;
    try {
      first.get('S').capOff.add('c0001');
      first.get('render()');
      assert.equal(first.$$('#main .inventory-asset').some((a) => a.textContent.includes('10.0.1.20') || a.nextSibling.textContent === '10.0.1.20'), false, 'a hidden capture device is not listed');
      saved = first.window.localStorage.getItem('view');
    } finally { first.close(); }
    const again = await loadApp({ routes: defaultRoutes({ captureAssets, captures }), hash: '#/inventory', storage: { view: saved } });
    try {
      assert.ok(again.get('S').capOff.has('c0001'), 'the hidden capture is still hidden after a reload');
    } finally { again.close(); }
  });

  await t.test('hiding a capture removes only its nodes, and Reset view brings them back', async () => {
    const captureAssets = { c0001: ['10.0.1.40', '10.0.1.20'], c0002: ['10.0.1.10', '10.0.1.40'] };
    const captures = [
      { id: 'c0001', file: 'cell1.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T10:00:00Z', sha256: 'a'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
      { id: 'c0002', file: 'cell2.pcap', state: 'done', by: 'A', size: 1, at: '2026-10-19T11:00:00Z', sha256: 'b'.repeat(64), diff: { new: 1, changed: 0, notSeen: 0 } },
    ];
    const app = await loadApp({ routes: defaultRoutes({ captureAssets, captures }), hash: '#/graph' });
    try {
      app.get('S').capOff.add('c0001');
      app.get('render()');
      assert.equal(node(app, '10.0.1.20'), null, 'the capture-exclusive node is gone');
      assert.ok(node(app, '10.0.1.40'), 'a node another capture also saw stays');
      assert.ok(node(app, '10.0.1.10'), 'the other capture stays');
      app.$$('#pop-filter button').find((b) => b.textContent === 'Reset view').click();
      await settle();
      assert.ok(node(app, '10.0.1.20'), 'Reset view clears the hidden captures');
      assert.equal(app.get('S').capOff.size, 0);
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
      assert.equal(nodes(app).filter((n) => !n.classList.contains('adv')).length, 3, 'a path hides every asset off it instead of dimming it');
      assert.equal(app.$$('#graph .pin.a').length + app.$$('#graph .pin.b').length, 2, 'start and target carry A and B pins');
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

  await t.test('path selection can use two clicked graph nodes', async () => {
    const app = await richApp();
    try {
      app.$('#btn-route').click();
      assert.equal(app.$('#btn-route').getAttribute('aria-pressed'), 'true');
      node(app, '10.0.1.50').dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      assert.equal(app.get('S.pathStart'), '10.0.1.50');
      assert.ok(node(app, '10.0.1.50').querySelector('.pin.a'), 'the start is pinned as soon as it is clicked');
      node(app, '10.0.1.40').dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
      assert.ok(app.get('S.path'), 'a path selection is stored');
      assert.deepEqual([...app.get('S.path.nodes')], ['10.0.1.50', '10.0.1.40']);
      assert.equal(app.get('S.pathPick'), false);
      assert.equal(app.$('#btn-route').getAttribute('aria-pressed'), 'false');
    } finally { app.close(); }
  });

  await t.test('colour by advisory risk recolours the nodes', async () => {
    const app = await loadApp({ routes: defaultRoutes(), hash: '#/graph' });
    try {
      const disc = () => node(app, '10.0.1.40').querySelector('.disc').getAttribute('stroke');
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
      app.$('#btn-filter').click();
      assert.equal(app.$('#pop-info').hidden, true);
      assert.equal(app.$('#pop-filter').hidden, false);
      app.document.dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Escape' }));
      assert.equal(app.$('#pop-filter').hidden, true);
    } finally { app.close(); }
  });

  await t.test('the filter popover drives the graph filters', async () => {
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

// Edges: protocol colours, the edge side panel, the filter toggles and the readable-label rules.
const flowEdges = (app) => app.$$('#graph .edge.flow');
const edgeOf = (app, proto) => flowEdges(app).find((e) => e.classList.contains('p-' + proto));
const stroke = (e) => e.querySelector('.epath').getAttribute('stroke');
const click = (app, el) => el.dispatchEvent(new app.window.MouseEvent('click', { bubbles: true }));
// Assets list the protocols they were seen speaking (the native detector and the Zeek reader both write them), which is what proto: matches.
function richInventory() {
  const inv = exampleInventory();
  const set = (id, ...p) => { inv.assets.find((a) => a.id === id).protocols = field(p); };
  set('10.0.1.20', 'dnp3'); set('10.0.1.10', 'dnp3'); set('10.0.1.50', 'modbus', 'unknown'); set('10.0.1.40', 'modbus'); set('10.0.1.60', 'unknown');
  return inv;
}
const richApp = (hash = '#/graph') => loadApp({ routes: defaultRoutes({ inventory: richInventory(), flows: RICH_FLOWS }), hash });
/** The "Hidden by default" facet row of one class (its label starts with `label`): the row text and its Show/Hide button. */
const facetRow = (app, label) => app.$$('#hidden-facet .row').find((r) => r.textContent.includes(label));
const showScans = async (app) => { facetRow(app, 'Scan-only').querySelector('button').click(); await settle(); };

test('edges', async (t) => {
  await t.test('each protocol has its own edge colour, unknown is grey, and width grows with the message count', async () => {
    const app = await richApp();
    try {
      await showScans(app);
      const colours = new Map(flowEdges(app).map((e) => [[...e.classList].find((c) => c.startsWith('p-')), stroke(e)]));
      assert.equal(colours.get('p-modbus'), app.get('PROTO_COLOR').modbus);
      assert.equal(colours.get('p-dnp3'), app.get('PROTO_COLOR').dnp3);
      assert.equal(colours.get('p-unknown'), '#7B8696');
      assert.equal(new Set(['modbus', 'dnp3', 'ethernet-ip', 's7comm', 'snmp'].map((k) => app.get('PROTO_COLOR')[k])).size, 5, 'five distinct colours');
      const width = (e) => parseFloat(e.querySelector('.epath').getAttribute('stroke-width'));
      assert.ok(width(edgeOf(app, 'modbus')) > width(edgeOf(app, 'dnp3')), '1200 messages draw wider than 30');
      assert.ok(width(edgeOf(app, 'dnp3')) > width(flowEdges(app).find((e) => e.classList.contains('scan'))), '30 messages draw wider than none');
      assert.match(edgeOf(app, 'modbus').querySelector('path[marker-end]').getAttribute('marker-end'), /arr-p-modbus/);
      assert.ok(app.$('#arr-p-dnp3'), 'an arrowhead exists for every protocol colour');
    } finally { app.close(); }
  });

  await t.test('clicking an edge opens its panel with protocol, ports, counters, times, rate and the operations table', async () => {
    const app = await richApp();
    try {
      click(app, edgeOf(app, 'modbus'));
      await settle();
      assert.equal(app.window.location.hash, '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.40>modbus>502/tcp'));
      assert.equal(app.$('#main').className, 'panel');
      const text = app.text();
      assert.match(text, /Modbus/);
      assert.match(text, /502\/tcp/);
      assert.match(text, /Messages.*1,200|1,200/);
      assert.match(text, /Packets\s*2,400/);
      assert.match(text, /Bytes\s*95\.7 kB/);
      assert.match(text, /First seen\s*2015-10-22 09:00:01Z/);
      assert.match(text, /Last seen\s*2015-10-22 10:00:00Z/);
      assert.match(text, /Rate\s*20\.0 \/min/, 'messages per minute over first..last seen: 1200 / 59.98 min');
      assert.match(text, /Span\s*60 min/);
      assert.match(text, /Modbus FC3 ×1100/);
      const rows = app.$$('#main .trow.g-op:not(.thead)');
      assert.equal(rows.length, 2);
      assert.match(rows[0].textContent, /FC3 read holding registers.*read.*40001.*10.*1100.*12, 0, 7/, 'busiest first');
      assert.match(rows[1].textContent, /FC16 write multiple registers.*write.*40100.*2.*100.*1, 2/);
      assert.ok(edgeOf(app, 'modbus').classList.contains('hot'), 'the open edge is highlighted');
      assert.ok(edgeOf(app, 'dnp3').classList.contains('dim'), 'the others dim');
      assert.equal(app.$$('#graph .node').filter((n) => n.classList.contains('dim')).length > 0, true);
    } finally { app.close(); }
  });

  await t.test('Enter on a focused edge opens the same panel; a DNP3 edge without operations explains where they come from', async () => {
    const app = await richApp();
    try {
      const e = edgeOf(app, 'dnp3');
      assert.equal(e.getAttribute('tabindex'), '0');
      assert.equal(e.getAttribute('role'), 'button');
      e.dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      await settle();
      assert.match(app.window.location.hash, /^#\/edge\/10\.0\.1\.20%3E10\.0\.1\.10%3Edn?p3/);
      assert.match(app.text(), /DNP3 FC1 READ ×20/);
      assert.match(app.text(), /Rate\s*3\.00 \/min/);
      assert.equal(app.$$('#main .trow.g-op:not(.thead)').length, 0);
      assert.match(app.text(), /No operation detail.*--engine zeek/);
    } finally { app.close(); }
  });

  await t.test('an undecoded host pair says so, and a scan-only edge is labelled as scan attempts', async () => {
    const app = await richApp('#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.60>unknown>80/tcp'));
    try {
      assert.match(app.text(), /Unknown/);
      assert.match(app.text(), /Carried but not decoded/);
      assert.match(app.text(), /Rate\s*n\/a/, 'under a second: a burst has no rate');
      await app.go('#/edge/' + encodeURIComponent('10.0.1.60>10.0.1.20>unknown>23/tcp'));
      assert.match(app.text(), /scan attempts only/);
      assert.match(app.text(), /Scan attempts\s*4/);
    } finally { app.close(); }
  });

  await t.test('a conversation trace is drawn as chat bubbles, and the side panel has a resize handle', async () => {
    const flows = [{ client: '10.0.1.50', server: '10.0.1.60', protocol: 'ssl', port: '443/tcp', transport: 'tcp', messages: 4, labels: {},
      trace: ['11:35:36 * TLS TLSv12 cipher=AES128', '11:35:36 > ClientHello server_name=plc.local', '11:35:36 < ServerHello', '11:35:37 < Certificate[0] subject=CN=plc.local self-signed'] }];
    const app = await loadApp({ routes: defaultRoutes({ flows }), hash: '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.60>ssl>443/tcp') });
    try {
      assert.equal(app.$$('.chat .msg.out').length, 1, 'the client line is one bubble');
      assert.equal(app.$$('.chat .msg.in').length, 1, 'two server lines in a row share one bubble');
      assert.match(app.text('.chat .msg.in'), /Certificate\[0\].*subject.*CN=plc\.local/);
      assert.equal(app.$('#split').hidden, false);
    } finally { app.close(); }
  });

  await t.test('an undecoded flow shows its port-inferred hint as a hint, and keeps the grey unknown colour', async () => {
    const flows = [{ client: '10.0.1.50', server: '10.0.1.60', protocol: 'unknown', port: '22/tcp', transport: 'tcp', messages: 4, portHint: 'ssh', labels: {} }];
    const app = await loadApp({ routes: defaultRoutes({ flows }), hash: '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.60>unknown>22/tcp') });
    try {
      assert.match(app.text(), /Carried but not decoded.*Port 22\/tcp is usually ssh \(a hint from the port number only/);
      await app.go('#/graph');
      assert.equal(app.$$('#graph .edge.flow')[0].querySelector('text').textContent, '22/tcp (ssh?)');
      assert.ok(app.$$('#graph .edge.flow')[0].classList.contains('p-unknown'));
    } finally { app.close(); }
  });

  await t.test('a conversation that is not in the inventory says so instead of failing', async () => {
    const app = await richApp('#/edge/nope');
    try {
      assert.match(app.text(), /No such conversation/);
    } finally { app.close(); }
  });

  await t.test('the filter toggles hide unknown edges, scan edges and single protocols', async () => {
    const app = await richApp();
    try {
      assert.equal(flowEdges(app).length, 3, 'scan-only conversations are in the data but hidden by default');
      assert.match(facetRow(app, 'Scan-only').textContent, /Scan-only conversations: 1.*hidden, kept in the inventory/);
      await showScans(app);
      assert.equal(flowEdges(app).length, 4);
      const hideUnknown = () => facetRow(app, 'Unknown-protocol').querySelector('button').click();
      hideUnknown();
      await settle();
      assert.equal(app.get('S').hideUnknown, true);
      assert.deepEqual(flowEdges(app).map((e) => [...e.classList].find((c) => c.startsWith('p-'))).sort(), ['p-dnp3', 'p-modbus'], 'both unknown edges (host pair and scan) go');
      hideUnknown();
      await settle();
      facetRow(app, 'Scan-only').querySelector('button').click();
      await settle();
      assert.equal(flowEdges(app).length, 3);
      assert.equal(flowEdges(app).some((e) => e.classList.contains('scan')), false);
      assert.ok(edgeOf(app, 'unknown'), 'the decoded-less host pair stays');
      await showScans(app);
      const box = app.$$('#pop-filter input[type=checkbox]').find((c) => /Modbus/.test(c.getAttribute('aria-label')));
      box.checked = false;
      box.dispatchEvent(new app.window.Event('change', { bubbles: true }));
      await settle();
      assert.equal(edgeOf(app, 'modbus'), undefined);
      assert.ok(edgeOf(app, 'dnp3'));
      assert.deepEqual(app.$$('#pop-filter input[type=checkbox]').map((c) => /DNP3|Modbus|ENIP|S7|SNMP|ICMP/.exec(c.getAttribute('aria-label'))[0]), ['Modbus', 'DNP3', 'ENIP', 'S7', 'SNMP', 'ICMP']);
    } finally { app.close(); }
  });

  await t.test('the query box understands proto:dnp3, proto:unknown and rate>N', async () => {
    const app = await richApp();
    try {
      const ask = async (q) => { app.$('#q').value = q; app.$('#q').dispatchEvent(new app.window.Event('input')); await settle(); };
      const lit = () => flowEdges(app).filter((e) => !e.classList.contains('dim')).map((e) => [...e.classList].find((c) => c.startsWith('p-'))).sort();
      await ask('proto:dnp3');
      assert.deepEqual(lit(), ['p-dnp3']);
      await ask('proto:unknown');
      assert.deepEqual(lit(), ['p-unknown'], 'the scan edge ends at a host that is not listed as unknown');
      await ask('rate>10');
      assert.deepEqual(lit(), ['p-modbus'], 'only the 20 /min conversation is faster than 10 /min');
      await ask('rate>2');
      assert.deepEqual(lit(), ['p-dnp3', 'p-modbus'], '3 /min passes');
      assert.equal(app.get('parseQuery("rate>2.5 proto:dnp3 plc")').rate, 2.5);
      assert.deepEqual([...app.get('parseQuery("rate>2.5 proto:dnp3 plc")').text], ['plc']);
      await ask('rate>nonsense');
      assert.equal(app.get('parseQuery("rate>nonsense")').rate, undefined, 'a malformed rate term is plain text, not a filter');
    } finally { app.close(); }
  });

  await t.test('the node panel lists peers with rate and the operations summary, linking to the edge panel', async () => {
    const app = await richApp('#/asset/10.0.1.40');
    try {
      app.$$('#main button.tab').find((b) => /^Talks to/.test(b.textContent)).click();
      await settle();
      const text = app.text();
      assert.match(text, /from.*10\.0\.1\.50.*modbus 502\/tcp.*1200 messages · 20\.0 \/min/);
      assert.match(text, /Operations: FC3 read holding registers @40001 ×1100 · FC16 write multiple registers @40100 ×100/);
      const link = app.$$('#main a').find((a) => a.textContent === 'Details');
      assert.equal(link.getAttribute('href'), '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.40>modbus>502/tcp'));
    } finally { app.close(); }
  });

  await t.test('Zeek-sourced strings are text in the edge panel, never markup', async () => {
    const evil = [{ client: '10.0.1.50', server: '10.0.1.40', protocol: '<img src=x onerror="window.__pwned=1">', port: '<script>window.__pwned=2</script>', messages: 3,
      firstSeen: '2015-10-22T09:00:00Z', lastSeen: '2015-10-22T09:01:00Z', source: '<b>zeek</b>',
      labels: { '<svg onload="window.__pwned=3">': 3 },
      operations: [{ function: '<img src=y onerror="window.__pwned=4">', access: '<i>read</i>', object: '<u>g1</u>', address: 1, quantity: 2, count: 3,
        sampleValues: ['<img src=z onerror="window.__pwned=5">', 7] }] }];
    const app = await loadApp({ routes: defaultRoutes({ flows: evil }), hash: '#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.40><img src=x onerror="window.__pwned=1">><script>window.__pwned=2</script>') });
    try {
      assert.equal(app.window.__pwned, undefined);
      assert.equal(app.$$('#main img, #main script, #main svg, #main b, #main i, #main u, #graph img, #graph script').length, 0, 'no element was created from a string');
      assert.match(app.text(), /<img src=y onerror=/);
      assert.match(app.text(), /<img src=z onerror=/);
      assert.match(app.text(), /<svg onload=/);
      assert.match(app.text(), /<script>window\.__pwned=2<\/script>/);
      assert.match(edgeOf(app, 'unknown').getAttribute('aria-label'), /<img src=x/);
    } finally { app.close(); }
  });

  await t.test('labels keep a minimum size on screen: they grow in graph units as the view zooms out, edge labels vanish below the threshold', async () => {
    const app = await richApp();
    try {
      const svg = app.$('#graph');
      const px = (name) => parseFloat(svg.style.getPropertyValue(name));
      app.get('GR').view = { x: 0, y: 0, k: 1 }; app.get('applyView()');
      assert.equal(px('--nfs'), 13);
      assert.equal(svg.classList.contains('no-elabels'), false);
      app.get('GR').view = { x: 0, y: 0, k: 0.5 }; app.get('applyView()');
      assert.ok(px('--nfs') * 0.5 >= 13 - 1e-9, 'node labels are at least 13 px on screen at zoom 0.5');
      assert.ok(px('--efs') * 0.5 >= 12 - 1e-9, 'edge labels are at least 12 px on screen');
      assert.equal(svg.classList.contains('no-elabels'), true, 'edge labels are dropped below zoom 0.55, not shrunk');
      app.get('GR').view = { x: 0, y: 0, k: 0.2 }; app.get('applyView()');
      assert.ok(px('--nfs') * 0.2 >= 13 - 1e-9);
      assert.equal(app.$$('#graph .nlabel').length > 0, true, 'node labels stay');
      app.get('GR').view = { x: 0, y: 0, k: 2 }; app.get('applyView()');
      assert.equal(px('--nfs'), 12, 'zoomed in, labels scale with the view as before');
      assert.equal(svg.classList.contains('no-elabels'), false);
    } finally { app.close(); }
  });
});
