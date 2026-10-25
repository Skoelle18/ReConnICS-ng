// Retained observations: seen-only hosts, broadcast/multicast group nodes, the "Hidden by default" facet, the Ethernet screen, unknown time.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp, settle } = require('./support/load-app');
const { defaultRoutes, exampleInventory, field } = require('./support/fixtures');

const GROUP = { address: '255.255.255.255', kind: 'broadcast', scope: 'limited broadcast (255.255.255.255)', packets: 15, bytes: 900, senders: ['10.0.1.50'], ports: ['67/udp'], protocols: ['dhcp'] };
const FLOWS = [
  { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', messages: 12, labels: { 'Modbus FC=0x3': 12 } },
  { client: '10.0.1.50', server: '255.255.255.255', protocol: 'unknown', port: '67/udp', messages: 15, packets: 15, portHint: 'dhcp', labels: {} },
  { client: '10.0.1.50', server: '10.0.1.60', protocol: 'icmp', port: 'icmp', messages: 2, labels: { 'ICMP echo request': 1, 'ICMP echo reply': 1 } },
];
const MACS = [
  { mac: '00:1c:7f:39:de:5b', vendor: 'Check Point Software Technologies Ltd.', frames: 900, framesTo: 10, ips: ['10.0.1.50', '10.0.1.60'], ipCount: 2, kind: 'gateway-like', notes: ['2 source IPs behind this MAC: a router, firewall, NAT or proxy interface, or a host with several addresses (inferred)'] },
  { mac: '00:0f:73:03:72:59', frames: 40, ips: ['10.0.1.40'], ipCount: 1, kind: 'host', notes: [] },
];

function inventory() {
  const inv = exampleInventory();
  const a = inv.assets.find((x) => x.id === '10.0.1.60');
  Object.assign(a, { seenOnly: true, behaviour: ['probe-like'], observed: { 'icmp-echo-target': 2 }, role: field('seen only: ICMP echo', 'LOW', 'reconnics-ng attributes.role (seen-only)') });
  const w = inv.assets.find((x) => x.id === '10.0.1.40');
  Object.assign(w, { http: { server: 'A-B WWW/0.1', requests: 40, uris: ['/logo.gif'], statuses: { 200: 30 } }, dhcp: { mac: '00:0f:73:03:72:59', messageTypes: ['unknown-message-type-0'], messages: 15 } });
  return inv;
}
const open = (hash = '#/graph') => loadApp({ routes: defaultRoutes({ inventory: inventory(), flows: FLOWS, groups: [GROUP], macs: MACS }), hash });
const facet = (a, label) => a.$$('#hidden-facet .row').find((r) => r.textContent.includes(label));
const groupNode = (a) => a.$('#graph .node.grp');

test('retained observations', async (t) => {
  await t.test('a broadcast address is hidden by default with its count, and a toggle draws it as a group node that is not an asset', async () => {
    const a = await open();
    try {
      assert.equal(groupNode(a), null);
      assert.match(facet(a, 'Broadcast').textContent, /Broadcast \/ multicast addresses: 1.*hidden, kept in the inventory/);
      facet(a, 'Broadcast').querySelector('button').click();
      await settle();
      const g = groupNode(a);
      assert.ok(g, 'the group node appears');
      assert.match(g.getAttribute('aria-label'), /broadcast address 255\.255\.255\.255, not a device/);
      const toGroup = a.$$('#graph .edge.flow').filter((e) => /255\.255\.255\.255/.test(e.getAttribute('aria-label')));
      assert.equal(toGroup.length, 1, 'the sender is linked to it');
      assert.equal(a.get('assets()').some((x) => x.id === '255.255.255.255'), false);
      g.dispatchEvent(new a.window.MouseEvent('click', { bubbles: true }));
      await settle();
      assert.match(a.text(), /not a device/);
      assert.match(a.text(), /Senders \(1\)/);
    } finally { a.close(); }
  });

  await t.test('a seen-only host is drawn low-confidence, kept visible, and its panel lists what was observed', async () => {
    const a = await open('#/asset/10.0.1.60');
    try {
      assert.ok(a.$('#graph .node.seen[data-id="10.0.1.60"]'));
      assert.match(a.text('#main'), /seen only/);
      const obs = a.text('#observed');
      assert.match(obs, /probe-like/);
      assert.match(obs, /was pinged ×2/);
      assert.match(facet(a, 'Seen-only').textContent, /Seen-only hosts \(low confidence\): 1.*shown/);
      facet(a, 'Seen-only').querySelector('button').click();
      await settle();
      assert.equal(a.$('#graph .node[data-id="10.0.1.60"]'), null, 'the toggle hides it from the graph, not from the inventory');
      assert.ok(a.get('assets()').some((x) => x.id === '10.0.1.60'));
    } finally { a.close(); }
  });

  await t.test('the web server header and DHCP details show on the host, and DHCP without options says so', async () => {
    const a = await open('#/asset/10.0.1.40');
    try {
      const txt = a.text('#observed');
      assert.match(txt, /Server header A-B WWW\/0\.1/);
      assert.match(txt, /\/logo\.gif/);
      assert.match(txt, /carry no host name, vendor class or requested address/);
    } finally { a.close(); }
  });

  await t.test('an ICMP conversation is a labelled edge with no invented dates', async () => {
    const a = await open();
    try {
      const icmp = a.$$('#graph .edge.flow').find((e) => e.classList.contains('p-icmp'));
      assert.ok(icmp);
      assert.match(icmp.querySelector('text').textContent, /^ICMP echo request \+1$/);
      await a.go('#/edge/' + encodeURIComponent('10.0.1.50>10.0.1.60>icmp>icmp'));
      assert.match(a.text(), /Time\s*unknown/);
      assert.doesNotMatch(a.text(), /1970|294247/);
    } finally { a.close(); }
  });

  await t.test('the Ethernet screen lists MACs with maker, counts and inferred gateway notes', async () => {
    const a = await open('#/ethernet');
    try {
      const txt = a.text();
      assert.match(txt, /00:1c:7f:39:de:5b/);
      assert.match(txt, /Check Point/);
      assert.match(txt, /gateway-like/);
      assert.match(txt, /\(inferred\)/);
      assert.match(txt, /10\.0\.1\.50, 10\.0\.1\.60/);
    } finally { a.close(); }
  });
});
