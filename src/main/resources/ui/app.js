// ReConICS site console. Plain JS, no build step, served by `serve` from the jar (docs/plans/2026-10-17-ui.md).
// All DOM is built with h() / sv() and textContent: device-supplied strings never reach innerHTML.
// Layout: a full-bleed asset graph (assets = nodes, observed conversations = edges, advisories hang off assets) with the
// other screens opening over it: #main is a side panel for one asset (#/asset/ID) and a sheet for everything else.
'use strict';

const ATTRS = [
  ['ip', 'IP address', 'passive'], ['mac', 'MAC address', 'passive'], ['protocols', 'Protocols', 'passive'],
  ['ports', 'Ports / services', 'passive'], ['role', 'Role / type', 'passive'], ['vendor', 'Manufacturer', 'passive'],
  ['model', 'Model', 'passive'], ['os', 'OS / firmware', 'passive'], ['hostname', 'Hostname', 'passive'],
  ['criticality', 'Criticality', 'human'], ['asset_number', 'Asset number', 'human'], ['location', 'Physical location', 'human'],
  ['logging', 'Logging', 'human'], ['user_accounts', 'User accounts', 'human'],
];
// Identity details that are not among the 14 but are decoded from the same identity messages; shown in the attribute table only.
const ATTRS_EXTRA = [['serial', 'Serial number', 'passive'], ['deviceType', 'Device type', 'passive'], ['alerts', 'Suricata alerts', 'passive']];
// Open-source tool behind a value, read from the evidence text the server wrote (the tool name is always in it). Badges only; the full text stays next to them.
const SOURCE_TAGS = [[/p0f/i, 'p0f'], [/suricata/i, 'Suricata'], [/ndpi/i, 'nDPI'], [/tshark|wireshark manuf/i, 'Wireshark'], [/nmap/i, 'Nmap data'],
  [/ICSNPP|zeek/i, 'Zeek'], [/IEEE MA-/i, 'IEEE OUI']];
const sourceTags = (text) => SOURCE_TAGS.filter(([re]) => re.test(text || '')).map(([, t]) => t);
const IDENTITY_KEYS = ['vendor', 'model', 'os', 'serial', 'deviceType'];
const NO_IDENTITY = 'No identity message observed (needs Modbus FC43 / ENIP ListIdentity / S7 SZL)';
const EXTRA_HINT = { alerts: 'Only with Suricata (optional engine, see Engines): rule matches on this host traffic.', serial: 'Modbus FC43 object, ENIP ListIdentity serial, S7 SZL 0x0011.', deviceType: 'ENIP ListIdentity device type or S7 SZL 0x001C module type.' };
const LEVELS = ['EXACT', 'PROBABLE', 'POSSIBLE', 'NONE'];
const LEVEL_COLOR = { EXACT: '#FF6B61', PROBABLE: '#F59E4B', POSSIBLE: '#E8C84A', NONE: '#8793A5', UNRUN: '#6B7585' };
const ROLE_COLOR = { PLC: '#2DD4BF', Drive: '#4ADE80', 'Comms adapter': '#A78BFA', Network: '#60A5FA', Workstation: '#F5C542', Other: '#94A3B8', External: '#687384', Unknown: '#6B7585' };
const PURDUE = [['3', 'Level 3', 'Site operations'], ['2', 'Level 2', 'Supervisory: HMI, EWS'], ['1', 'Level 1', 'Basic control: PLCs, adapters'],
  ['0', 'Level 0', 'Process: drives, I/O'], ['', 'Unplaced', 'Not enough identity yet']];
const LIFECYCLE = ['Acquisition', 'Deployment', 'Commissioning', 'In service', 'Maintenance', 'Decommissioned'];
// What a site field shows before anyone has set it. The edit form must compare against the same value,
// or saving an untouched form would log a change nobody made.
const SITE_DEFAULTS = { lifecycle: 'In service' };

const S = { engines: null, inv: null, rank: [], site: {}, flows: [], caps: [], changes: [], index: null, search: '', level: 'ALL', purdueFilter: null, kevOnly: false, unvalOnly: false,
  openCap: null, openAdv: null, tab: 'attrs', editing: false, staged: null,
  color: 'role', showAdv: true, layout: 'force', path: null, pathPick: false, pathStart: null,
  hideUnknown: false, hideScans: true, hideSeenOnly: false, hideDecommissioned: true, showGroups: false, groups: [], macs: [], images: [], imageSummary: {}, protoOff: new Set(),
  capAssets: {}, assetCaps: new Map(), capOff: new Set(), inventoryGroupMac: false, bulkSelected: new Set(), macExpanded: new Set(),
  findingsTab: 'advisories', advisorySearch: '', reviewSearch: '', logSearch: '', dataTab: 'captures' };

// ------------------------------------------------------------------ helpers

function build(el, props, kids) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'style') Object.assign(el.style, v);                      // CSSOM: allowed under the CSP
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
const h = (tag, props, ...kids) => build(document.createElement(tag), props, kids);
const sv = (tag, props, ...kids) => build(document.createElementNS('http://www.w3.org/2000/svg', tag), props, kids);
const $ = (id) => document.getElementById(id);
const store = { get(k) { try { return localStorage.getItem(k) || ''; } catch { return ''; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* private window */ } } };
// Which captures and host classes the graph shows survives a reload; the inventory uses the same view.
const VIEW_KEYS = ['hideUnknown', 'hideScans', 'hideSeenOnly', 'hideDecommissioned', 'showGroups'];
try {
  const v = JSON.parse(store.get('view') || '{}');
  VIEW_KEYS.forEach((k) => { if (typeof v[k] === 'boolean') S[k] = v[k]; });
  if (Array.isArray(v.capOff)) S.capOff = new Set(v.capOff.filter((x) => typeof x === 'string'));
} catch { /* no saved view */ }
const saveView = () => store.set('view', JSON.stringify({ ...Object.fromEntries(VIEW_KEYS.map((k) => [k, S[k]])), capOff: [...S.capOff] }));
S.floats = [];   // asset ids whose panel floats beside the node; any number, while one docks via the route
const val = (a, k) => (a && a[k] && a[k].value != null ? a[k].value : null);
const str = (v) => (Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v));
const fmtTime = (iso) => (iso ? String(iso).replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, 'Z') : '');
const fmtSize = (n) => (n > 1 << 30 ? (n / (1 << 30)).toFixed(1) + ' GB' : (n / (1 << 20)).toFixed(1) + ' MB');
const bar = (pct, color) => h('span', { class: 'bar' }, h('span', { style: { width: Math.max(0, Math.min(100, pct)) + '%', background: color || null } }));
const dot = (color) => h('span', { class: 'dot', style: { background: color } });
const chip = (label, on, fn) => h('button', { class: 'chip' + (on ? ' on' : ''), 'aria-pressed': String(on), onclick: () => { fn(); render(); } }, label);
const levelBadge = (l) => h('span', { class: 'badge lv-' + l }, l === 'UNRUN' ? 'NOT RUN' : l);

let toastTimer;
function toast(msg) {
  $('toast').textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $('toast').textContent = ''; }, 3500);
}

async function api(method, path, body, type, extra) {
  const headers = Object.assign({ 'X-Actor': store.get('actor') || 'unknown', 'X-Role': store.get('role') || 'collector' }, extra || {});
  if (type) headers['Content-Type'] = type;
  const res = await fetch('/api/v1/' + path, { method, headers, body });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || res.status + ' ' + res.statusText);
  return data;
}

// ------------------------------------------------------------------ data

function assets() { return (S.inv && S.inv.assets) || []; }
function byId(id) { return assets().find((a) => a.id === id); }
function siteOf(a) { return S.site[a.id] || {}; }
function levelOf(a) { return a.match ? a.match.level : 'UNRUN'; }
function nameOf(a) { return str(val(a, 'hostname')) || str(val(a, 'model')) || a.id; }
function isValidated(a) { return siteOf(a).validated === 'yes'; }

/** Capture ids that contributed this asset (server: captureAssets), and the file name a capture id belongs to. */
const capturesOf = (a) => S.assetCaps.get(a.id) || [];
const capFileName = (id) => { const c = S.caps.find((x) => x.id === id); return c ? c.file : id; };
const capAllHidden = (ids) => !!(ids && ids.length) && ids.every((id) => S.capOff.has(id));
/** A capture hidden from the graph removes only the nodes it exclusively contributed; a shared node stays. */
const assetVisible = (a) => { const ids = capturesOf(a); return !ids.length || ids.some((id) => !S.capOff.has(id)); };
/** What the graph draws, and so what the inventory lists: the selected captures and the hidden-by-default classes. */
const inView = (a) => assetVisible(a) && !(S.hideSeenOnly && isSeenOnly(a)) && !(S.hideDecommissioned && isDecommissioned(a));

function roleGroup(a) {
  const r = (str(val(a, 'role')) + ' ' + str(val(a, 'deviceType'))).toLowerCase();
  if (!r.trim()) return 'Unknown';
  if (/plc|controller|cpu|cip:0x0e/.test(r)) return 'PLC';
  if (/drive|cip:0x0?2\b|0x13|0x25/.test(r)) return 'Drive';
  if (/adapter|0x0c/.test(r)) return 'Comms adapter';
  if (/switch|gateway|router|dns server|dhcp server|ntp server|syslog server|vpn gateway/.test(r)) return 'Network';
  if (/hmi|workstation|ews|client|initiator/.test(r)) return 'Workstation';
  if (/external|internet|public/.test(r)) return 'External';
  return 'Other';
}
function purdueOf(a) {
  if (siteOf(a).purdue) return String(siteOf(a).purdue);
  return { PLC: '1', 'Comms adapter': '1', Network: '1', Drive: '0', Workstation: '2', External: '4' }[roleGroup(a)] || '';
}

// ------------------------------------------------------------------ flows (edges)

const PROTO_NAME = { modbus: 'Modbus', dnp3: 'DNP3', s7comm: 'S7', 'ethernet-ip': 'ENIP', snmp: 'SNMP', bacnet: 'BACnet', 'opc-ua': 'OPC UA', profinet: 'PROFINET', icmp: 'ICMP', unknown: 'Unknown' };
// One colour per protocol on the graph; anything unnamed (including a service name Zeek made up) is grey like unknown.
const PROTO_COLOR = { modbus: '#38BDF8', dnp3: '#F472B6', 'ethernet-ip': '#A3E635', s7comm: '#FB923C', snmp: '#C084FC', bacnet: '#2DD4BF', 'opc-ua': '#818CF8', profinet: '#F87171', icmp: '#FACC15', unknown: '#7B8696' };
const protoKey = (p) => (PROTO_COLOR[p] ? p : 'unknown');
const protoColor = (p) => PROTO_COLOR[protoKey(p)];
const protoName = (p) => PROTO_NAME[p] || p;
const flowKey = (f) => [f.client, f.server, f.protocol, f.port].join('>');
/** Key of a merged busy pair (see graphModel). Every edge has a key (flowKey or this), so no Details link or route can carry "null". */
const pairKey = (from, to) => 'pair:' + from + '>' + to;
/** A conversation that only ever saw scan attempts: it has an edge only when the analyzer ran with --keep-scans. */
const isScan = (f) => !(f.messages > 0) && f.scanAttempts > 0;
/** Messages per minute over first..last seen, or null when the span is missing or under a second (a burst has no rate). */
function flowRate(f) {
  const a = Date.parse(f.firstSeen), b = Date.parse(f.lastSeen);
  return a >= 0 && b - a >= 1000 && f.messages >= 0 ? f.messages / ((b - a) / 60000) : null;
}
const fmtStamp = (iso) => (iso ? String(iso).replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '');   // fmtTime drops the seconds; a rate needs them
const fmtRate = (r) => (r == null ? 'n/a' : (r >= 100 ? Math.round(r) : r >= 10 ? r.toFixed(1) : r.toFixed(2)) + ' /min');
const fmtSpan = (f) => {
  const ms = Date.parse(f.lastSeen) - Date.parse(f.firstSeen);
  return ms >= 0 ? (ms < 1000 ? '< 1 s' : ms < 90000 ? Math.round(ms / 1000) + ' s' : ms < 5400000 ? Math.round(ms / 60000) + ' min' : (ms / 3600000).toFixed(1) + ' h') : '';
};
const fmtBytes = (n) => (n >= 1 << 30 ? (n / (1 << 30)).toFixed(1) + ' GB' : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' kB' : n + ' B');
/** Operations of one flow as short text: "FC3 read holding registers ×1100 · FC16 … ×100", the busiest first. */
const opsSummary = (f, max) => (f.operations || []).slice().sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, max || 3)
  .map((o) => o.function + (o.address != null ? ' @' + o.address : '') + ' ×' + (o.count || 0)).join(' · ');
/** Hidden by the filter toggles (not drawn at all); the query box only dims. */
const flowHidden = (f) => (S.hideUnknown && protoKey(f.protocol) === 'unknown') || (S.hideScans && isScan(f)) || S.protoOff.has(protoKey(f.protocol)) || capAllHidden(f.captures);
/** The query's proto:, rate> and capture terms applied to one conversation. */
const flowProtoIs = (f, p) => protoKey(f.protocol) === p || String(f.protocol).toLowerCase().includes(p);
const capQueryHits = (q, ids) => {
  if (!q.pcap && !q.capture) return true;
  return (ids || []).some((id) => (!q.capture || id.toLowerCase() === q.capture || id.toLowerCase().endsWith(q.capture))
    && (!q.pcap || capFileName(id).toLowerCase().includes(q.pcap)));
};
function flowMatchesQuery(f) {
  const q = parseQuery(S.search);
  return (!q.proto || flowProtoIs(f, q.proto)) && (q.rate == null || flowRate(f) > q.rate) && capQueryHits(q, f.captures);
}
const flowsOf = (a) => {
  const ip = str(val(a, 'ip')) || a.id.split('/')[0];
  return S.flows.filter((f) => f.client === ip || f.server === ip);
};

/** Free-text words (all must match) plus filters: level:exact proto:modbus role:plc pcap:cell1 capture:c0001 rate>10 kev unvalidated. */
function parseQuery(q) {
  const t = { text: [] };
  for (const w of String(q).toLowerCase().split(/\s+/).filter(Boolean)) {
    const m = w.match(/^(level|proto|role|pcap|capture):(.+)$/), r = w.match(/^rate>(\d+(?:\.\d+)?)$/);
    if (r) t.rate = parseFloat(r[1]);
    else if (m) t[m[1]] = m[2]; else if (w === 'kev' || w === 'unvalidated') t[w] = true; else t.text.push(w);
  }
  return t;
}
const filterActive = () => !!(S.search.trim() || S.level !== 'ALL' || S.purdueFilter != null || S.kevOnly || S.unvalOnly);
/** The chips (level, KEV, not validated) and the query box together: the table hides what fails, the graph dims it. */
function matches(a) {
  const q = parseQuery(S.search), lv = levelOf(a), kev = !!(a.match && a.match.kevAtModel);
  const hay = [a.id, nameOf(a), val(a, 'vendor'), val(a, 'model'), val(a, 'mac'), val(a, 'hostname')].filter(Boolean).map((v) => str(v).toLowerCase());
  return (S.level === 'ALL' || lv === S.level) && (S.purdueFilter == null || purdueOf(a) === S.purdueFilter) && (!S.kevOnly || kev) && (!S.unvalOnly || !isValidated(a))
    && (!q.level || lv.toLowerCase() === q.level) && (!q.kev || kev) && (!q.unvalidated || !isValidated(a))
    && (!q.proto || str(val(a, 'protocols')).toLowerCase().includes(q.proto))
    && (q.rate == null || flowsOf(a).some(flowMatchesQuery))
    && (!q.role || (roleGroup(a) + ' ' + str(val(a, 'role'))).toLowerCase().includes(q.role))
    && capQueryHits(q, capturesOf(a))
    && q.text.every((w) => hay.some((v) => v.includes(w)));
}

function advisoryRows() {
  const m = new Map();
  for (const a of assets()) {
    for (const x of (a.match && a.match.advisories) || []) {
      if (!m.has(x.advisory)) m.set(x.advisory, { id: x.advisory, title: x.title, cvss: x.cvss || 0, kev: (x.kev || []).length > 0, cves: x.cves || [], affected: new Set(), hits: [] });
      const r = m.get(x.advisory);
      if (x.affected) r.affected.add(x.affected);
      r.cvss = Math.max(r.cvss, x.cvss || 0);
      r.hits.push({ a, level: x.level });
    }
  }
  return [...m.values()].sort((x, y) => (y.kev - x.kev) || (y.cvss - x.cvss));
}

function reviewGroups() {
  const all = assets();
  const conflicts = all.filter((a) => Object.values(a).some((f) => f && f.conflict));
  const low = all.filter((a) => !isValidated(a) && ['vendor', 'model', 'role'].some((k) => a[k] && a[k].confidence === 'LOW'));
  return [
    { title: 'Conflicting values', color: '#F59E4B', items: conflicts.map((a) => [a, 'Values disagree across observations: ' + Object.keys(a).filter((k) => a[k] && a[k].conflict).join(', ')]) },
    { title: 'Low-confidence identity', color: '#8793A5', items: low.map((a) => [a, 'Role, vendor or model rests on weak evidence. Confirm with the plant engineer.']) },
    { title: 'Awaiting validation', color: '#2DD4BF', items: all.filter((a) => !isValidated(a)).map((a) => [a, a.completeness.filled + ' of 14 attributes filled']) },
  ].filter((g) => g.items.length);
}
const reviewCount = () => new Set(reviewGroups().flatMap((g) => g.items.map((i) => i[0].id))).size;

async function loadAll() {
  const [inv, caps, idx] = await Promise.all([api('GET', 'inventory'), api('GET', 'captures'), api('GET', 'index')]);
  S.inv = inv.inventory; S.rank = inv.rank; S.site = inv.site; S.flows = inv.flows || []; S.caps = caps; S.index = idx;
  S.groups = inv.groups || []; S.macs = inv.macs || [];
  S.images = inv.images || []; S.imageSummary = inv.imageSummary || {};
  S.capAssets = inv.captureAssets || {};
  S.assetCaps = new Map();
  Object.entries(S.capAssets).forEach(([id, ids]) => (ids || []).forEach((a) => {
    const list = S.assetCaps.get(a) || []; list.push(id); S.assetCaps.set(a, list);
  }));
}

// ------------------------------------------------------------------ chrome

function chrome(route) {
  const mode = route === 'overview' || route === 'inventory' || route === 'ethernet' ? 'inventory' : ['advisories', 'review', 'findings'].includes(route) ? 'findings'
    : ['captures', 'index', 'engines', 'log', 'data', 'export', 'settings'].includes(route) ? 'data' : 'graph';
  document.querySelectorAll('#modes [data-mode]').forEach((n) => {
    const active = n.dataset.mode === mode;
    n.classList.toggle('on', active);
    if (active) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  $('mode-review-count').textContent = reviewCount() || '';
  $('tree-capture-count').textContent = S.caps.length || '';
  $('tree-advisory-count').textContent = advisoryRows().length || '';
  $('tree-review-count').textContent = reviewCount() || '';
  document.querySelectorAll('#tree .tree-row[href]:not([data-level])').forEach((n) => {
    const selected = n.getAttribute('href') === location.hash || (route === 'asset' || route === 'edge' || route === 'group') && n.getAttribute('href') === '#/graph';
    n.classList.toggle('selected', selected);
    if (selected) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  document.querySelectorAll('#tree .tree-row[data-level]').forEach((n) => {
    const selected = S.purdueFilter === n.dataset.level;
    n.classList.toggle('selected', selected);
    if (selected) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  $('asset-list').replaceChildren(...S.rank.map(byId).filter(Boolean).slice(0, 500).map((a) => h('option', { value: a.id }, nameOf(a))));
  filterPanel();
  legendPanel();
  graphControls();
  const ix = S.index || {};
  const badge = $('idx-badge');
  const indexAge = ix.generated ? Math.floor((Date.now() - Date.parse(ix.generated)) / 86400000) : null;
  const indexStaleDays = Math.max(1, Number(store.get('index-stale-days')) || 30);
  badge.className = 'badge ' + (!ix.verified ? 'bad' : ix.warning || indexAge != null && indexAge > indexStaleDays ? 'warn' : 'ok');
  badge.textContent = (ix.verified ? 'Index verified' : 'Index UNVERIFIED') + ' · ' + String(ix.generated || '?').slice(0, 10);
  const banner = $('banner');
  banner.replaceChildren();
  if (!ix.verified) banner.append(h('div', { class: 'banner bad' }, 'Advisory index is UNVERIFIED (no public key). An altered index can hide vulnerable devices.'));
  else if (ix.warning) banner.append(h('div', { class: 'banner warn' }, ix.warning));
}

/**
 * Nothing the analyzer retained is dropped; classes of low value are only left off the graph, and each one is listed here with how many
 * it holds, whether it is hidden now, and a button to flip it (docs/data-contract.md, "Hidden by default").
 */
const isSeenOnly = (a) => !!a.seenOnly;
const isDecommissioned = (a) => String(siteOf(a).lifecycle || '').toLowerCase() === 'decommissioned';
function hiddenClasses() {
  return [
    { label: 'Broadcast / multicast addresses', n: S.groups.length, hidden: !S.showGroups, flip: () => { S.showGroups = !S.showGroups; relayoutSoon(); } },
    { label: 'Scan-only conversations', n: S.flows.filter(isScan).length, hidden: S.hideScans, flip: () => { S.hideScans = !S.hideScans; } },
    { label: 'Seen-only hosts (low confidence)', n: assets().filter(isSeenOnly).length, hidden: S.hideSeenOnly, flip: () => { S.hideSeenOnly = !S.hideSeenOnly; } },
    { label: 'Decommissioned hosts', n: assets().filter(isDecommissioned).length, hidden: S.hideDecommissioned, flip: () => { S.hideDecommissioned = !S.hideDecommissioned; } },
    { label: 'Unknown-protocol conversations', n: S.flows.filter((f) => protoKey(f.protocol) === 'unknown' && !isScan(f)).length, hidden: S.hideUnknown, flip: () => { S.hideUnknown = !S.hideUnknown; } },
  ];
}

/** Filter button: the match-level / KEV / validation filters and how the graph is drawn. */
function filterPanel() {
  const p = $('pop-filter');
  const had = [...p.querySelectorAll('button')].indexOf(document.activeElement);   // keep keyboard focus on the same chip after the rebuild
  const on = (label, is, fn) => h('button', { class: 'chip' + (is ? ' on' : ''), 'aria-pressed': String(is), onclick: () => { fn(); render(); } }, label);
  const group = (title, ...kids) => h('div', { class: 'stack', style: { gap: '6px' } }, h('div', { class: 'small strong' }, title), h('div', { class: 'row' }, kids));
  p.replaceChildren(
    group('Advisory match', ['ALL', ...LEVELS].map((l) => on(l === 'ALL' ? 'All levels' : l, S.level === l, () => { S.level = l; }))),
    group('Show only', on('Not validated', S.unvalOnly, () => { S.unvalOnly = !S.unvalOnly; })),
    h('div', { class: 'stack', style: { gap: '6px' }, id: 'hidden-facet' }, h('div', { class: 'small strong' }, 'Hidden by default'),
      hiddenClasses().map((c) => h('div', { class: 'row small' },
        on(c.hidden ? 'Show' : 'Hide', !c.hidden, c.flip), h('span', {}, c.label + ': ' + c.n), h('span', { class: 'muted' }, c.n === 0 ? 'none' : c.hidden ? 'hidden, kept in the inventory' : 'shown')))),
    group('Colour nodes by', on('Role', S.color === 'role', () => { S.color = 'role'; }), on('Advisory risk', S.color === 'risk', () => { S.color = 'risk'; })),
    group('Advisories on the graph', on(S.showAdv ? 'Shown (EXACT, PROBABLE)' : 'Hidden', S.showAdv, () => { S.showAdv = !S.showAdv; })),
    doneCaps().length ? group('Captures on the graph', doneCaps().map((c) => on(c.file, !S.capOff.has(c.id), () => toggleCapture(c.id))))
      : group('Captures on the graph', h('span', { class: 'muted small' }, 'No merged captures yet')),
    info('Protocols, KEV only and layout are the chips above the graph. Reset filters is in the graph tools. Capture buttons hide or show everything that capture contributed.'));
  if (had >= 0) p.querySelectorAll('button')[had].focus();
}
/** Compact always-visible graph chips from the console reference; detailed facets stay in the filter popover. */
function graphControls() {
  const chips = $('graph-chips'), layout = $('graph-layout');
  const toggle = (label, on, fn, color) => h('button', { class: 'chip graph-chip' + (on ? ' on' : ''), 'aria-pressed': String(on),
    style: color ? { '--chip-color': color } : null, onclick: () => { fn(); render(); } }, label);
  chips.replaceChildren(...Object.keys(PROTO_COLOR).map((p) => toggle(protoName(p), !S.protoOff.has(p), () => {
    if (S.protoOff.has(p)) S.protoOff.delete(p); else S.protoOff.add(p);
  }, PROTO_COLOR[p])));
  layout.replaceChildren(toggle('KEV only', S.kevOnly, () => { S.kevOnly = !S.kevOnly; }),
    toggle('Force', S.layout === 'force', () => { S.layout = 'force'; relayoutSoon(); }),
    toggle('Purdue', S.layout === 'purdue', () => { S.layout = 'purdue'; relayoutSoon(); }));
}
const relayoutSoon = () => { GR.pos.clear(); GR.sig = ''; GR.fitted = false; };
const doneCaps = () => S.caps.filter((c) => c.state === 'done');
function toggleCapture(id) { if (S.capOff.has(id)) S.capOff.delete(id); else S.capOff.add(id); }
/** Show only one capture on the graph, replacing any other query. */
function focusCapture(id) {
  S.capOff.delete(id);
  S.search = 'capture:' + id;
  const q = $('q');
  if (q) q.value = S.search;
  if (location.hash !== '#/graph') location.hash = '#/graph'; else render();
}
/** Clear every view filter and selection; captures, edits and the change log stay untouched. */
function resetView() {
  S.search = ''; S.level = 'ALL'; S.purdueFilter = null; S.kevOnly = false; S.unvalOnly = false;
  S.hideUnknown = false; S.hideScans = true; S.hideSeenOnly = false; S.hideDecommissioned = true; S.showGroups = false; S.protoOff = new Set(); S.capOff = new Set();
  S.color = 'role'; S.showAdv = true; S.layout = 'force'; S.path = null; S.pathPick = false; S.pathStart = null; S.openCap = null; S.openAdv = null;
  $('q').value = ''; $('start').value = ''; $('target').value = '';
  lastRoute = '';
  if (location.hash && location.hash !== '#/graph') location.hash = '#/graph';
  else { relayoutSoon(); render(); }
}

function svgIcon(d) {
  const e = document.createElementNS('http://www.w3.org/2000/svg', 'svg'), p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  e.setAttribute('viewBox', '-11 -11 22 22'); e.setAttribute('class', 'gicon'); p.setAttribute('d', d); e.append(p);
  return e;
}

function legendPanel() {
  const sw = (c, t) => h('span', { class: 'row legend' }, h('span', { class: 'dot', style: { background: c } }), t);
  const ix = S.index || {};
  $('pop-info').replaceChildren(
    h('div', { class: 'strong' }, S.color === 'risk' ? 'Node colour: advisory match' : 'Node shape: role'),
    h('div', { class: 'stack', style: { gap: '4px' } }, S.color === 'risk' ? [...LEVELS, 'UNRUN'].map((l) => sw(LEVEL_COLOR[l], l === 'UNRUN' ? 'NOT RUN' : l)) : Object.keys(ICONS).map((g) => h('span', { class: 'row legend' }, svgIcon(ICONS[g]), g))),
    h('div', { class: 'strong' }, 'Edge colour: protocol'),
    h('div', { class: 'stack', style: { gap: '4px' } }, Object.keys(PROTO_COLOR).map((k) => sw(PROTO_COLOR[k], protoName(k) + (k === 'unknown' ? ' (carried, not decoded)' : '')))),
    h('div', { class: 'small' }, 'Dashed ring: a host only seen on the wire (low confidence). Grey broadcast node: a broadcast or multicast address, not a device.'),
    h('div', { class: 'small' }, 'Red ring: KEV-listed advisory at model. Check badge: validated. Triangle: advisory (red when KEV-listed). Dashed grey edge: unit or slot behind a gateway.'),
    h('div', { class: 'small' }, 'Arrows run client to server and are labelled with the message kind seen (Modbus FC43/14, ListIdentity, S7 SZL). Thicker means more messages. Click an edge for its operations, rate and times. Unknown edges are host pairs that were counted, not decoded.'),
    h('div', { class: 'small muted' }, 'Keyboard: Tab to a node, Enter opens it. On the graph: arrows pan, + and - zoom, 0 fits.'),
    h('div', { class: 'small' }, 'Advisory index: ' + (ix.verified ? 'signature verified' : 'UNVERIFIED') + ', generated ' + fmtTime(ix.generated) + ', KEV ' + (ix.kevCatalogVersion || '?') + '.'));
}

// ------------------------------------------------------------------ screens

/** The (i) marker: the explanation lives in a tooltip (read by #tip) instead of a paragraph on the page. */
const info = (text) => h('span', { class: 'inf', tabindex: '0', 'aria-label': 'What is this' }, 'i', h('span', { class: 'tip' }, text));

/** Overview, the asset table and Ethernet are one Inventory section; the top bar's Inventory tab opens it. */
const inventoryTabs = (current) => h('nav', { class: 'screen-tabs', 'aria-label': 'Inventory sections' },
  [['overview', 'Overview'], ['inventory', 'Assets'], ['ethernet', 'Ethernet']].map(([key, label]) =>
    h('a', { href: '#/' + key, class: current === key ? 'selected' : '', 'aria-current': current === key ? 'page' : null }, label)));

function overview() {
  const all = assets(), sum = S.inv.summary || {}, n = all.length || 1;
  const kev = all.filter((a) => a.match && a.match.kevAtModel).length;
  const lv = Object.fromEntries(LEVELS.map((l) => [l, all.filter((a) => levelOf(a) === l).length]));
  const done = S.caps.filter((c) => c.state === 'done');
  const last = done[done.length - 1];
  const groups = Object.keys(ROLE_COLOR).map((g) => ({ g, n: all.filter((a) => roleGroup(a) === g).length })).filter((x) => x.n);
  const ranked = S.rank.map(byId).filter(Boolean);
  return [
    inventoryTabs('overview'),
    h('div', { class: 'head' },
      h('div', {}, h('h1', {}, 'Site overview'), h('div', { class: 'muted' }, done.length + ' captures merged' + (last ? ' · last ' + fmtTime(last.at) : ''))),
      h('div', { class: 'row' }, h('a', { class: 'btn', href: '/api/v1/export/report.html', download: 'report.html' }, 'Export report'), h('a', { class: 'btn pri', href: '#/captures' }, 'Queue PCAPs'))),
    all.length === 0 ? h('div', { class: 'card empty' }, 'No assets yet. Queue a capture to start the inventory.') : [
      h('div', { class: 'card strip' },
        h('div', { class: 'stat' }, h('span', { class: 'stat-label' }, 'Assets'),
          h('span', { class: 'row' }, h('span', { class: 'kpi' }, all.length), last && last.diff ? h('span', { class: 'badge ok' }, '+' + last.diff.new + ' last capture') : null),
          h('span', { class: 'muted small' }, all.filter((a) => !a.subaddr).length + ' addresses · ' + all.filter((a) => a.subaddr).length + ' units / slots')),
        h('div', { class: 'stat' }, h('span', { class: 'stat-label' }, 'CISA attributes filled (avg)'),
          h('span', { class: 'row' }, h('span', { class: 'kpi' }, sum.meanFilled), h('span', { class: 'muted' }, '/ 14 · passive max 9')), bar(sum.meanFilled / 14 * 100)),
        h('div', { class: 'stat' }, h('span', { class: 'stat-label' }, 'KEV at model'),
          h('span', { class: 'kpi', style: { color: kev ? LEVEL_COLOR.EXACT : null } }, kev), h('span', { class: 'muted small' }, lv.EXACT + ' EXACT · ' + lv.PROBABLE + ' PROBABLE matches')),
        h('div', { class: 'stat' }, h('span', { class: 'stat-label' }, 'Needs review'),
          h('span', { class: 'head' }, h('span', { class: 'kpi' }, reviewCount()), h('a', { class: 'btn sm', href: '#/review' }, 'Review')),
          h('span', { class: 'muted small' }, all.filter((a) => !isValidated(a)).length + ' not validated'))),
      h('div', { class: 'split' },
        h('div', { class: 'card wide' },
          h('div', { class: 'card-h' }, 'Purdue model view', h('span', { class: 'muted small' }, 'suggested from role; set per asset')),
          PURDUE.map(([lvl, label, sub]) => {
            const items = all.filter((a) => purdueOf(a) === lvl);
            return h('div', { class: 'lane' }, h('span', {}, h('span', { class: 'cell-name' }, label), h('span', { class: 'muted small' }, sub)),
              h('span', { class: 'row' }, items.length ? items.map((a) => h('a', { class: 'lane-chip', href: '#/asset/' + encodeURIComponent(a.id) },
                dot(LEVEL_COLOR[levelOf(a)]), nameOf(a), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV') : null))
                : h('span', { class: 'muted small' }, 'Nothing observed at this level')));
          }),
          h('div', { class: 'card-b muted small row' }, ['EXACT', 'PROBABLE', 'NONE'].map((l) => h('span', { class: 'row' }, dot(LEVEL_COLOR[l]), l)))),
        h('div', { class: 'stack narrow' },
          h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Advisory match level'),
            h('div', { class: 'card-b stack' }, LEVELS.map((l) => h('a', { href: '#/graph', class: 'stack', title: 'Show only ' + l + ' on the graph', style: { gap: '6px', textDecoration: 'none', color: 'inherit' }, onclick: () => { S.level = l; } },
              h('span', { class: 'head' }, levelBadge(l), h('span', { class: 'muted small' }, lv[l] + ' assets')), bar(lv[l] / n * 100, LEVEL_COLOR[l]))),
              h('div', { class: 'muted small' }, 'NONE means no advisory in this index, not a clean device.'))),
          h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Assets by role'),
            h('div', { class: 'card-b stack' },
              h('div', { class: 'stacked' }, groups.map((x) => h('span', { style: { width: (x.n / n * 100) + '%', background: ROLE_COLOR[x.g] } }))),
              h('div', { class: 'row' }, groups.map((x) => h('span', { class: 'row' }, dot(ROLE_COLOR[x.g]), x.g, h('span', { class: 'muted small' }, x.n)))))))),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Fix-first ranking', h('a', { class: 'btn sm', href: '#/graph' }, 'Open the graph')),
          ranked.slice(0, 5).map((a, i) => h('a', { class: 'rv', href: '#/asset/' + encodeURIComponent(a.id) },
            h('span', { class: 'mono muted' }, i + 1), h('span', { style: { flex: '1', minWidth: '0' } }, h('span', { class: 'cell-name' }, nameOf(a)), h('span', { class: 'mono muted small' }, a.id)),
            a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV') : null, levelBadge(levelOf(a)),
            h('span', { class: 'mono small' }, a.match && a.match.maxCvss ? a.match.maxCvss.toFixed(1) : '—')))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'CISA attribute fill rate', h('span', { class: 'muted small' }, '14 high-priority attributes')),
          h('div', { class: 'card-b fill' }, ATTRS.map(([k, label, by]) => {
            const pct = Math.round(parseFloat((sum.fillRate || {})[k] || 0) * 100);
            return h('div', { class: 'stack', style: { gap: '4px' } }, h('span', { class: 'head' }, label, h('span', { class: 'badge ' + (by === 'human' ? 'c-PERSON' : 'c-LOW') }, pct + '%')),
              bar(pct, by === 'human' ? '#A78BFA' : null));
          })))),
    ],
  ];
}

const BULK_FIELDS = [['zone', 'Zone'], ['purdue', 'Purdue level'], ['owner', 'Owner'], ['lifecycle', 'Lifecycle'],
  ['criticality', 'Criticality'], ['asset_number', 'Asset number'], ['location', 'Physical location'], ['logging', 'Logging'], ['user_accounts', 'User accounts']];
function inventoryAssetRow(a, grouped) {
  const mac = str(val(a, 'mac'));
  const vendor = val(a, 'vendor') || val(a, 'vendor_oui');
  const locallyAdministered = mac && ((parseInt(mac.slice(0, 2), 16) || 0) & 2) !== 0;
  return h('tr', { class: grouped ? 'inventory-child' : '' },
    h('td', {}, h('input', { type: 'checkbox', checked: S.bulkSelected.has(a.id), 'aria-label': 'Select ' + a.id,
      onchange: (e) => { e.target.checked ? S.bulkSelected.add(a.id) : S.bulkSelected.delete(a.id); render(); } })),
    h('td', {}, h('a', { class: 'inventory-asset', href: '#/asset/' + encodeURIComponent(a.id) }, nameOf(a)), h('span', { class: 'mono muted small' }, a.id)),
    h('td', { class: 'mono small' }, mac || '—', locallyAdministered ? h('span', { class: 'badge warn', title: 'Locally administered bit is set; this address may be assigned locally' }, 'local MAC') : null),
    h('td', {}, vendor ? str(vendor.value) : '—'), h('td', {}, val(a, 'role') || '—'), h('td', {}, purdueOf(a) ? 'Level ' + purdueOf(a) : 'Unplaced'),
    h('td', {}, levelBadge(levelOf(a)), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV') : null),
    h('td', {}, a.completeness ? a.completeness.filled + ' / 14' : '—'),
    h('td', { class: 'muted small' }, capturesOf(a).map(capFileName).join(', ') || 'No capture provenance'));
}

function inventory() {
  const rows = S.rank.map(byId).filter((a) => a && inView(a) && matches(a));
  const selectedVisible = rows.filter((a) => S.bulkSelected.has(a.id)).length;
  const checkAll = h('input', { type: 'checkbox', checked: rows.length > 0 && selectedVisible === rows.length, 'aria-label': 'Select all filtered assets',
    onchange: (e) => { rows.forEach((a) => e.target.checked ? S.bulkSelected.add(a.id) : S.bulkSelected.delete(a.id)); render(); } });
  const valueOptions = S.bulkField === 'purdue' ? [['', 'Clear / use role suggestion'], ['3.5', 'Level 3.5'], ['3', 'Level 3'], ['2', 'Level 2'], ['1', 'Level 1'], ['0', 'Level 0']]
    : S.bulkField === 'lifecycle' ? LIFECYCLE.map((v) => [v, v])
      : S.bulkField === 'criticality' ? [['', 'Clear'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']] : null;
  const valueInput = valueOptions ? h('select', { 'aria-label': 'Bulk edit value', value: S.bulkValue, onchange: (e) => { S.bulkValue = e.target.value; } },
    valueOptions.map(([value, label]) => h('option', { value, selected: value === S.bulkValue }, label)))
    : h('input', { 'aria-label': 'Bulk edit value', placeholder: 'Value (blank clears this field)', value: S.bulkValue, oninput: (e) => { S.bulkValue = e.target.value; } });

  let bodyRows;
  if (!S.inventoryGroupMac) bodyRows = rows.map((a) => inventoryAssetRow(a, false));
  else {
    const groups = new Map();
    rows.forEach((a) => {
      const mac = str(val(a, 'mac')) || '(no MAC) ' + a.id;
      (groups.get(mac) || groups.set(mac, []).get(mac)).push(a);
    });
    bodyRows = [...groups.entries()].map(([mac, members]) => {
      const info = S.macs.find((m) => m.mac === mac), open = S.macExpanded.has(mac);
      const locallyAdministered = mac.startsWith('(') ? false : (((parseInt(mac.slice(0, 2), 16) || 0) & 2) !== 0);
      const inferred = (info && (info.notes || []).join('; ')) || (members.length > 1 ? 'Multiple assets share this MAC; router or NAT is possible (inferred).' : '');
      return [h('tr', { class: 'mac-group' },
        h('td', { colspan: 9 }, h('button', { class: 'mac-expander', 'aria-expanded': String(open), 'aria-label': (open ? 'Collapse' : 'Expand') + ' MAC group ' + mac,
          onclick: () => { open ? S.macExpanded.delete(mac) : S.macExpanded.add(mac); render(); } }, open ? '▾' : '▸'),
        h('span', { class: 'mono strong' }, mac), h('span', { class: 'muted small' }, members.length + (members.length === 1 ? ' asset' : ' assets')),
        locallyAdministered ? h('span', { class: 'badge warn' }, 'locally administered MAC') : null,
        inferred ? h('span', { class: 'badge warn', title: inferred }, 'router or NAT inference') : null)),
      open ? members.map((a) => inventoryAssetRow(a, true)) : null];
    });
  }
  return [
    inventoryTabs('inventory'),
    h('div', { class: 'head inventory-heading' }, h('div', {}, h('h1', {}, 'Inventory'), h('div', { class: 'muted' }, rows.length + ' of ' + assets().length + ' assets · fix-first order' + (assets().filter((a) => !inView(a)).length ? ' · the rest are hidden in the graph view (Filter, or Hide/Show on Captures)' : ''))),
      h('label', { class: 'row inventory-group-toggle' }, h('input', { type: 'checkbox', checked: S.inventoryGroupMac, onchange: (e) => { S.inventoryGroupMac = e.target.checked; render(); } }), 'Group by MAC')),
    h('form', { class: 'card bulk-edit', onsubmit: (e) => { e.preventDefault(); applyBulkEdit(rows); } },
      h('div', { class: 'card-h' }, h('span', {}, 'Bulk edit ', info('Each selected asset is saved through the existing asset endpoint and logged under your session name. Validation is not part of bulk edit.')), h('span', { class: 'muted small' }, selectedVisible + ' of ' + rows.length + ' shown selected' + (S.bulkSelected.size !== selectedVisible ? ' · ' + S.bulkSelected.size + ' selected overall' : ''))),
      h('div', { class: 'bulk-edit-row' }, h('label', {}, 'Field', h('select', { value: S.bulkField, onchange: (e) => { S.bulkField = e.target.value; S.bulkValue = ''; render(); } }, BULK_FIELDS.map(([v, label]) => h('option', { value: v, selected: S.bulkField === v }, label)))),
        h('label', {}, 'Value', valueInput), h('button', { class: 'btn pri', type: 'submit', disabled: selectedVisible === 0 }, 'Apply to selected'),
        h('button', { class: 'btn', type: 'button', onclick: () => { S.bulkSelected.clear(); render(); } }, 'Clear selection')),
      null),
    h('div', { class: 'card inventory-table-wrap' },
      rows.length ? h('table', { class: 'inventory-table' },
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, checkAll), ...['Asset', 'MAC', 'Vendor', 'Role', 'Purdue', 'Match', 'Completeness', 'Seen in'].map((label) => h('th', { scope: 'col' }, label)))),
        h('tbody', {}, bodyRows))
        : h('div', { class: 'empty' }, filterActive() ? 'No assets match the current search or filters.' : 'No assets yet. Queue a capture to start the inventory.',
          h('div', { class: 'row', style: { justifyContent: 'center', marginTop: '10px' } }, h('a', { class: 'btn pri', href: '#/captures' }, 'Queue PCAPs')))),
  ];
}

async function applyBulkEdit(visibleRows) {
  const targets = visibleRows.filter((a) => S.bulkSelected.has(a.id));
  if (!targets.length) return toast('Select at least one visible asset');
  let saved = 0, failed = null;
  for (const a of targets) {
    try {
      const result = await api('PATCH', 'assets/' + encodeURIComponent(a.id), JSON.stringify({ [S.bulkField]: S.bulkValue }), 'application/json');
      saved += result.changes.length > 0 ? 1 : 0;
    } catch (e) { failed = failed || (a.id + ': ' + e.message); }
  }
  S.bulkSelected.clear();
  toast(failed ? saved + ' assets updated; ' + failed : saved + ' assets updated and logged');
  await refresh();
}

function captures() {
  const pick = h('input', { type: 'file', multiple: true, accept: '.pcap,.pcapng,.cap', class: 'sr', id: 'pick', onchange: (e) => upload([...e.target.files]) });
  const drop = h('div', { class: 'drop', ondragover: (e) => { e.preventDefault(); drop.classList.add('over'); }, ondragleave: () => drop.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); drop.classList.remove('over'); upload([...e.dataTransfer.files]); } },
    h('div', {}, h('div', { class: 'strong' }, 'Drop capture files here'),
      h('div', { class: 'muted small' }, 'Classic PCAP or pcapng ', info('Each file is hashed while it streams to disk; the same file twice is refused.'))),
    pick, h('label', { for: 'pick', class: 'btn pri', tabindex: '0' }, 'Add PCAPs'));
  const c = S.caps.find((x) => x.id === S.openCap);
  const stateTxt = { done: 'Merged', running: 'Analyzing', queued: 'Queued', failed: 'Failed' };
  return [
    h('div', {}, h('h1', {}, 'Capture queue', info('Captures run one at a time, in order, and merge into the site inventory. Nothing is sent to the plant.'))),
    drop,
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-cap' }, h('span', {}, 'File'), h('span', {}, 'Status'), h('span', {}, 'Queued by'), h('span', {}, 'Result'), h('span', {}, 'SHA-256'), h('span', {})),
      S.caps.length === 0 ? h('div', { class: 'empty' }, 'Nothing queued yet.') : S.caps.slice().reverse().map((x) =>
        h('div', { class: 'trow g-cap' + (x.id === S.openCap ? ' sel' : '') },
          h('span', {}, h('span', { class: 'cell-name wrap' }, x.file), h('span', { class: 'muted small' }, fmtSize(x.size) + ' · ' + fmtTime(x.at)
            + (x.state === 'done' ? ' · ' + (S.capAssets[x.id] || []).length + ((S.capAssets[x.id] || []).length === 1 ? ' device' : ' devices') : ''))),
          h('span', { class: 'row' }, h('span', { class: 'badge st-' + x.state }, stateTxt[x.state]), S.capOff.has(x.id) ? h('span', { class: 'badge lv-NONE' }, 'Hidden') : null),
          h('span', {}, x.by),
          h('span', { class: 'small' }, x.state === 'done' && x.diff ? '+' + x.diff.new + ' new · ' + x.diff.changed + ' changed · ' + x.diff.notSeen + ' not seen'
            : x.state === 'failed' ? 'Exit ' + x.exit : x.state === 'running' ? 'Reading frames…' : 'Waiting for the worker'),
          h('span', { class: 'mono small muted', title: x.sha256 }, x.sha256.slice(0, 8) + '…' + x.sha256.slice(-4)),
          h('span', { class: 'row' },
            x.state === 'queued' || x.state === 'failed' ? h('button', { class: 'btn sm', onclick: () => removeCapture(x) }, 'Remove') : null,
            x.state === 'done' ? h('button', { class: 'btn sm', title: 'Delete this capture and the assets only it contributed', onclick: () => removeCapture(x) }, 'Remove assets') : null,
            x.state === 'done' ? h('button', { class: 'btn sm', onclick: () => { toggleCapture(x.id); render(); } }, S.capOff.has(x.id) ? 'Show' : 'Hide') : null,
            x.state === 'done' || x.state === 'failed' ? h('button', { class: 'btn sm', onclick: () => { S.openCap = x.id; render(); } }, 'Details') : null))))),
    c ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, c.file, h('span', { class: 'badge st-' + c.state }, stateTxt[c.state])),
      c.state === 'done' && c.summary ? h('div', { class: 'card-b facts' },
        c.kind === 'posted' ? fact('Source', 'Assets posted to the ingest API (no capture to re-read)', true) : [
          fact('Frames processed', c.summary.frames.toLocaleString()), fact('Malformed / skipped', c.summary.malformed.toLocaleString()),
          fact('Protocol candidates', Object.entries(c.summary.protocols || {}).map(([k, v]) => k + ' ' + v).join(', ') || 'none', true),
          fact('Identity fields decoded', c.summary.identityFields)], fact('Devices in capture', c.summary.devices),
        h('div', {}, h('div', { class: 'muted small' }, 'Change to inventory'), h('div', { class: 'row' },
          h('span', { class: 'badge ok' }, '+' + c.diff.new + ' new'), h('span', { class: 'badge warn' }, c.diff.changed + ' changed'), h('span', { class: 'badge lv-NONE' }, c.diff.notSeen + ' not seen'))))
        : c.state === 'failed' ? h('div', { class: 'card-b stack' }, h('div', {}, h('strong', {}, 'Exit ' + c.exit + '. '), c.error),
          h('div', { class: 'muted small' }, 'Classic PCAP and pcapng are read. For anything else, convert on this machine and queue it again, e.g.'),
          h('div', { class: 'mono code' }, 'editcap -F pcap input.cap output.pcap')) : null,
      c.state === 'done' && c.summary && (c.summary.tools || []).length ? h('div', { class: 'card-b stack', style: { gap: '4px' } },
        h('div', { class: 'muted small' }, 'Engines for this capture'), h('div', { class: 'row' }, c.summary.tools.map((t) => toolBadge(t))),
        h('a', { class: 'small', href: '#/engines' }, 'What each engine is and its licence')) : null,
      c.state === 'done' ? h('div', { class: 'card-b stack' },
        h('div', { class: 'head' }, h('div', { class: 'muted small' }, c.kind === 'posted' ? 'Assets posted in this batch' : 'Devices contributed by this capture'),
          h('button', { class: 'btn sm', onclick: () => focusCapture(c.id) }, 'Show only on graph')),
        (S.capAssets[c.id] || []).length ? (S.capAssets[c.id] || []).map((id) => {
          const a = byId(id);
          return a ? h('a', { class: 'rv', href: '#/asset/' + encodeURIComponent(a.id) },
            h('span', { class: 'cell-name' }, nameOf(a)), h('span', { class: 'mono muted small' }, a.id))
            : h('div', { class: 'mono small muted' }, id);
        }) : h('div', { class: 'empty' }, 'No assets recorded for this capture.')) : null) : null,
  ];
}
const TOOL_STATE = { ran: ['ok', 'ran'], found: ['ok', 'installed'], reference: ['lv-NONE', 'reference'], skipped: ['lv-NONE', 'skipped'], failed: ['bad', 'failed'], 'not-installed': ['lv-NONE', 'not installed'] };
/** One engine's state for one capture or for this machine: name, state, version. The detail (why it did not run) is the tooltip. */
function toolBadge(t) {
  const [cls, txt] = TOOL_STATE[t.state] || ['lv-NONE', t.state];
  return h('span', { class: 'badge ' + cls, title: [t.via, t.detail].filter(Boolean).join(': ') }, [t.name || t.id, t.version, txt].filter(Boolean).join(' · '));
}

/** "Powered by": every open-source component, whether it is installed here, how many captures used it, and its licence. */
function engines() {
  const rows = S.engines || [];
  const done = S.caps.filter((c) => c.state === 'done').length;
  const seen = (id, ok) => S.caps.filter((c) => c.state === 'done' && c.summary && (c.summary.tools || []).some((t) => t.id === id && ok(t))).length;
  const ran = (id) => seen(id, (t) => t.state === 'ran');
  // "named in evidence": a field's evidence text, or a conversation's alerts / classification, credits this tool.
  const EV = { zeek: /zeek/i, icsnpp: /icsnpp/i, tshark: /tshark|wireshark/i, suricata: /suricata/i, ndpi: /ndpi/i, p0f: /p0f/i };
  const inEvidence = (id) => S.flows.some((f) => [].concat(f.alerts || [], f.classifiedBy || []).some((x) => x.tool === id))
    || assets().some((a) => Object.values(a).some((v) => v && typeof v.evidence === 'string' && EV[id] && EV[id].test(v.evidence)));
  const step = (on, text) => h('span', { class: 'badge ' + (on ? 'ok' : 'lv-NONE') }, (on ? '✓ ' : '○ ') + text);
  const steps = (r, st) => {
    const found = st.state === 'found' || st.state === 'ran', hint = [st.via, st.detail].filter(Boolean).join(' · ');
    const first = step(found, found ? [st.version, 'installed'].filter(Boolean).join(' · ') : (TOOL_STATE[st.state] || [, st.state])[1]);
    const later = r.kind === 'engine' || r.kind === 'package' ? [step(ran(r.id) > 0, 'ran'), step(inEvidence(r.id), 'named in evidence')] : [];
    return h('span', { class: 'row steps' }, first, ...later, hint ? h('span', { class: 'inf', tabindex: '0', 'aria-label': 'how it was found' }, 'i', h('span', { class: 'tip' }, hint)) : null);
  };
  const kindTxt = { engine: 'engine', package: 'Zeek package', data: 'data file', reference: 'reference only' };
  const section = (title, note, list) => list.length ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, title, h('span', { class: 'muted small' }, note)),
    h('div', { class: 'scroll' }, h('div', { class: 'trow thead g-eng' }, ['Component', 'Status here', 'Used in', 'Licence', 'What it does for ReConnICS'].map((t) => h('span', {}, t))),
      list.map((r) => { const st = r.status || {}; return h('div', { class: 'trow g-eng' },
        h('span', {}, h('a', { class: 'cell-name', href: r.url, target: '_blank', rel: 'noopener noreferrer' }, r.name), h('span', { class: 'muted small' }, (kindTxt[r.kind] || r.kind) + (r.kind === 'reference' ? '' : r.optional ? ', optional' : ', bundled in the jar'))),
        steps(r, st),
        h('span', { class: 'small' }, r.kind === 'reference' ? '-' : done ? ran(r.id) + ' of ' + done + ' captures' : 'no captures yet'),
        h('span', { class: 'small wrap' }, r.licence), h('span', { class: 'small wrap' }, r.role)); }))) : null;
  return [
    h('div', {}, h('h1', {}, 'Engines', info('ReConnICS-ng wraps existing open-source tools instead of rewriting them. Zeek with the ICSNPP packages is the primary engine; every other tool is optional and used only when it is installed (on PATH, or in the reconics-tools Docker image). Everything is passive: capture files are only read.'))),
    S.engines === null ? h('div', { class: 'card empty' }, 'Looking for installed tools…') : null,
    section('Engines and Zeek packages', 'status of this machine', rows.filter((r) => r.kind === 'engine' || r.kind === 'package')),
    section('Data files', 'read-only reference tables', rows.filter((r) => r.kind === 'data')),
    section('Lineage and credits', 'not run, not bundled', rows.filter((r) => r.kind === 'reference')),
    h('div', { class: 'small muted' }, 'Suricata, nDPI and p0f are evidence, never a decode ', info('Their results are shown with the tool named and a confidence. They never count as a decoded protocol. Details and what was not adopted: docs/foss-components.md.')),
  ].filter(Boolean);
}

const fact = (label, value, mono) => h('div', {}, h('div', { class: 'muted small' }, label), h('div', { class: mono ? 'mono' : 'fact-v' }, value));

async function upload(files) {
  for (const f of files) {
    try {
      toast('Uploading ' + f.name + '…');
      const c = await api('POST', 'captures?name=' + encodeURIComponent(f.name), f, 'application/octet-stream');
      toast(c.file + ' queued');
    } catch (e) { toast(f.name + ': ' + e.message); }
  }
  await refresh();
}
/** Queued and failed captures just leave the queue; a merged one also takes out the assets only it saw (after a confirm that says so). */
async function removeCapture(c) {
  const n = (S.capAssets[c.id] || []).length;
  if (c.state === 'done' && !window.confirm('Remove ' + c.file + ' and its ' + n + (n === 1 ? ' device' : ' devices') + ' from the inventory?\n\n'
    + 'Devices also seen in another capture stay. Devices with human edits stay with just those edits. Everything else only this capture saw is dropped, '
    + 'the stored PCAP and its analysis are deleted from this site, and it cannot be undone. The removal is written to the change log.')) return;
  try {
    const r = await api('DELETE', 'captures/' + encodeURIComponent(c.id));
    toast(r ? 'Removed ' + c.file + ': ' + r.assetsDropped + ' dropped, ' + r.assetsKeptSeenElsewhere + ' kept (seen in other captures), ' + r.assetsKeptWithEdits + ' kept (human edits)' : 'Removed ' + c.file);
  } catch (e) { toast(e.message); }
  await refresh();
}

function asset(id) {
  const a = byId(id);
  if (!a) return [h('a', { class: 'btn sm', href: '#/graph' }, '‹ Graph'), h('div', { class: 'card empty' }, 'No asset ' + id + ' in the current inventory.')];
  const site = siteOf(a), c = a.completeness, role = store.get('role') || 'collector';
  const tab = (k, label) => h('button', { class: 'tab' + (S.tab === k ? ' on' : ''), onclick: () => { S.tab = k; S.editing = false; render(); } }, label);
  const advs = (a.match && a.match.advisories) || [];
  const hist = S.changes.filter((x) => x.asset === a.id);
  const convs = convsOf(a);
  return [
    h('div', { class: 'card' },
      h('div', { class: 'card-b head', style: { alignItems: 'flex-start' } },
        h('div', { class: 'stack', style: { gap: '6px' } },
          h('div', { class: 'row' }, h('h1', {}, nameOf(a)), levelBadge(levelOf(a)), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV at model') : null,
            h('span', { class: 'badge ' + (isValidated(a) ? 'ok' : 'lv-NONE') }, isValidated(a) ? 'Validated' : 'Pending validation'),
            a.seenOnly ? h('span', { class: 'badge warn', title: 'Only seen on the wire: no decoder, Zeek host or tool has evidence beyond that' }, 'seen only') : null,
            (a.behaviour || []).filter((b) => b !== 'addressed-only').map((b) => h('span', { class: 'badge warn' }, b))),
          h('div', { class: 'mono muted' }, a.id + ' · ' + (str(val(a, 'mac')) || 'no MAC (sub-unit or routed)')),
          a.subaddr ? h('div', { class: 'small muted' }, 'Sub-unit ' + a.subaddr + '. Inherits IP, protocols and ports from its parent.') : null,
          h('div', { class: 'small row' }, h('span', { class: 'muted' }, 'Seen in:'), capturesOf(a).length
            ? capturesOf(a).map((cid) => h('button', { class: 'btn sm', title: 'Show only this capture on the graph', onclick: () => focusCapture(cid) }, capFileName(cid)))
            : h('span', { class: 'muted' }, 'no capture provenance')),
          a.match && a.match.matchedAs ? h('div', { class: 'small muted' }, 'Matched as ' + a.match.matchedAs + ' (from the Siemens order number).') : null),
        h('div', { class: 'row', style: { gap: '20px' } },
          fact('Completeness', c.filled + ' / 14'), h('div', {}, h('div', { class: 'muted small' }, 'Match ceiling'), levelBadge(c.matchCeiling)),
          fact('Lifecycle', site.lifecycle || 'In service'))),
      h('div', { class: 'tabs' }, tab('attrs', 'Attributes'), tab('advs', 'Advisories (' + advs.length + ')'), tab('conv', 'Talks to (' + peersOf(convs, a.id) + ')'), tab('hist', 'History (' + hist.length + ')'))),
    S.tab === 'attrs' ? [attrsCard(a, site, role), observedCard(a)] : S.tab === 'conv' ? convCard(convs, a.id) : S.tab === 'advs' ? h('div', { class: 'card' },
      advs.length ? advs.map((x) => h('div', { class: 'card-b stack', style: { gap: '8px', borderBottom: '1px solid var(--line2)' } },
        h('div', { class: 'row' }, h('span', { class: 'mono strong' }, x.advisory), levelBadge(x.level), (x.kev || []).length ? h('span', { class: 'badge kev' }, 'KEV') : null,
          h('span', { class: 'badge lv-NONE' }, 'CVSS ' + (x.cvss || 0).toFixed(1))),
        h('div', { class: 'strong' }, x.title),
        h('div', { class: 'small muted' }, 'Affected: ' + (x.affected || '?') + ' · ' + (x.cves || []).join(', ')),
        h('div', { class: 'small' }, x.level === 'EXACT' ? 'Vendor, model and firmware fall inside the affected range.'
          : x.level === 'PROBABLE' ? 'Vendor and model match; the firmware could not be checked against the version range.' : 'Vendor only; every advisory for this vendor is listed.')))
        : h('div', { class: 'card-b' }, h('strong', {}, a.match ? 'No matching advisory in index (generated ' + fmtTime(S.index.generated) + '). ' : 'Matcher not run. '),
          h('span', { class: 'muted' }, 'This is not a clean bill of health: with match ceiling ' + c.matchCeiling + ' the matcher could not check this device against version ranges.')))
      : h('div', { class: 'card' }, hist.length ? hist.map((x) => h('div', { class: 'card-b row', style: { borderBottom: '1px solid var(--line2)' } },
        h('span', { class: 'mono small muted' }, fmtTime(x.at)), h('span', { class: 'strong' }, x.actor), h('span', {}, x.field + ': ', h('span', { class: 'muted' }, x.from || '∅'), ' → ', x.to || '∅'), h('span', { class: 'small muted' }, x.source === 'human' ? '' : x.source)))
        : h('div', { class: 'empty' }, 'No changes yet. Human edits and the field changes a capture merge made to this asset appear here.')),
  ];
}

const OBSERVED_TEXT = { 'icmp-echo-request': 'sent ICMP echo requests', 'icmp-echo-reply': 'answered ICMP echo', 'icmp-echo-target': 'was pinged', 'dhcp-client': 'sent DHCP',
  'group-sender': 'sent to a broadcast / multicast address', 'arp-sender': 'sent ARP', 'arp-asked': 'was asked for in ARP', 'arp-probe': 'sent an ARP probe', 'source-0.0.0.0': 'sent from 0.0.0.0',
  'arp-sender-virtual-router-mac': 'sent ARP from a virtual-router MAC' };
const BEHAVIOUR_TEXT = { 'probe-like': 'SYNs nobody answered or a port refused: it behaves like a probe', 'incomplete-handshake': 'the server answered SYN-ACK and this client never completed the handshake (half-open; not the same as a refused or unanswered probe)',
  'addressed-only': 'only ever the destination: it never sent a frame in these captures' };
/** What the analyzer saw on the wire without being able to decode it: tags, DHCP details, the web server's identity, traffic to group addresses. */
function observedCard(a) {
  const obs = a.observed || {}, tags = Object.entries(obs), syn = tags.filter(([k]) => k.startsWith('syn-target:')), d = a.dhcp, w = a.http, ip = str(val(a, 'ip')) || a.id.split('/')[0];
  const groups = S.flows.filter((f) => f.client === ip && S.groups.some((g) => g.address === f.server));
  const imgs = S.images.filter((i) => i.host === ip), notImages = ((S.imageSummary.nonImageByHost || {})[ip]) || 0;
  if (!tags.length && !d && !w && !groups.length && !(a.behaviour || []).length && !imgs.length && !notImages) return null;
  const line = (label, text) => h('div', {}, h('span', { class: 'muted small' }, label + ' '), h('span', { class: 'wrap' }, text));
  return h('div', { class: 'card', id: 'observed' }, h('div', { class: 'card-h' }, 'Observed on the wire', info('Traffic seen on the wire that is not a decoded industrial message: ARP, ICMP, DHCP, scan attempts and conversations the decoders could not read. It is evidence of what the host did, not proof of what it is.')),
    h('div', { class: 'card-b stack', style: { gap: '6px' } },
      (a.behaviour || []).map((b) => line(b + ':', BEHAVIOUR_TEXT[b] || b)),
      tags.length ? h('div', { class: 'small row' }, tags.filter(([k]) => !k.startsWith('syn-target:')).map(([k, n]) => h('span', { class: 'badge lv-NONE' }, (OBSERVED_TEXT[k] || k.replace(/^icmp:/, 'ICMP ')) + ' ×' + n))) : null,
      syn.length ? h('details', { class: 'small' }, h('summary', {}, 'SYNs to ' + syn.length + ' port' + (syn.length > 1 ? 's' : '') + ' (' + syn.reduce((t, [, n]) => t + n, 0) + ' in all)'),
        h('div', { class: 'row' }, syn.map(([k, n]) => h('span', { class: 'badge lv-NONE' }, k.slice(11) + ' ×' + n)))) : null,
      groups.map((f) => line('To ' + f.server + ' ' + f.port + ':', (f.messages || f.packets || 0) + ' messages, ' + (f.protocol === 'unknown' ? (f.portHint ? protoName(f.portHint) + '?' : 'not decoded') : f.protocol))),
      d ? h('div', { class: 'stack small', style: { gap: '2px' } }, h('strong', {}, 'DHCP'), d.hostName ? line('Host name', d.hostName) : null, d.clientFqdn ? line('FQDN', d.clientFqdn) : null,
        d.vendorClass ? line('Vendor class', d.vendorClass) : null, d.requestedAddr ? line('Requested address', d.requestedAddr) : null, d.mac ? line('Client MAC', d.mac) : null,
        (d.messageTypes || []).length ? line('Messages', d.messageTypes.join(', ') + (d.messages ? ' (' + d.messages + ')' : '')) : null,
        !d.hostName && !d.vendorClass && !d.requestedAddr ? h('span', { class: 'muted' }, 'The DHCP packets carry no host name, vendor class or requested address.') : null) : null,
      w ? h('div', { class: 'stack small', style: { gap: '2px' } }, h('strong', {}, 'Web server'), w.server ? line('Server header', w.server) : null,
        (w.hosts || []).length ? line('Host', w.hosts.join(', ')) : null, (w.uris || []).length ? line('URIs', w.uris.join('  ')) : null,
        w.statuses ? line('Status codes', Object.entries(w.statuses).map(([k, n]) => k + ' ×' + n).join(', ')) : null, (w.contentTypes || []).length ? line('Content types', w.contentTypes.join(', ')) : null,
        w.requests ? line('Requests', String(w.requests)) : null) : null,
      imageStrip(imgs, notImages)));
}

/** Thumbnails of the images this server sent: files the console stored after checking their first bytes, served as inert image bytes. */
function imageStrip(imgs, notImages) {
  if (!imgs.length && !notImages) return null;
  const lost = ((S.imageSummary.notExtracted || {}).tooLarge || 0) + ((S.imageSummary.notExtracted || {}).overCap || 0);
  return h('div', { class: 'stack small', id: 'images', style: { gap: '4px' } }, h('strong', {}, 'Images this server sent'),
    imgs.length ? h('div', { class: 'thumbs' }, imgs.map((i) => h('figure', { class: 'thumb', title: i.sha256 },
      h('img', { src: '/api/v1/captures/' + encodeURIComponent(i.capture) + '/images/' + i.sha256, alt: i.name || i.kind, loading: 'lazy', referrerpolicy: 'no-referrer' }),
      h('figcaption', { class: 'muted' }, (i.name || i.kind) + ' · ' + fmtBytes(i.bytes || 0)),
      h('figcaption', {}, h('span', { class: 'badge lv-NONE' }, i.source || 'tshark'), ' ', h('span', { class: 'mono' }, i.sha256.slice(0, 8)))))) : null,
    notImages ? h('span', { class: 'muted' }, notImages + (notImages === 1 ? ' non-image file' : ' non-image files') + ' not extracted') : null,
    lost && imgs.length ? h('span', { class: 'muted' }, lost + ' more image' + (lost === 1 ? '' : 's') + ' over the size or count limit, not kept') : null);
}

/** Observed conversations of one asset (the graph's edges touching it), with the message kinds as evidence. */
const peersOf = (convs, id) => new Set(convs.map((e) => (e.from === id ? e.to : e.from))).size;
const convsOf = (a) => graphModel().edges.filter((e) => e.kind === 'flow' && (e.from === a.id || e.to === a.id));
function convCard(convs, id) {
  return h('div', { class: 'card' }, convs.length ? h('div', { class: 'small muted strip-note' }, 'One row per device this one talks to. Several ports between the same two devices are one row; open it to see each thread (one protocol on one port).') : null, convs.length ? convs.map((e) => {
    const out = e.from === id, peerId = out ? e.to : e.from, grp = peerId.startsWith('grp:'), peer = grp ? { id: peerId.slice(4) } : byId(peerId);
    return h('div', { class: 'card-b stack', style: { gap: '6px', borderBottom: '1px solid var(--line2)' } },
      h('div', { class: 'row' }, h('span', { class: 'badge lv-NONE' }, out ? 'to' : 'from'), h('a', { class: 'strong', href: (grp ? '#/group/' : '#/asset/') + encodeURIComponent(peer.id) }, grp ? peer.id : nameOf(peer)),
        h('span', { class: 'mono small muted' }, peer.id), h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + protoColor(e.f.protocol) } }, e.f.protocol + ' ' + e.f.port + (e.f.portHint ? ' (' + e.f.portHint + '?)' : '')),
        h('span', { class: 'small muted' }, e.n + (e.n === 1 ? ' message' : ' messages') + ' · ' + fmtRate(flowRate(e.f))),
        h('a', { class: 'btn sm', href: '#/edge/' + encodeURIComponent(e.key) }, 'Details')),
      h('div', { class: 'small' }, Object.entries(e.f.labels || {}).map(([k, n]) => k + ' ×' + n).join(' · ') || 'no message kinds recorded'),
      (e.f.operations || []).length ? h('div', { class: 'small muted' }, 'Operations: ' + opsSummary(e.f, 3) + ((e.f.operations || []).length > 3 ? ' · +' + (e.f.operations.length - 3) + ' more' : '')) : null);
  }) : h('div', { class: 'empty' }, 'No conversation seen for this asset yet. Edges come from decoded Modbus, DNP3, EtherNet/IP, S7comm and SNMP messages, and from TCP/UDP host pairs the analyzer could not decode (shown as unknown).'));
}

/** The side panel of a broadcast or multicast address: not an asset, so no match, no role, no score. */
function groupPanel(address) {
  const back = h('a', { class: 'btn sm', href: '#/graph' }, '‹ Graph');
  const g = S.groups.find((x) => x.address === address);
  if (!g) return [back, h('div', { class: 'card empty' }, 'No such address in the current inventory.')];
  const fs = S.flows.filter((f) => f.server === address);
  return [h('div', { class: 'card' },
    h('div', { class: 'card-b stack', style: { gap: '8px' } }, h('h1', {}, address), h('div', { class: 'row' }, h('span', { class: 'badge lv-NONE' }, g.kind), g.scope ? h('span', { class: 'small muted' }, g.scope) : null),
      h('div', { class: 'small muted' }, 'A group address, not a device ', info('A group address is where frames are sent to be heard by many hosts. It is never an asset, never matched to an advisory and never scored.'))),
    h('div', { class: 'card-b facts' }, fact('Packets', (g.packets || 0).toLocaleString()), fact('Bytes', fmtBytes(g.bytes || 0)), g.firstSeen ? fact('First seen', fmtStamp(g.firstSeen)) : fact('Time', 'unknown'),
      g.lastSeen ? fact('Last seen', fmtStamp(g.lastSeen)) : null, (g.ports || []).length ? fact('Ports', g.ports.join(', '), true) : null, (g.protocols || []).length ? fact('Protocols', g.protocols.join(', ')) : null)),
  h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Senders (' + (g.senders || []).length + ')'),
    h('div', { class: 'card-b stack', style: { gap: '4px' } }, (g.senders || []).map((ip) => h('div', {}, endLink(ip), (fs.find((f) => f.client === ip) ? h('span', { class: 'small muted' }, '  ' + fs.filter((f) => f.client === ip).map((f) => f.port + ' ×' + (f.messages || 0)).join(', ')) : null)))))];
}

/** The Ethernet view: one row per MAC with the maker, frame counts and the IPs behind it; the gateway, firewall and NAT notes are inference. */
function ethernet() {
  const rows = S.macs;
  const notes = rows.filter((m) => (m.notes || []).length);
  return [inventoryTabs('ethernet'), h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Ethernet', h('span', { class: 'muted small' }, rows.length + ' MAC addresses')),
    h('div', { class: 'card-b small muted' }, 'Per source MAC address: who made the network card, how many frames it sent and received, and which IP addresses were seen behind it. A MAC that carries several IPs is often a router, firewall or NAT interface; every such note below is inferred from addresses, not observed.')),
  notes.length ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Inferred topology notes'),
    h('div', { class: 'card-b stack', style: { gap: '6px' } }, notes.slice(0, 40).map((m) => h('div', { class: 'small' }, h('span', { class: 'mono strong' }, m.mac), m.vendor ? ' (' + m.vendor + ')' : '', ' ', h('span', { class: 'badge warn' }, m.kind), ' ', m.notes.join('; '))))) : null,
  h('div', { class: 'card' }, rows.length ? h('div', { class: 'scroll' },
    h('div', { class: 'trow thead g-mac' }, ['MAC', 'Maker', 'Frames sent', 'Received', 'Kind', 'IPs behind it'].map((t) => h('span', {}, t))),
    rows.slice(0, 500).map((m) => h('div', { class: 'trow g-mac' }, h('span', { class: 'mono small' }, m.mac), h('span', { class: 'small wrap' }, m.vendor || '—'),
      h('span', { class: 'mono' }, (m.frames || 0).toLocaleString()), h('span', { class: 'mono' }, (m.framesTo || 0).toLocaleString()), h('span', {}, m.kind && m.kind !== 'host' ? h('span', { class: 'badge warn' }, m.kind) : m.kind || ''),
      h('span', { class: 'mono small wrap' }, (m.ips || []).slice(0, 6).join(', ') + ((m.ipCount || 0) > 6 ? ' +' + (m.ipCount - 6) + ' more' : ''))))) : h('div', { class: 'empty' }, 'No Ethernet data yet. It comes from analyzing a capture with this version.'))];
}

/** One asset as a link, from the IP a conversation names. */
function endLink(ip) {
  const a = assets().find((x) => !x.subaddr && (str(val(x, 'ip')) || x.id) === ip) || assets().find((x) => (str(val(x, 'ip')) || x.id.split('/')[0]) === ip);
  return a ? h('a', { href: '#/asset/' + encodeURIComponent(a.id) }, nameOf(a), ' ', h('span', { class: 'mono small muted' }, ip)) : h('span', { class: 'mono' }, ip);
}
/** Message kinds, then the operations table: the same two cards for one conversation and for a merged pair. */
function kindsAndOps(f) {
  const ops = f.operations || [];
  return [
    Object.keys(f.labels || {}).length ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Message kinds'),
      h('div', { class: 'card-b small wrap' }, Object.entries(f.labels).map(([k, n]) => k + ' ×' + n).join(' · '))) : null,
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Operations', h('span', { class: 'muted small' }, ops.length ? ops.length + (ops.length === 1 ? ' row' : ' rows') + ', busiest first' : '')),
      ops.length ? h('div', { class: 'scroll' },
        h('div', { class: 'trow thead g-op' }, ['Function', 'Access', 'Address', 'Qty', 'Count', 'Sample values'].map((t) => h('span', {}, t))),
        ops.slice().sort((a, b) => (b.count || 0) - (a.count || 0)).map((o) => h('div', { class: 'trow g-op' },
          h('span', { class: 'small wrap' }, o.function, o.object ? h('span', { class: 'mono muted' }, ' ' + o.object) : null,
            o.unit != null ? h('span', { class: 'mono muted', title: 'Modbus unit id' }, ' unit ' + o.unit) : null,
            // how the calls ended: ok, a Modbus exception, a DNP3 IIN flag or control status, an S7/CIP error
            Object.keys(o.statuses || {}).length ? h('div', { class: 'small' }, Object.entries(o.statuses).map(([k, n]) => h('span', { class: 'badge ' + (k === 'ok' ? 'lv-NONE' : 'warn'), style: { marginRight: '4px' } }, k + ' ×' + n))) : null),
          h('span', {}, h('span', { class: 'badge ' + (o.access === 'write' || o.access === 'control' ? 'warn' : 'lv-NONE') }, o.access || 'other')),
          h('span', { class: 'mono small' }, o.address != null ? o.address : '—'), h('span', { class: 'mono small' }, o.quantity != null ? o.quantity : '—'),
          h('span', { class: 'mono' }, o.count != null ? o.count : ''), h('span', { class: 'mono small wrap' }, (o.sampleValues || []).map(String).join(', ') || '—'))))
        : h('div', { class: 'card-b small muted' }, 'No operation detail for this conversation. Function, address, quantity and values come from the Zeek + ICSNPP engine (analyze --engine zeek); the native decoders record message kinds only.')),
  ];
}

/** The side panel of one conversation, or of a merged busy pair ("pair:" key): protocol, ports, counters, times, rate, operations. */
function edgePanel(key) {
  const back = h('a', { class: 'btn sm', href: '#/graph' }, '‹ Graph');
  const pair = key.startsWith('pair:') ? graphModel().edges.find((e) => e.key === key) : null;
  const f = pair ? pair.f : S.flows.find((x) => flowKey(x) === key);
  if (!f) return [back, h('div', { class: 'card empty' }, 'No such conversation in the current inventory. It may have been re-merged, or hidden by a filter or a capture toggle; open the graph and click the edge again.')];
  const rate = flowRate(f), pk = protoKey(f.protocol);
  const parent = pair ? null : graphModel().edges.find((e) => e.members && e.members.includes(f));       // the merged pair this thread was opened from, if any
  const crumbs = h('nav', { class: 'crumbs small', 'aria-label': 'Where you are' }, h('a', { href: '#/graph' }, 'Graph'), ' › ',
    parent ? h('a', { href: '#/edge/' + encodeURIComponent(parent.key) }, f.client + ' → ' + f.server + ' (' + parent.members.length + ' threads)') : h('span', {}, f.client + ' → ' + f.server),
    pair ? null : [' › ', h('span', { class: 'strong' }, protoName(f.protocol) + ' ' + (f.port || ''))]);
  return [
    crumbs,
    pair ? null : h('div', { class: 'small muted' }, 'One thread: ' + protoName(f.protocol) + ' on port ' + (f.port || '?') + ' between these two devices. Messages are the protocol messages inside it.'),
    h('div', { class: 'card' },
      h('div', { class: 'card-b stack', style: { gap: '8px' } },
        h('h1', {}, endLink(f.client), ' → ', endLink(f.server)),
        h('div', { class: 'row' },
          h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + PROTO_COLOR[pk] } }, pair ? pair.label : protoName(f.protocol)),
          pair ? null : h('span', { class: 'mono small' }, f.port || ''), f.transport && !String(f.port || '').includes('/') ? h('span', { class: 'mono small' }, f.transport) : null,
          f.source ? h('span', { class: 'badge lv-NONE', title: 'which engine produced this conversation' }, f.source) : null,
          isScan(f) ? h('span', { class: 'badge warn' }, 'scan attempts only') : null),
        pair ? h('div', { class: 'small muted' }, 'A busy host pair drawn as one edge: the counters and kinds below add up its ' + pair.members.length + ' threads, which are listed under them as threads.')
          : (f.trace || []).some((l) => l.startsWith('* TLS')) ? h('div', { class: 'small muted' }, 'Encrypted (TLS): the payload cannot be read by anyone without the keys. Messages count data packets; everything the handshake and the connection record reveal is in the session trace below.')
          : pk === 'unknown' ? h('div', { class: 'small muted' }, 'Carried but not decoded: the host pair and port are known, the protocol is not. Messages count data packets.',
            f.portHint ? [' ', h('span', { class: 'badge warn' }, 'port-inferred: ' + protoName(f.portHint) + '?'),
              ' Port ' + f.port + ' is usually ' + protoName(f.portHint) + ' (a hint from the port number only, not decoded'
              + (f.portHintSource ? '; port name from ' + f.portHintSource : '') + ').'] : null) : null,
        f.note ? h('div', { class: 'small' }, h('span', { class: 'badge warn' }, 'ICS decode rejected'), ' ' + f.note) : null),
      h('div', { class: 'card-b facts' },
        fact('Messages', (f.messages || 0).toLocaleString()), pair ? null : fact('Rate', fmtRate(rate)),
        f.packets != null ? fact('Packets', f.packets.toLocaleString()) : null, f.bytes != null ? fact('Bytes', fmtBytes(f.bytes)) : null,
        f.bytesToServer != null ? fact('Client → server', fmtBytes(f.bytesToServer)) : null, f.bytesToClient != null ? fact('Server → client', fmtBytes(f.bytesToClient)) : null,
        f.firstSeen ? fact('First seen', fmtStamp(f.firstSeen)) : null, f.lastSeen ? fact('Last seen', fmtStamp(f.lastSeen)) : null,
        !pair && !f.firstSeen && !f.lastSeen ? fact('Time', 'unknown (the capture has no usable timestamps)') : null,
        fmtSpan(f) ? fact('Span', fmtSpan(f)) : null, f.scanAttempts ? fact('Scan attempts', f.scanAttempts.toLocaleString()) : null)),
    traceCard(f),
    ...kindsAndOps(f),
    ...toolEvidence(f),
    pair ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Threads (' + pair.members.length + ')', h('span', { class: 'muted small' }, 'one protocol on one port each')),
      pair.members.slice().sort((a, b) => (b.messages || 0) - (a.messages || 0)).map((m) => h('div', { class: 'card-b stack', style: { gap: '4px', borderBottom: '1px solid var(--line2)' } },
        h('div', { class: 'row' }, h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + protoColor(m.protocol) } }, m.protocol + ' ' + m.port),
          h('span', { class: 'small muted' }, (m.messages || 0) + ' messages · ' + fmtRate(flowRate(m))), h('a', { class: 'btn sm', href: '#/edge/' + encodeURIComponent(flowKey(m)) }, 'Details')),
        h('div', { class: 'small' }, Object.entries(m.labels || {}).map(([k, n]) => k + ' ×' + n).join(' · ') || 'no message kinds recorded')))) : null,
  ].filter(Boolean);
}

/** One trace line as a bubble row: a bold head, then its key=value pairs as small labelled values. */
function bubbleRow(text) {
  const parts = text.split(/ (?=[a-z_][a-z0-9_.]*=)/), head = /^[a-z_][a-z0-9_.]*=/.test(parts[0]) ? null : parts.shift();
  return h('div', { class: 'bl' }, head ? h('span', { class: 'bh' }, head) : null,
    parts.map((p) => { const i = p.indexOf('='); return h('span', { class: 'kv' }, h('span', { class: 'k' }, p.slice(0, i)), h('span', { class: 'v' }, p.slice(i + 1))); }));
}

/** What the Zeek logs recorded about one conversation, as a chat: client on the right, server on the left, session facts in the middle. */
function traceCard(f) {
  const msgs = [];
  for (const l of f.trace || []) {
    const m = /^(\d\d:\d\d:\d\d) ([*<>]) (.*)$/.exec(l);
    if (!m) continue;
    const side = { '>': 'out', '<': 'in', '*': 'sys' }[m[2]], last = msgs[msgs.length - 1];
    if (last && last.side === side && side !== 'sys') last.rows.push(m[3]); else msgs.push({ side, time: m[1], rows: [m[3]] });
  }
  if (!msgs.length) return null;
  let prev = '';
  return h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Conversation', h('span', { class: 'muted small' }, (f.trace || []).length + ' events from the Zeek logs, UTC')),
    h('div', { class: 'chat' }, msgs.map((m) => {
      const who = m.side === 'out' ? 'Client ' + f.client : m.side === 'in' ? 'Server ' + f.server : null, showWho = who && prev !== m.side;
      prev = m.side;
      return h('div', { class: 'msg ' + m.side }, showWho ? h('div', { class: 'who' }, who) : null,
        m.rows.map(bubbleRow), h('div', { class: 'time' }, m.time));
    })));
}

/** What optional open-source tools said about a conversation: nDPI/tshark labels (not decodes), Suricata alerts, Community IDs. */
function toolEvidence(f) {
  const cls = f.classifiedBy || [], al = f.alerts || [], ids = f.communityIds || [];
  if (!cls.length && !al.length && !ids.length) return [];
  const tool = (t) => ({ ndpi: 'nDPI', tshark: 'Wireshark tshark', suricata: 'Suricata' }[t] || t);
  return [h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Other open-source tools', h('a', { class: 'btn sm', href: '#/engines' }, 'Engines')),
    h('div', { class: 'card-b stack', style: { gap: '8px' } },
      cls.map((c) => h('div', { class: 'row' }, h('span', { class: 'badge lv-NONE' }, tool(c.tool) + (c.version ? ' ' + c.version : '')),
        h('span', { class: 'badge warn' }, 'classified, not decoded: ' + c.protocol + '?'), h('span', { class: 'badge c-' + c.confidence }, c.confidence),
        h('span', { class: 'small muted' }, c.basis === 'dissector' ? 'Wireshark dissector chain' : 'deep-packet inspection'))),
      al.map((x) => h('div', { class: 'row' }, h('span', { class: 'badge lv-NONE' }, tool(x.tool) + (x.version ? ' ' + x.version : '')),
        h('span', { class: 'badge ' + (x.severity <= 1 ? 'bad' : 'warn') }, x.kind + (x.severity ? ' sev ' + x.severity : '')),
        h('span', { class: 'small wrap' }, x.signature + (x.sid ? ' (sid ' + x.sid + ')' : '') + (x.count > 1 ? ' x' + x.count : '')))),
      al.length ? h('div', { class: 'small muted' }, 'Suricata matched a rule or flagged an anomaly. That is evidence that something looked unusual, not a decoded protocol and not proof of an attack.') : null,
      ids.length ? h('div', { class: 'small' }, 'Community ID ', ids.map((i) => h('span', { class: 'mono' }, i + ' ')), h('span', { class: 'muted' }, '(search the same ID in Suricata, Zeek or Wireshark)')) : null))];
}

function attrsCard(a, site, role) {
  const missing = Object.fromEntries((a.completeness.missing || []).map((m) => [m.attr, m]));
  const fieldVal = (k) => (k === 'os' ? a.os || a.firmware : k === 'vendor' ? a.vendor || a.vendor_oui : a[k]);   // OUI vendor is shown, flagged LOW
  const noIdentity = !IDENTITY_KEYS.some((k) => (k === 'os' ? a.os || a.firmware : a[k]));
  const head = h('div', { class: 'card-h' }, 'CISA high-priority attributes', h('span', { class: 'row' },
    S.editing ? null : h('button', { class: 'btn sm', onclick: () => { S.editing = true; render(); } }, 'Edit site fields'),
    S.editing ? null : h('button', { class: 'btn sm pri', disabled: role !== 'validator', title: role !== 'validator' ? 'Only a validator can validate. Change Role in the sidebar.' : null,
      onclick: () => save(a, { validated: !isValidated(a) }) }, isValidated(a) ? 'Remove validation' : 'Mark validated')));
  if (S.editing) return h('div', { class: 'card' }, head, editForm(a, site));
  return h('div', { class: 'card' }, head,
    role !== 'validator' ? h('div', { class: 'small muted strip-note' }, 'Only a validator can mark an asset validated. Change your role in Settings.') : null,
    h('div', { class: 'scroll' },
      ATTRS.concat(ATTRS_EXTRA).filter(([k]) => k !== 'alerts' || a.alerts).map(([k, label]) => {
        const f = fieldVal(k), person = f && /^entered by /.test(f.evidence || '');
        if (!f) return h('div', { class: 'g-attr at muted', title: missing[k] ? missing[k].hint : EXTRA_HINT[k] || '' }, label + ': ' + (noIdentity && IDENTITY_KEYS.includes(k) ? NO_IDENTITY : 'Not filled'),
          missing[k] || EXTRA_HINT[k] ? h('span', { class: 'tip' }, missing[k] ? missing[k].hint : EXTRA_HINT[k]) : null);
        return h('div', { class: 'g-attr at' }, h('b', {}, label), h('span', { class: 'wrap val' }, str(f.value)),
          h('span', { class: 'badge c-' + (person ? 'PERSON' : f.confidence) }, person ? 'PERSON' : f.confidence),
          f.conflict ? h('span', { class: 'badge warn' }, 'conflict') : null, f.inherited ? h('span', { class: 'badge lv-NONE' }, 'inherited') : null,
          sourceTags(f.evidence).map((t) => h('span', { class: 'badge lv-NONE', title: 'open-source component named in the evidence; see Engines' }, t)),
          f.evidence ? h('span', { class: 'inf', tabindex: '0', 'aria-label': 'evidence' }, 'i', h('span', { class: 'tip mono' }, f.evidence)) : null);
      })),
    h('div', { class: 'card-h', style: { borderTop: '1px solid var(--line2)' } }, 'Site fields', h('span', { class: 'muted small' }, 'not part of the 14; for grouping and lifecycle')),
    h('div', { class: 'form' }, [['Zone', site.zone], ['Purdue level', site.purdue ? 'Level ' + site.purdue : 'Suggested: ' + (purdueOf(a) ? 'Level ' + purdueOf(a) : 'none')],
      ['Owner', site.owner], ['Lifecycle', site.lifecycle || 'In service']].map(([l, v]) => fact(l, v || 'Not set', true))));
}

function editForm(a, site) {
  const cur = (k) => str(val(a, k));
  const inputs = {};
  const text = (k, label, hint, value) => h('label', {}, label, inputs[k] = h('input', { value: value || '', placeholder: hint }), h('span', { class: 'hint muted small' }, ''));
  const select = (k, label, opts, value) => h('label', {}, label, inputs[k] = h('select', {}, opts.map(([v, t]) => h('option', { value: v, selected: v === (value || '') }, t))));
  const human = (k) => {
    // Only a person's own entry can be edited here; capture-derived values stay as evidence.
    const f = a[k];
    return f && /^entered by /.test(f.evidence || '') ? cur(k) : '';
  };
  return h('form', { class: 'stack', style: { gap: '0' }, onsubmit: (e) => {
    e.preventDefault();
    const body = {};
    for (const [k, el] of Object.entries(inputs)) {
      const before = ['criticality', 'asset_number', 'location', 'logging', 'user_accounts'].includes(k) ? human(k) : (site[k] || SITE_DEFAULTS[k] || '');
      if (el.value.trim() !== before) body[k] = el.value.trim();
    }
    S.editing = false;
    if (Object.keys(body).length) save(a, body); else render();
  } },
  h('div', { class: 'form' },
    select('criticality', 'Criticality', [['', 'Unknown'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], human('criticality')),
    text('asset_number', 'Asset number', 'e.g. A-10442', human('asset_number')),
    text('location', 'Physical location', 'e.g. Hall B, cabinet 3', human('location')),
    text('logging', 'Logging', 'e.g. syslog to HIST-01', human('logging')),
    text('user_accounts', 'User accounts (comma-separated)', 'e.g. engineer, maint', human('user_accounts')),
    text('zone', 'Zone', 'e.g. Cell 1 control', site.zone),
    select('purdue', 'Purdue level', [['', 'Suggest from role'], ['3.5', 'Level 3.5 (DMZ)'], ['3', 'Level 3'], ['2', 'Level 2'], ['1', 'Level 1'], ['0', 'Level 0']], site.purdue),
    text('owner', 'Owner', 'who validates this record', site.owner),
    select('lifecycle', 'Lifecycle stage', LIFECYCLE.map((x) => [x, x]), site.lifecycle || SITE_DEFAULTS.lifecycle)),
  h('div', { class: 'card-b row' }, h('button', { class: 'btn pri', type: 'submit' }, 'Save changes'),
    h('button', { class: 'btn', type: 'button', onclick: () => { S.editing = false; render(); } }, 'Cancel'),
    h('span', { class: 'muted small' }, 'Saved values are logged under your name and count toward completeness.')));
}

async function save(a, body) {
  try {
    const r = await api('PATCH', 'assets/' + encodeURIComponent(a.id), JSON.stringify(body), 'application/json');
    toast(r.changes.length ? r.changes.length + ' change(s) saved and logged' : 'Nothing changed');
  } catch (e) { toast(e.message); }
  await refresh();
}

function review() {
  const q = S.reviewSearch.trim().toLowerCase();
  const groups = reviewGroups().map((g) => ({ ...g, items: g.items.filter(([a, why]) => !q || [nameOf(a), a.id, why].join(' ').toLowerCase().includes(q)) })).filter((g) => g.items.length);
  const pending = [...new Map(reviewGroups().flatMap((g) => g.items).filter(([a]) => !isValidated(a)).map(([a]) => [a.id, a])).values()];
  const canConfirm = store.get('role') === 'validator';
  const cards = groups.map((g) => h('div', { class: 'card' },
    h('div', { class: 'card-h' }, g.title, h('span', { class: 'badge lv-NONE' }, g.items.length)),
    ...g.items.map(([a, why]) => h('a', { class: 'rv', href: '#/asset/' + encodeURIComponent(a.id) }, dot(g.color),
      h('span', { style: { flex: '1', minWidth: '0' } }, h('span', { class: 'cell-name' }, nameOf(a), ' ', h('span', { class: 'mono small muted' }, a.id)), h('span', { class: 'small muted' }, why)),
      h('span', { class: 'review-meta' }, h('span', { class: 'small muted' }, 'Last reviewed: ' + lastReviewed(a.id)), h('span', { class: 'btn sm' }, 'Open'))))));
  return [
    h('div', {}, h('h1', {}, 'Review queue', info('Cross-check collected data before an owner validates it (CISA: assign roles for collection and validation).'))),
    h('div', { class: 'row findings-actions' }, h('label', { class: 'screen-search' }, h('span', { class: 'sr' }, 'Search review queue'), h('input', { type: 'search', value: S.reviewSearch, placeholder: 'Search hosts and review reasons', oninput: (e) => { S.reviewSearch = e.target.value; render(); $('main .screen-search input')?.focus(); } })),
      h('button', { class: 'btn pri', type: 'button', disabled: !canConfirm || pending.length === 0, title: canConfirm ? '' : 'Only a Validator can confirm assets', onclick: async () => {
        if (!canConfirm) return;
        for (const a of pending) {
          try { await api('PATCH', 'assets/' + encodeURIComponent(a.id), JSON.stringify({ validated: true }), 'application/json'); }
          catch (e) { toast('Stopped at ' + a.id + ': ' + e.message); break; }
        }
        await refresh();
        toast('Validation confirmations saved under ' + (store.get('actor') || 'unknown'));
      } }, 'Confirm all ' + pending.length)),
    groups.length === 0 ? h('div', { class: 'card empty' }, 'Nothing to review.') : cards,
  ];
}

function lastReviewed(id) {
  const entry = S.changes.find((x) => x.asset === id && x.field === 'validated');
  return entry ? fmtTime(entry.at) : 'Never';
}

function findings() {
  const tab = route().name === 'review' ? 'review' : route().name === 'advisories' ? 'advisories' : S.findingsTab;
  S.findingsTab = tab;
  return tab === 'review' ? review() : advisories();
}

function advisories() {
  const query = S.advisorySearch.trim().toLowerCase();
  const rows = advisoryRows().filter((r) => !query || [r.id, r.title, ...r.cves, ...r.affected].join(' ').toLowerCase().includes(query));
  return [
    h('div', {}, h('h1', {}, 'Advisories', info('CISA CSAF ICS advisories that hit at least one asset. KEV-listed first, then CVSS.'))),
    h('label', { class: 'screen-search' }, h('span', { class: 'sr' }, 'Search advisories'), h('input', { type: 'search', value: S.advisorySearch, placeholder: 'Search advisories, CVEs or affected products', oninput: (e) => { S.advisorySearch = e.target.value; render(); const input = $('main .screen-search input'); if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); } } })),
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-adv' }, ['Advisory', 'Title', 'CVSS', 'KEV', 'Assets'].map((t) => h('span', {}, t))),
      rows.length === 0 ? h('div', { class: 'empty' }, query ? 'No advisory matches this search.' : 'No advisory matches any asset in this index.') : rows.map((r) => [
        h('button', { class: 'trow g-adv' + (S.openAdv === r.id ? ' sel' : ''), 'aria-expanded': String(S.openAdv === r.id), onclick: () => { S.openAdv = S.openAdv === r.id ? null : r.id; render(); } },
          h('span', { class: 'mono strong' }, r.id), h('span', {}, r.title), h('span', { class: 'mono' }, r.cvss.toFixed(1)),
          h('span', {}, r.kev ? h('span', { class: 'badge kev' }, 'KEV') : null), h('span', {}, r.hits.length + (r.hits.length === 1 ? ' asset' : ' assets'))),
        S.openAdv === r.id ? h('div', { class: 'card-b stack', style: { background: 'var(--accent-tint)', paddingLeft: '32px' } },
          h('div', { class: 'small' }, h('strong', {}, 'Affected: '), [...r.affected].join('; ') || '?', ' · ', h('strong', {}, 'CVEs: '), h('span', { class: 'mono' }, r.cves.join(', '))),
          h('div', { class: 'row' }, r.hits.map((x) => h('a', { class: 'lane-chip', href: '#/asset/' + encodeURIComponent(x.a.id) }, nameOf(x.a), ' ', levelBadge(x.level))))) : null,
      ]))),
  ];
}

function indexScreen() {
  const ix = S.index || {};
  const staleDays = Math.max(1, Math.min(3650, Number(store.get('index-stale-days')) || 30));
  const ageDays = ix.generated ? Math.floor((Date.now() - Date.parse(ix.generated)) / 86400000) : null;
  const isStale = Boolean(ix.warning) || ageDays != null && ageDays > staleDays;
  const idxFile = h('input', { type: 'file', accept: '.json', id: 'idx-file' }), sigFile = h('input', { type: 'file', accept: '.sig', id: 'sig-file' });
  const check = async () => {
    const f = idxFile.files[0], s = sigFile.files[0];
    if (!f) { toast('Choose index.json first'); return; }
    try {
      const sig = s ? (await s.text()).trim() : null;
      S.staged = { file: f, sig, meta: await api('POST', 'index?dry=1', f, 'application/octet-stream', sig ? { 'X-Index-Signature': sig } : {}) };
    } catch (e) { S.staged = null; toast('Refused: ' + e.message); }
    render();
  };
  const st = S.staged;
  return [
    h('div', {}, h('h1', {}, 'Advisory index', info('Built on the online side from CISA CSAF OT + KEV, signed, and carried across the air gap.'))),
    h('div', { class: 'facts' },
      h('div', { class: 'card card-b' }, fact('Generated', fmtTime(ix.generated)), isStale ? h('span', { class: 'badge warn' }, 'stale') : h('span', { class: 'badge ok' }, 'current')),
      h('div', { class: 'card card-b' }, fact('KEV catalog', ix.kevCatalogVersion || '?')),
      h('div', { class: 'card card-b' }, fact('Advisories / rows', (ix.advisories || 0).toLocaleString() + ' / ' + (ix.rows || 0).toLocaleString())),
      h('div', { class: 'card card-b' }, fact('Signature', ix.verified ? 'Ed25519 verified' : 'UNVERIFIED'))),
    h('div', { class: 'card card-b stale-setting' }, h('label', { for: 'index-stale-days' }, 'Mark index stale after days'), h('input', { id: 'index-stale-days', type: 'number', min: '1', max: '3650', value: staleDays, onchange: (e) => { store.set('index-stale-days', String(Math.max(1, Math.min(3650, Number(e.target.value) || 30)))); render(); } }),
      h('span', { class: 'muted small' }, 'Saved in this browser. The server warning remains authoritative.')),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Import a new index'),
      h('div', { class: 'form' }, h('label', { for: 'idx-file' }, 'index.json', idxFile), h('label', { for: 'sig-file' }, 'index.json.sig', sigFile)),
      h('div', { class: 'card-b row' }, h('button', { class: 'btn pri', onclick: check }, 'Verify'),
        h('span', { class: 'muted small' }, 'Nothing changes until you activate. A bad signature is refused.'))),
    st ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Ready to activate', h('span', { class: 'badge ' + (st.meta.verified ? 'ok' : 'bad') }, st.meta.verified ? 'signature valid' : 'UNVERIFIED')),
      h('div', { class: 'card-b facts' },
        fact('Generated', fmtTime(ix.generated) + ' → ' + fmtTime(st.meta.generated), true), fact('KEV catalog', (ix.kevCatalogVersion || '?') + ' → ' + st.meta.kevCatalogVersion, true),
        fact('Advisories', (ix.advisories || 0) + ' → ' + st.meta.advisories, true)),
      h('div', { class: 'card-b row' },
        h('button', { class: 'btn pri', onclick: async () => {
          try { await api('POST', 'index', st.file, 'application/octet-stream', st.sig ? { 'X-Index-Signature': st.sig } : {}); toast('Index activated. All assets re-matched.'); S.staged = null; } catch (e) { toast(e.message); }
          await refresh();
        } }, 'Activate and re-match'),
        h('button', { class: 'btn', onclick: () => { S.staged = null; render(); } }, 'Cancel'))) : null,
  ];
}

function exportScreen() {
  return [h('div', {}, h('h1', {}, 'Export', info('Download the current site inventory and report.'))),
    h('div', { class: 'card export-list' },
      h('a', { class: 'btn', href: '/api/v1/export/inventory.csv', download: 'inventory.csv' }, 'inventory.csv'),
      h('a', { class: 'btn', href: '/api/v1/export/inventory.json', download: 'inventory.json' }, 'inventory.json'),
      h('a', { class: 'btn', href: '/api/v1/export/report.html', download: 'report.html' }, 'report.html'),
      h('button', { class: 'btn', type: 'button', onclick: () => toast('PDF export is not available yet. Use report.html.') }, 'report.pdf'))];
}

function settingsScreen() {
  const actor = h('input', { id: 'setting-actor', name: 'actor', autocomplete: 'name', value: store.get('actor'), placeholder: 'e.g. R. Analyst', required: true });
  const role = h('select', { id: 'setting-role', name: 'role' },
    h('option', { value: 'collector' }, 'Collector'), h('option', { value: 'validator' }, 'Validator'));
  role.value = store.get('role') || 'collector';
  const stale = h('input', { id: 'setting-stale-days', name: 'stale-days', type: 'number', min: '1', max: '3650', value: Math.max(1, Number(store.get('index-stale-days')) || 30) });
  return [h('div', {}, h('h1', {}, 'Settings', info('Choose the name recorded on future changes and the local console role.'))),
    h('form', { class: 'card settings-form', onsubmit: (e) => {
      e.preventDefault();
      store.set('actor', actor.value.trim()); store.set('role', role.value);
      store.set('index-stale-days', String(Math.max(1, Math.min(3650, Number(stale.value) || 30))));
      toast('Settings saved on this browser. Future writes use ' + actor.value.trim() + ' (' + role.value + ').'); render();
    } },
      h('div', { class: 'form' }, h('label', { for: 'setting-actor' }, 'Your name', actor), h('label', { for: 'setting-role' }, 'Role', role),
        h('label', { for: 'setting-stale-days' }, 'Mark index stale after days', stale)),
      h('div', { class: 'card-b row' }, h('button', { class: 'btn pri', type: 'submit' }, 'Save settings'),
        info('Changes are sent with your session name and appear in the append-only change log. Only a Validator can validate assets or confirm review items. The role is enforced by the server; the console listens on 127.0.0.1.')) )];
}

function dataScreen() {
  const selected = ({ captures: 'captures', index: 'index', engines: 'engines', log: 'log', export: 'export' })[route().name] || S.dataTab;
  S.dataTab = selected;
  const screen = { captures, index: indexScreen, engines, log, export: exportScreen }[selected] || captures;
  return screen();
}

function log() {
  const q = S.logSearch.trim().toLowerCase();
  const rows = S.changes.filter((x) => [x.at, x.actor, x.asset, x.field, x.from, x.to, x.source].join(' ').toLowerCase().includes(q));
  return [
    h('div', {}, h('h1', {}, 'Change log', info('Append-only. Every capture merge, human edit and index swap, newest first.'))),
    h('label', { class: 'screen-search' }, h('span', { class: 'sr' }, 'Filter change log'), h('input', { type: 'search', value: S.logSearch, placeholder: 'Filter by asset, actor, field or source capture', oninput: (e) => { S.logSearch = e.target.value; render(); $('main .screen-search input')?.focus(); } })),
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-log' }, ['When', 'Actor', 'Asset', 'Field', 'Change', 'Source capture'].map((t) => h('span', {}, t))),
      rows.length === 0 ? h('div', { class: 'empty' }, S.changes.length ? 'No changes match this filter.' : 'No changes yet.') : rows.map((x) => h('div', { class: 'trow g-log' },
        h('span', { class: 'mono small' }, fmtTime(x.at)), h('span', { class: 'strong' }, x.actor),
        x.asset.startsWith('(') ? h('span', { class: 'muted' }, x.asset) : h('a', { class: 'mono small', href: '#/asset/' + encodeURIComponent(x.asset) }, x.asset),
        h('span', {}, x.field), h('span', { class: 'wrap' }, h('span', { class: 'muted' }, x.from || '∅'), ' → ', x.to || '∅'), h('span', { class: 'small muted' }, x.source))))),
  ];
}

// ------------------------------------------------------------------ graph

// Assets are nodes, observed conversations (S.flows, client -> server) are directed edges, advisories hang off assets.
// Plain SVG and a small force layout; no library, so nothing is fetched and the CSP stays default-src 'self'.
const NODE_R = 18;
const MERGE_AT = 3;   // more conversations than this from one host to another are drawn as a single edge that opens the client's asset panel
const ICONS = {   // outline glyphs centred on 0, ~±9 units, from the design reference
  PLC: 'M-9,-7H9V7H-9Z M-9,-2H9 M-5,3H-3 M0,3H2', Workstation: 'M-9,-8H9V3H-9Z M-3,3V7 M3,3V7 M-6,7H6', Network: 'M-9,-4H9V4H-9Z M-6,0H-4 M-1,0H1 M4,0H6',
  Drive: 'M-9,-7H9V7H-9Z M-6,0H-2L0,-3L2,3L4,0H6', 'Comms adapter': 'M-9,-5H9V5H-9Z M-5,-2H5 M-5,2H1',
  Other: 'M-8,-9H8V-3H-8Z M-8,-3H8V3H-8Z M-8,3H8V9H-8Z M-5,-6H-3 M-5,0H-3 M-5,6H-3', External: 'M-9,-9H9V9H-9Z M-9,0H9 M0,-9V9', Unknown: 'M-8,-8H8V8H-8Z',
};
const GROUP_ICON = 'M-9,-6H9 M-9,0H9 M-9,6H9 M-6,-9V9 M0,-9V9 M6,-9V9';   // a grid: a broadcast
const ADV_ICON = 'M0 -21 L19 13 L-19 13 Z';
const GR = { pos: new Map(), view: { x: 0, y: 0, k: 1 }, fitted: false, sig: '', vp: null, els: null, drag: null, moved: false };

/** "ListIdentity" -> "ENIP ListIdentity"; the top message kind of a conversation, "+n" when there are more. */
function flowLabel(f) {
  const kinds = Object.entries(f.labels || {}).sort((a, b) => b[1] - a[1]).map((x) => x[0]);
  if (isScan(f)) return 'scan ×' + f.scanAttempts;
  if (!kinds.length) return protoKey(f.protocol) === 'unknown' ? (f.port || 'unknown') + (f.portHint ? ' (' + protoName(f.portHint) + '?)'
    : f.classifiedBy && f.classifiedBy.length ? ' (' + f.classifiedBy[0].protocol + '?)' : '') : protoName(f.protocol);
  const pre = protoName(f.protocol);
  const top = /^(Modbus|DNP3|SNMP|S7|EtherNet\/IP|CIP|ICMP)/.test(kinds[0]) ? kinds[0] : pre + ' ' + kinds[0];
  return top + (kinds.length > 1 ? ' +' + (kinds.length - 1) : '');
}

function graphModel() {
  const all = assets().filter(inView), nodes = all.map((a) => ({ id: a.id, a })), edges = [];
  const groupAt = new Map(S.groups.map((g) => [g.address, g]));       // broadcast / multicast destinations: drawn as grey nodes only when asked for
  const ipOf = (a) => str(val(a, 'ip')) || a.id.split('/')[0];
  const owner = new Map();                                              // IP -> the asset that owns it (a unit/slot only when nothing else does)
  for (const a of all) if (!a.subaddr) owner.set(ipOf(a), a.id);
  for (const a of all) if (a.subaddr && !owner.has(ipOf(a))) owner.set(ipOf(a), a.id);
  for (const a of all) if (a.subaddr && owner.get(ipOf(a)) !== a.id) edges.push({ id: 'u:' + a.id, kind: 'unit', from: owner.get(ipOf(a)), to: a.id, label: a.subaddr });
  const byPair = new Map();                                             // from>to -> its flows; a busy pair becomes one edge, not one per port
  S.flows.forEach((f, i) => {
    const from = owner.get(f.client), g = groupAt.get(f.server);
    const to = g ? (S.showGroups ? 'grp:' + g.address : null) : owner.get(f.server);
    if (!(from && to && from !== to) || flowHidden(f)) return;
    if (g && !nodes.some((n) => n.id === to)) nodes.push({ id: to, g });
    const k = from + '\n' + to;
    (byPair.get(k) || byPair.set(k, []).get(k)).push({ f, i, from, to });
  });
  for (const g of byPair.values()) {
    if (g.length <= MERGE_AT) { for (const { f, i, from, to } of g) edges.push({ id: 'f' + i, key: flowKey(f), kind: 'flow', from, to, f, n: f.messages || 0, label: flowLabel(f) }); continue; }
    const fs = g.map((x) => x.f), labels = {}, byProto = {};
    for (const f of fs) { for (const [k, c] of Object.entries(f.labels || {})) labels[k] = (labels[k] || 0) + c; byProto[f.protocol] = (byProto[f.protocol] || 0) + (f.messages || 0) + 1; }
    const top = Object.keys(byProto).sort((a, b) => byProto[b] - byProto[a])[0], n = fs.reduce((a, f) => a + (f.messages || 0), 0), scans = fs.reduce((a, f) => a + (f.scanAttempts || 0), 0);
    const sum = (k) => fs.reduce((a, x) => a + (x[k] || 0), 0);
    const f = { client: fs[0].client, server: fs[0].server, protocol: top, port: fs.length + ' ports', labels, messages: n, scanAttempts: scans, bytes: sum('bytes') || undefined, bytesToServer: sum('bytesToServer') || undefined, bytesToClient: sum('bytesToClient') || undefined, operations: fs.flatMap((x) => x.operations || []) };   // synthetic: what the drawing and the cards read
    edges.push({ id: 'm' + g[0].i, key: pairKey(g[0].from, g[0].to), kind: 'flow', from: g[0].from, to: g[0].to, f, n, members: fs, label: fs.length + ' threads' });
  }
  if (S.showAdv) {
    for (const r of advisoryRows()) {
      const hits = r.hits.filter((x) => (x.level === 'EXACT' || x.level === 'PROBABLE') && assetVisible(x.a));   // vendor-only matches would hang every advisory on every device
      if (!hits.length) continue;
      nodes.push({ id: 'adv:' + r.id, adv: r });
      for (const x of hits) edges.push({ id: 'a:' + r.id + '>' + x.a.id, kind: 'adv', from: x.a.id, to: 'adv:' + r.id, label: x.level });
    }
  }
  return { nodes, edges };
}

function nodeLabel(n) {
  if (n.g) return n.g.kind + ' address ' + n.g.address + ', not a device; ' + (n.g.senders || []).length + ' sender' + ((n.g.senders || []).length === 1 ? '' : 's');
  if (n.adv) return 'Advisory ' + n.adv.id + ', CVSS ' + n.adv.cvss.toFixed(1) + (n.adv.kev ? ', KEV listed' : '') + ', affects ' + n.adv.hits.length + (n.adv.hits.length === 1 ? ' asset' : ' assets');
  const a = n.a, vm = [str(val(a, 'vendor')), str(val(a, 'model'))].filter(Boolean).join(' ');
  return nameOf(a) + ', ' + a.id + ', ' + roleGroup(a) + (vm ? ', ' + vm : '') + ', advisory match ' + (levelOf(a) === 'UNRUN' ? 'not run' : levelOf(a))
    + (a.match && a.match.kevAtModel ? ', KEV at model' : '') + (isValidated(a) ? ', validated' : '');
}
const edgeLabel = (e, byNode) => (e.kind === 'flow' ? 'Conversation from ' + byNode(e.from) + ' to ' + byNode(e.to) + ': ' + e.f.protocol + ' ' + e.f.port + ', '
  + Object.entries(e.f.labels || {}).map(([k, n]) => k + ' x' + n).join(', ') + ', ' + e.n + ' messages' + (e.f.scanAttempts ? ', ' + e.f.scanAttempts + ' scan attempts' : '')
  : e.kind === 'unit' ? byNode(e.to) + ' sits behind ' + byNode(e.from) + ' as ' + e.label : byNode(e.from) + ' matches advisory ' + byNode(e.to) + ' at ' + e.label);

const K = 150;   // layout spacing
// Link distance grows with how much two hosts talk: distance = K * min(LINK_MAX, 1 + LINK_GROWTH * log10(1 + messages)). Tune here:
// LINK_GROWTH 0 turns it off, higher spreads busy pairs further apart; LINK_MAX caps the stretch (repulsion only reaches 3K, keep this below 3).
const LINK_GROWTH = 0.35, LINK_MAX = 2.5;
/** How many times K a pair of hosts with `messages` messages (all their conversations together) wants to sit apart. */
const linkStretch = (messages) => Math.min(LINK_MAX, 1 + LINK_GROWTH * Math.log10(1 + messages));
/** One spring per node pair, however many conversations they share: its pull, weaker the more messages the pair exchanged. */
function springsOf(edges, ix) {
  const m = new Map();
  for (const e of edges) {
    const i = ix.get(e.from), j = ix.get(e.to);
    if (i == null || j == null) continue;
    const pk = i < j ? i + ',' + j : j + ',' + i, s = m.get(pk) || m.set(pk, { i, j, adv: e.kind === 'adv', msgs: 0 }).get(pk);
    if (e.kind === 'flow') s.msgs += Math.max(1, e.n || 0);
  }
  for (const s of m.values()) s.f = (s.adv ? 0.6 : 1) / Math.pow(linkStretch(s.msgs), 3);   // spring d*d/K against repulsion K*K/d balances at d = K*stretch, so the pull shrinks with stretch^3
  return m;
}
/** Fruchterman-Reingold on one set of nodes: repulsion K*K/d (not beyond 3K), springs d*d/K, gravity to the origin. */
function relax(nodes, edges, iters, warm) {
  const P = nodes.map((n) => GR.pos.get(n.id)), ix = new Map(nodes.map((n, i) => [n.id, i]));
  const springs = springsOf(edges, ix);
  const band = (n) => (n.a ? ({ '3.5': -1.5, 3: -1, 2: 0, 1: 1, 0: 2 }[purdueOf(n.a)] ?? 3) : 3.5) * K * 0.8;   // Purdue layers: top = site operations, bottom = process; advisories and unplaced below
  for (let it = 0; it < iters; it++) {
    const t = warm ? K * 0.08 * (1 - it / iters) + 0.5 : K * 0.6 * (1 - it / iters) + 1;
    const dx = P.map(() => 0), dy = P.map(() => 0);
    for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) {
      let x = P[i].x - P[j].x, y = P[i].y - P[j].y, d = Math.hypot(x, y);
      if (d > 3 * K) continue;
      if (d < 1) { x = 1; y = 0; d = 1; }
      const f = K * K / d / d;
      dx[i] += x * f; dy[i] += y * f; dx[j] -= x * f; dy[j] -= y * f;
    }
    for (const { i, j, f: k } of springs.values()) {
      const x = P[i].x - P[j].x, y = P[i].y - P[j].y, d = Math.hypot(x, y) || 1, f = d / K * k;
      dx[i] -= x * f; dy[i] -= y * f; dx[j] += x * f; dy[j] += y * f;
    }
    P.forEach((p, i) => {
      if (p.fixed) return;
      dx[i] -= p.x * 0.05; dy[i] -= p.y * 0.05;
      if (S.layout === 'purdue') dy[i] += (band(nodes[i]) - p.y) * 0.25;
      const d = Math.hypot(dx[i], dy[i]) || 1, m = Math.min(d, t) / d;
      p.x += dx[i] * m; p.y += dy[i] * m;
    });
  }
}

/**
 * Fresh layout: every connected component is laid out on its own, then the components are packed in rows, biggest
 * first (one force run over everything flings small components far away). A later poll only nudges (`warm`) so
 * nothing the user has looked at jumps. Purdue mode is one global run because the levels fix the rows.
 */
function layoutGraph({ nodes, edges }, warm) {
  const ids = new Set(nodes.map((n) => n.id));
  for (const id of [...GR.pos.keys()]) if (!ids.has(id)) GR.pos.delete(id);
  nodes.forEach((n, i) => {
    if (GR.pos.has(n.id)) return;
    const e = edges.find((x) => (x.from === n.id && GR.pos.has(x.to)) || (x.to === n.id && GR.pos.has(x.from)));
    const q = e && GR.pos.get(e.from === n.id ? e.to : e.from), r = e ? 90 : 45 * Math.sqrt(i + 1), t = i * 2.4;   // golden-ish angle: deterministic, no Math.random
    GR.pos.set(n.id, { x: (q ? q.x : 0) + r * Math.cos(t), y: (q ? q.y : 0) + r * Math.sin(t) });
  });
  const big = nodes.length > 600 ? 60 : nodes.length > 250 ? 120 : 0;
  if (warm || S.layout === 'purdue') return relax(nodes, edges, big || (warm ? 50 : 260), warm);
  const adj = new Map(nodes.map((n) => [n.id, []]));
  edges.forEach((e) => { if (adj.has(e.from) && adj.has(e.to)) { adj.get(e.from).push(e.to); adj.get(e.to).push(e.from); } });
  const seen = new Set(), groups = [];
  for (const n of nodes) {
    if (seen.has(n.id)) continue;
    const stack = [n.id], members = [];
    seen.add(n.id);
    while (stack.length) { const u = stack.pop(); members.push(u); for (const v of adj.get(u)) if (!seen.has(v)) { seen.add(v); stack.push(v); } }
    groups.push(members);
  }
  groups.sort((x, y) => y.length - x.length);
  const boxes = groups.map((g) => {
    const set = new Set(g);
    relax(nodes.filter((n) => set.has(n.id)), edges.filter((e) => set.has(e.from) && set.has(e.to)), big || 260, false);
    const P = g.map((id) => GR.pos.get(id));
    const x0 = Math.min(...P.map((p) => p.x)) - 60, y0 = Math.min(...P.map((p) => p.y)) - 60;
    return { g, x0, y0, w: Math.max(...P.map((p) => p.x)) + 60 - x0, h: Math.max(...P.map((p) => p.y)) + 60 - y0 };
  });
  const rowW = Math.max(900, Math.sqrt(boxes.reduce((a, b) => a + b.w * b.h, 0)) * 1.5);
  let x = 0, y = 0, rowH = 0;
  for (const b of boxes) {
    if (x > 0 && x + b.w > rowW) { x = 0; y += rowH; rowH = 0; }
    for (const id of b.g) { const p = GR.pos.get(id); p.x += x - b.x0; p.y += y - b.y0; }
    x += b.w; rowH = Math.max(rowH, b.h);
  }
}

const stageSize = () => [$('stage').clientWidth || 1200, $('stage').clientHeight || 700];
function applyView() {
  const v = GR.view;
  if (GR.vp) GR.vp.setAttribute('transform', 'translate(' + v.x + ' ' + v.y + ') scale(' + v.k + ')');
  fitLabels();
  placeFloats();
}
function fitView() {
  const P = [...GR.pos.values()], [W, H] = stageSize();
  if (!P.length) { GR.view = { x: W / 2, y: H / 2, k: 1 }; return applyView(); }
  const x0 = Math.min(...P.map((p) => p.x)), x1 = Math.max(...P.map((p) => p.x)), y0 = Math.min(...P.map((p) => p.y)), y1 = Math.max(...P.map((p) => p.y));
  const k = Math.max(0.15, Math.min(1.2, (W - 120) / (x1 - x0 + 160), (H - 120) / (y1 - y0 + 160)));   // leave room for the toolbar
  GR.view = { k, x: (W - 60) / 2 - (x0 + x1) / 2 * k, y: H / 2 - (y0 + y1) / 2 * k };
  GR.fitted = true;
  applyView();
}
function zoomBy(f, cx, cy) {
  const v = GR.view, [W, H] = stageSize(), k = Math.max(0.1, Math.min(4, v.k * f));
  cx = cx == null ? W / 2 : cx; cy = cy == null ? H / 2 : cy;
  GR.view = { k, x: cx - (cx - v.x) * k / v.k, y: cy - (cy - v.y) * k / v.k };
  applyView();
}
function centerOn(id) {
  const p = GR.pos.get(id), [W, H] = stageSize(), k = Math.max(GR.view.k, 0.9);
  if (!p) return;
  GR.view = { k, x: (W > 900 ? W / 2 - 230 : W / 2) - p.x * k, y: H / 2 - p.y * k };   // left of the side panel
  applyView();
}
/** Forget every position (and any pinned node) and lay the graph out again. */
function relayout() { relayoutSoon(); render(); }

/** Directed conversation path first, then ignoring direction; advisory links do not count as a path. */
function findPath(from, to) {
  const { edges } = graphModel();
  for (const directed of [true, false]) {
    const prev = new Map([[from, null]]), queue = [from];
    while (queue.length && !prev.has(to)) {
      const u = queue.shift();
      for (const e of edges) {
        if (e.kind === 'adv' || e.to.startsWith('grp:')) continue;            // a path through a broadcast address is no path
        const v = e.from === u ? e.to : !directed && e.to === u ? e.from : null;
        if (v && !prev.has(v)) { prev.set(v, { u, e: e.id }); queue.push(v); }
      }
    }
    if (prev.has(to)) {
      const nodes = [to], es = [];
      for (let c = to; prev.get(c); c = prev.get(c).u) { es.push(prev.get(c).e); nodes.unshift(prev.get(c).u); }
      return { nodes, edges: es };
    }
  }
  return null;
}

function nodeColor(n) {
  if (n.g) return '#5B6676';
  if (n.adv) return n.adv.kev ? LEVEL_COLOR.EXACT : LEVEL_COLOR.PROBABLE;
  return S.color === 'risk' ? LEVEL_COLOR[levelOf(n.a)] : '#AEB2B9';   // role is the glyph; colour is kept for advisory risk
}

function pickNode(id) {
  if (id.startsWith('grp:')) location.hash = '#/group/' + encodeURIComponent(id.slice(4));
  else if (id.startsWith('adv:')) { S.openAdv = id.slice(4); location.hash = '#/advisories'; } else toggleFloat(id);
}
function toggleFloat(id) {
  const i = S.floats.indexOf(id);
  if (i < 0) S.floats.push(id); else S.floats.splice(i, 1);
  if (route().name === 'asset' && route().arg === id) location.hash = '#/graph';   // floating the docked asset takes it off the dock
  renderFloats();
}
function renderFloats() {
  const host = $('floats'), keep = new Map([...host.querySelectorAll('.float')].map((e) => [e.dataset.id, e.querySelector('.float-body').scrollTop]));
  host.replaceChildren(...S.floats.filter((id) => byId(id)).map((id) => {
    const body = h('div', { class: 'float-body' }, ...[].concat(asset(id)).flat(Infinity));
    const el = h('div', { class: 'float', 'data-id': id, role: 'dialog', 'aria-label': 'Asset ' + id },
      h('div', { class: 'float-bar' },
        h('button', { type: 'button', class: 'float-dock', title: 'Dock beside the graph', 'aria-label': 'Dock ' + id + ' beside the graph', onclick: () => { S.floats = S.floats.filter((x) => x !== id); location.hash = '#/asset/' + encodeURIComponent(id); } }, '⇥'),
        h('button', { type: 'button', class: 'float-close', title: 'Close', 'aria-label': 'Close ' + id, onclick: () => toggleFloat(id) }, '×')), body);
    body.scrollTop = keep.get(id) || 0;
    return el;
  }));
  placeFloats();
}
function placeFloats() {
  const v = GR.view;
  for (const el of $('floats').children) {
    const p = GR.pos.get(el.dataset.id);
    el.hidden = !p;
    if (p) el.style.transform = 'translate(' + (p.x * v.k + v.x + (NODE_R + 10) * v.k) + 'px,' + (p.y * v.k + v.y - 24 * v.k) + 'px) scale(' + v.k + ')';
  }
}
function clickPathNode(id) {
  if (!S.pathPick) { pickNode(id); return; }
  if (id.startsWith('grp:') || id.startsWith('adv:')) { toast('Choose two asset nodes for a path'); return; }
  if (!S.pathStart) {
    S.pathStart = id; $('start').value = id; $('target').value = '';
    toast('Start pinned: ' + id + '. Click a target asset.'); render(); return;
  }
  const start = S.pathStart; S.pathStart = null; S.pathPick = false;
  $('btn-route').setAttribute('aria-pressed', 'false');
  $('start').value = start; $('target').value = id;
  S.path = findPath(start, id);
  if (!S.path) toast('No observed conversation path from ' + start + ' to ' + id);
  else toast('Path of ' + S.path.edges.length + (S.path.edges.length === 1 ? ' hop' : ' hops') + ' highlighted');
  if (location.hash !== '#/graph') location.hash = '#/graph'; else render();
}

/** A map-style pin above a node: lettered when it marks the path's start (A) or target (B), a ghost under the cursor while picking. */
function pin(letter, ghost) {
  if (ghost ? !!letter : !letter) return null;
  return sv('g', { class: 'pin' + (ghost ? ' ghost' : letter === 'A' ? ' a' : ' b'), transform: 'translate(0 ' + (-NODE_R - 4) + ')', 'pointer-events': 'none' },
    sv('path', { d: 'M0 0C-4 -6 -10 -11 -10 -18a10 10 0 0 1 20 0C10 -11 4 -6 0 0z' }), sv('circle', { cx: 0, cy: -18, r: 4 }),
    ghost ? null : sv('text', { y: -14.5, 'text-anchor': 'middle' }, letter));
}

function drawGraph() {
  const svg = $('graph'), model = graphModel(), { nodes, edges } = model;
  const ae = document.activeElement, keep = ae && ae.classList && ae.classList.contains('node') ? ae.dataset.id : null;
  const sig = nodes.map((n) => n.id).join(',') + '|' + edges.map((e) => e.id).join(',');
  if (sig !== GR.sig) { const first = GR.sig === ''; GR.sig = sig; layoutGraph(model, !first && GR.pos.size > 0); }
  if (!GR.fitted) fitView();
  const empty = $('graph-empty'), count = assets().length, matching = assets().filter(matches).length;
  const noMatch = count > 0 && matching === 0;
  empty.hidden = nodes.length > 0 && !noMatch;
  if (!empty.hidden) {
    $('graph-empty-text').textContent = !count ? 'No assets yet. Upload a PCAP or drop one here to start the inventory.'
      : noMatch ? 'No assets match the current search or filters.' : 'All assets are hidden by graph display filters.';
    $('graph-reset').hidden = count === 0;
  }

  const r = route(), sel = r.name === 'asset' ? r.arg : null, selEdge = r.name === 'edge' ? r.arg : null, byNode = (id) => (id.startsWith('adv:') || id.startsWith('grp:') ? id.slice(4) : nameOf(byId(id)) === id ? id : nameOf(byId(id)) + ' (' + id + ')');
  const near = new Set(sel ? [sel] : []);
  if (sel) edges.forEach((e) => { if (e.from === sel) near.add(e.to); if (e.to === sel) near.add(e.from); });
  if (selEdge) edges.forEach((e) => { if (e.key === selEdge) { near.add(e.from); near.add(e.to); } });
  const pathN = S.path && new Set(S.path.nodes), pathE = S.path && new Set(S.path.edges);
  const fa = filterActive(), good = new Set(assets().filter(matches).map((a) => a.id));
  const nodeOn = (n) => (pathN ? pathN.has(n.id) : sel || selEdge ? near.has(n.id) : fa ? (n.a ? good.has(n.id) : edges.some((e) => e.to === n.id && good.has(e.from))) : true);
  const on = new Set(nodes.filter(nodeOn).map((n) => n.id));

  // several edges between one pair fan out as arcs
  const pairs = new Map();
  for (const e of edges) { const k = e.from < e.to ? e.from + '\n' + e.to : e.to + '\n' + e.from; (pairs.get(k) || pairs.set(k, []).get(k)).push(e); }
  for (const g of pairs.values()) g.forEach((e, i) => { e.idx = i; e.cnt = g.length; });

  const marker = (id, color) => sv('marker', { id, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: 'userSpaceOnUse', orient: 'auto' }, sv('path', { d: 'M0 0L10 5L0 10z', fill: color }));
  const els = { nodes: new Map(), edges: [] };
  const edgeEls = edges.filter((e) => pathE ? pathE.has(e.id) : selEdge ? e.key === selEdge : sel ? e.from === sel || e.to === sel : true).map((e) => {   // a path, an open edge or an open node hides everything else; Back / Clear brings it back
    const flow = e.kind === 'flow', pk = flow ? protoKey(e.f.protocol) : '';
    const chosen = !!e.key && selEdge === e.key, hot = chosen || (pathE && pathE.has(e.id));
    const dim = !(on.has(e.from) && on.has(e.to)) || (pathE && !hot) || (sel && !(e.from === sel || e.to === sel)) || (selEdge && !chosen) || (flow && !(e.members || [e.f]).some(flowMatchesQuery));
    const path = sv('path', { class: 'epath', fill: 'none', 'stroke-width': flow ? 1.5 + Math.min(5, Math.log10(e.n + 1) * 1.6) : 1.5,
      stroke: flow && !hot ? PROTO_COLOR[pk] : null, 'marker-end': 'url(#arr-' + (hot ? 'hot' : flow ? 'p-' + pk : e.kind) + ')' });
    const hit = flow ? sv('path', { class: 'ehit', fill: 'none' }) : null;      // a wide invisible stroke: a 2 px line is hard to click
    const label = sv('text', { class: 'elabel', 'text-anchor': 'middle', 'paint-order': 'stroke' }, e.label);
    els.edges.push({ e, path, hit, label });
    const open = () => { if (GR.moved || GR.panned) { GR.moved = GR.panned = false; return; } location.hash = '#/edge/' + encodeURIComponent(e.key); };
    return sv('g', { class: 'edge ' + e.kind + (flow ? ' p-' + pk : '') + (dim ? ' dim' : '') + (hot ? ' hot' : '') + (flow && isScan(e.f) ? ' scan' : ''),
      role: flow ? 'button' : 'img', tabindex: flow ? '0' : null, 'data-key': flow ? e.key : null, 'aria-label': edgeLabel(e, byNode),
      onclick: flow ? open : null, onkeydown: flow ? (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } } : null },
      sv('title', {}, edgeLabel(e, byNode)), hit, path, label);
  });
  const pinA = S.path ? S.path.nodes[0] : S.pathStart, pinB = S.path ? S.path.nodes[S.path.nodes.length - 1] : null;
  const nodeEls = nodes.filter((n) => pathN ? pathN.has(n.id) : sel || selEdge ? near.has(n.id) : true).map((n) => {
    const a = n.a, dim = !on.has(n.id), kev = a ? !!(a.match && a.match.kevAtModel) : !!(n.adv && n.adv.kev);
    const name = n.adv ? n.adv.id : n.g ? n.g.address : nameOf(a), short = name.length > 22 ? name.slice(0, 21) + '…' : name;
    const g = sv('g', { class: 'node' + (dim ? ' dim' : '') + (n.id === sel ? ' sel' : '') + (n.adv ? ' adv' : '') + (n.g ? ' grp' : '') + (a && isSeenOnly(a) ? ' seen' : ''), tabindex: '0', role: 'button', 'data-id': n.id, 'aria-label': nodeLabel(n),
      onclick: () => { if (GR.moved) { GR.moved = false; return; } clickPathNode(n.id); },
      onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); clickPathNode(n.id); } },
      onpointerdown: (ev) => { if (ev.button) return; GR.moved = false; GR.drag = { id: n.id, x: ev.clientX, y: ev.clientY }; ev.stopPropagation(); } },
    sv('title', {}, nodeLabel(n)),
    pin(n.id === pinA ? 'A' : n.id === pinB ? 'B' : null),
    pin('', true),
    kev && !n.adv ? sv('circle', { class: 'ring-kev', r: NODE_R + 5 }) : null,
    sv('circle', { class: 'hit', r: NODE_R }),
    sv('path', { class: 'disc', d: n.adv ? ADV_ICON : n.g ? GROUP_ICON : ICONS[roleGroup(a)], transform: n.adv ? null : 'scale(1.35)', 'vector-effect': 'non-scaling-stroke', stroke: nodeColor(n) }),
    n.adv ? sv('path', { class: 'icon', d: 'M0 -6v8M0 6.5h.01', stroke: nodeColor(n) }) : null,
    a && isValidated(a) ? sv('g', { class: 'badge-ok', transform: 'translate(13 -13)' }, sv('circle', { r: 7 }), sv('path', { d: 'M-3.5 0l2.5 2.5 4.5-5' })) : null,
    sv('text', { class: 'nlabel', y: NODE_R + 5, 'text-anchor': 'middle', 'paint-order': 'stroke' }, short));
    els.nodes.set(n.id, g);
    return g;
  });
  GR.vp = sv('g', { id: 'viewport' }, sv('g', { class: 'edges' }, edgeEls), sv('g', { class: 'nodes' }, nodeEls));
  svg.replaceChildren(sv('defs', {}, ...Object.keys(PROTO_COLOR).map((k) => marker('arr-p-' + k, PROTO_COLOR[k])), marker('arr-flow', '#C5CCD6'), marker('arr-hot', '#2DD4BF'), marker('arr-unit', '#8793A5'), marker('arr-adv', '#F59E4B')),
    sv('rect', { class: 'bg', x: -50000, y: -50000, width: 100000, height: 100000, fill: 'transparent' }), GR.vp);
  GR.els = els;
  placeGraph();
  applyView();
  if (keep && els.nodes.get(keep)) els.nodes.get(keep).focus({ preventScroll: true });
}

/** Set every node and edge position from GR.pos (also called while dragging, so nothing is rebuilt mid-drag). */
function placeGraph() {
  if (!GR.els) return;
  for (const [id, g] of GR.els.nodes) { const p = GR.pos.get(id); g.setAttribute('transform', 'translate(' + p.x + ' ' + p.y + ')'); }
  placeFloats();
  for (const { e, path, hit, label } of GR.els.edges) {
    const a = GR.pos.get(e.from), b = GR.pos.get(e.to), dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, sgn = e.from < e.to ? 1 : -1;
    const off = (e.idx - (e.cnt - 1) / 2) * Math.min(120, 360 / Math.max(1, e.cnt - 1));   // control-point offset; the arc peaks at half of it; the whole fan stays within ±180 so a scanner's hundreds of ports are not a streak across the canvas
    const cx = (a.x + b.x) / 2 - dy / len * sgn * off, cy = (a.y + b.y) / 2 + dx / len * sgn * off;
    const d0 = Math.hypot(cx - a.x, cy - a.y) || 1, d1 = Math.hypot(b.x - cx, b.y - cy) || 1, r1 = NODE_R + (e.kind === 'adv' ? 9 : 5);
    const sx = a.x + (cx - a.x) / d0 * (NODE_R + 3), sy = a.y + (cy - a.y) / d0 * (NODE_R + 3), ex = b.x - (b.x - cx) / d1 * r1, ey = b.y - (b.y - cy) / d1 * r1;
    path.setAttribute('d', 'M' + sx + ' ' + sy + ' Q' + cx + ' ' + cy + ' ' + ex + ' ' + ey);
    if (hit) hit.setAttribute('d', path.getAttribute('d'));
    e.len = len;
    let ang = Math.atan2(ey - sy, ex - sx) * 180 / Math.PI;
    if (ang > 90 || ang < -90) ang += 180;                                 // keep the text upright
    label.setAttribute('transform', 'translate(' + (sx / 4 + cx / 2 + ex / 4) + ' ' + (sy / 4 + cy / 2 + ey / 4) + ') rotate(' + ang + ')');
  }
  fitLabels();
}

// Labels keep a minimum size ON SCREEN: below zoom 1 their font grows in graph units instead of shrinking with the view.
// Edge labels are dropped below EDGE_LABEL_ZOOM (they would overlap), node labels stay. An edge too short to carry its
// text loses the label too; the tooltip and the conversations table still have it.
const LABEL_PX = { node: 13, edge: 12 }, EDGE_LABEL_ZOOM = 0.55;
function fitLabels() {
  const svg = $('graph'), k = GR.view.k, nfs = Math.max(12, LABEL_PX.node / k), efs = Math.max(11, LABEL_PX.edge / k);
  svg.style.setProperty('--nfs', nfs + 'px');
  svg.style.setProperty('--efs', efs + 'px');
  svg.style.setProperty('--lsw', Math.max(4, 4 / k) + 'px');
  svg.classList.toggle('no-elabels', k < EDGE_LABEL_ZOOM);
  if (!GR.els) return;
  for (const { e, label } of GR.els.edges) {
    if ((e.len || 0) < e.label.length * 0.62 * efs + 40) label.setAttribute('display', 'none'); else label.removeAttribute('display');
  }
}

function initGraph() {
  const svg = $('graph'), stage = $('stage');
  const world = (ev) => { const r = svg.getBoundingClientRect(), v = GR.view; return { x: (ev.clientX - r.left - v.x) / v.k, y: (ev.clientY - r.top - v.y) / v.k }; };
  let pan = null;
  svg.addEventListener('pointerdown', (ev) => { if (!ev.button) { GR.panned = false; pan = { x: ev.clientX, y: ev.clientY, vx: GR.view.x, vy: GR.view.y }; svg.classList.add('panning'); } });
  window.addEventListener('pointermove', (ev) => {
    if (GR.drag) {
      if (Math.hypot(ev.clientX - GR.drag.x, ev.clientY - GR.drag.y) > 4) GR.moved = true;
      if (GR.moved) { const p = GR.pos.get(GR.drag.id), w = world(ev); if (p) { p.x = w.x; p.y = w.y; p.fixed = true; placeGraph(); } }
    } else if (pan) {
      if (Math.hypot(ev.clientX - pan.x, ev.clientY - pan.y) > 4) GR.panned = true;                       // a drag that ends over an edge is not a click on it
      GR.view.x = pan.vx + ev.clientX - pan.x; GR.view.y = pan.vy + ev.clientY - pan.y; applyView();
    }
  });
  window.addEventListener('pointerup', () => { GR.drag = null; pan = null; svg.classList.remove('panning'); });
  svg.addEventListener('wheel', (ev) => { ev.preventDefault(); const r = svg.getBoundingClientRect(); zoomBy(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX - r.left, ev.clientY - r.top); }, { passive: false });
  svg.addEventListener('keydown', (ev) => {
    const step = ev.target === svg && { ArrowLeft: [60, 0], ArrowRight: [-60, 0], ArrowUp: [0, 60], ArrowDown: [0, -60] }[ev.key];
    if (step) { GR.view.x += step[0]; GR.view.y += step[1]; applyView(); ev.preventDefault(); }
    else if (ev.key === '+' || ev.key === '=') zoomBy(1.25); else if (ev.key === '-') zoomBy(0.8); else if (ev.key === '0') fitView();
  });
  stage.addEventListener('dragover', (ev) => ev.preventDefault());
  stage.addEventListener('drop', (ev) => { ev.preventDefault(); upload([...ev.dataTransfer.files]); });
  $('z-in').addEventListener('click', () => zoomBy(1.25));
  $('z-out').addEventListener('click', () => zoomBy(0.8));
  $('z-fit').addEventListener('click', fitView);
}

// ------------------------------------------------------------------ routing, refresh

function route() {
  const [, name, arg] = (location.hash || '#/graph').match(/^#\/([a-z]+)\/?(.*)$/) || [, 'graph', ''];
  return { name, arg: decodeURIComponent(arg || '') };
}

// The side panel's width, draggable like a split screen; remembered per browser.
(function splitter() {
  const root = document.documentElement, KEY = 'reconics.panelWidth';
  const set = (w) => { w = Math.max(280, Math.min(w, Math.round(innerWidth * 0.75))); root.style.setProperty('--panel-w', w + 'px'); return w; };
  const save = (w) => { try { localStorage.setItem(KEY, String(w)); } catch (e) { /* not remembered */ } };
  try { const w = parseInt(localStorage.getItem(KEY), 10); if (w) set(w); } catch (e) { /* storage blocked: the default width applies */ }
  let raf = 0, drag = null;
  const redraw = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => drawGraph()); };
  // delegated on the document: the handle lives in index.html, which may not be parsed yet when this runs
  document.addEventListener('pointerdown', (ev) => { if (ev.target.id === 'split') { drag = ev.target; drag.setPointerCapture(ev.pointerId); } });
  document.addEventListener('pointermove', (ev) => { if (drag) { set(innerWidth - ev.clientX); redraw(); } });
  document.addEventListener('pointerup', () => { if (drag) { drag = null; save(parseInt(root.style.getPropertyValue('--panel-w'), 10) || 360); } });
  document.addEventListener('keydown', (e) => {
    if (e.target.id !== 'split' || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
    const w = set($('main').getBoundingClientRect().width + (e.key === 'ArrowLeft' ? 40 : -40));
    save(w); redraw(); e.preventDefault();
  });
})();

let lastRoute = '';
function render() {
  const r = route();
  if (!S.inv) return;
  if (r.name + r.arg !== lastRoute) { S.tab = 'attrs'; S.editing = false; lastRoute = r.name + r.arg; }
  chrome(r.name);
  saveView();
  const screens = { overview, inventory, data: dataScreen, export: dataScreen, engines: dataScreen, captures: dataScreen, index: dataScreen, log: dataScreen, settings: settingsScreen, review: findings, advisories: findings, findings, ethernet, asset: () => asset(r.arg), edge: () => edgePanel(r.arg), group: () => groupPanel(r.arg) };
  const main = $('main'), open = r.name !== 'graph', side = r.name === 'asset' || r.name === 'edge' || r.name === 'group';
  main.hidden = !open;
  main.className = side ? 'panel' : 'sheet';
  $('split').hidden = !side;
  $('stage').toggleAttribute('inert', open && !side);                         // a sheet covers the graph; the side panel does not
  main.replaceChildren(...(open ? [h('a', { class: 'close', href: '#/graph', 'aria-label': 'Close and return to the graph', title: 'Close' }, '×'),
    r.name === 'asset' ? h('button', { class: 'dock-btn', type: 'button', 'aria-label': 'Float the panel beside its node', title: 'Float beside the node', onclick: () => toggleFloat(r.arg) }, '⇱') : null,
    ...[].concat((screens[r.name] || overview)()).flat(Infinity)] : []).filter(Boolean));
  drawGraph();
  renderFloats();
}

// The page keeps itself current: captures queued by another process (the lab feed, curl) show up without a click.
// Polls every 3 s, every 1.5 s while a capture is queued or running, not at all in a hidden tab.
const POLL = { idle: 3000, busy: 1500 };
let pollTimer = null, lastSig = '';
function schedulePoll() {
  clearTimeout(pollTimer); pollTimer = null;
  if (document.hidden) return;
  const busy = S.caps.some((c) => c.state === 'queued' || c.state === 'running');
  pollTimer = setTimeout(() => refresh(true), busy ? POLL.busy : POLL.idle);
}
document.addEventListener('visibilitychange', () => { if (document.hidden) { clearTimeout(pollTimer); pollTimer = null; } else refresh(true); });

/** background: a poll, not a user action: stay silent on errors and leave the DOM alone when nothing changed (keeps focus and scroll). */
async function refresh(background) {
  try {
    await loadAll();
    $('load-error').hidden = true;
    if (S.floats.length || ['log', 'asset', 'review', 'findings'].includes(route().name)) S.changes = await api('GET', 'changes');
    if (route().name === 'engines') S.engines = await api('GET', 'engines').catch(() => S.engines || []);
  } catch (e) {
    if (background) { schedulePoll(); return; }
    if (!S.inv) { $('load-error-text').textContent = e.message; $('load-error').hidden = false; }
    else toast('Cannot reach the console: ' + e.message);
  }
  const sig = JSON.stringify([S.inv, S.rank, S.site, S.flows, S.groups, S.macs, S.images, S.imageSummary, S.caps, S.index, S.changes, S.engines]);
  if (!background || sig !== lastSig) { lastSig = sig; if (!S.editing) render(); else chrome(route().name); }
  schedulePoll();
}

/** Search panel, toolbar and popovers: one popover open at a time, Escape closes it (or the sheet). */
function initChrome() {
  const pops = [['btn-filter', 'pop-filter'], ['tb-info', 'pop-info']];
  const closeAll = (except) => {
    const closed = new Set();
    pops.forEach(([b, p]) => {
      if (p !== except && !closed.has(p)) { $(p).hidden = true; closed.add(p); }
      if (p !== except) $(b).setAttribute('aria-expanded', 'false');
    });
  };
  pops.forEach(([b, p]) => $(b).addEventListener('click', () => {
    const open = $(p).hidden; closeAll(p); $(p).hidden = !open;
    pops.filter(([, target]) => target === p).forEach(([button]) => $(button).setAttribute('aria-expanded', String(open)));
  }));
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if ($('tree').classList.contains('mobile-open')) { $('tree').classList.remove('mobile-open'); $('mobile-menu').setAttribute('aria-expanded', 'false'); return; }
    if (pops.some(([, p]) => !$(p).hidden)) closeAll();
    else if (S.pathPick) { S.pathPick = false; S.pathStart = null; $('btn-route').setAttribute('aria-pressed', 'false'); toast('Graph path selection cancelled'); }
    else if (route().name !== 'graph') location.hash = '#/graph';
  });
  $('btn-route').addEventListener('click', () => {
    S.pathPick = !S.pathPick; S.pathStart = null;
    $('btn-route').setAttribute('aria-pressed', String(S.pathPick));
    toast(S.pathPick ? 'Choose a start and target asset on the graph' : 'Graph path selection cancelled');
  });
  $('btn-route').setAttribute('aria-pressed', 'false');
  $('top-upload').addEventListener('click', () => $('import-pick').click());
  $('mobile-menu').addEventListener('click', () => {
    const open = !$('tree').classList.contains('mobile-open');
    $('tree').classList.toggle('mobile-open', open);
    $('mobile-menu').setAttribute('aria-expanded', String(open));
    $('mobile-menu').setAttribute('aria-label', open ? 'Close site navigation' : 'Open site navigation');
  });
  $('tree').addEventListener('click', (e) => {
    if (e.target.closest('a[href]') && $('tree').classList.contains('mobile-open')) {
      $('tree').classList.remove('mobile-open'); $('mobile-menu').setAttribute('aria-expanded', 'false');
      $('mobile-menu').setAttribute('aria-label', 'Open site navigation');
    }
  });
  $('search-hints').addEventListener('click', (e) => {
    const term = e.target.closest('[data-query]')?.dataset.query;
    if (!term) return;
    $('q').value = S.search = (S.search.trim() + ' ' + term).trim() + ' ';
    $('q').focus(); render();
  });
  document.querySelectorAll('#tree [data-level]').forEach((n) => n.addEventListener('click', (e) => {
    e.preventDefault(); S.purdueFilter = n.dataset.level; if (location.hash !== '#/graph') location.hash = '#/graph'; else render();
  }));
  $('tb-reset').addEventListener('click', resetView);
  $('import-pick').addEventListener('change', (e) => { upload([...e.target.files]); e.target.value = ''; });
  $('tb-layout').addEventListener('click', relayout);
  $('graph-reset').addEventListener('click', resetView);
  $('retry-load').addEventListener('click', () => refresh());
  $('tree').addEventListener('keydown', (e) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const rows = [...$('tree').querySelectorAll('.tree-row')].filter((n) => n.getClientRects().length || window.innerWidth > 760);
    const at = rows.indexOf(document.activeElement);
    if (at < 0) return;
    e.preventDefault();
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? rows.length - 1 : Math.max(0, Math.min(rows.length - 1, at + (e.key === 'ArrowDown' ? 1 : -1)));
    rows[next]?.focus();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const target = e.target;
    if (target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT|BUTTON)$/.test(target.tagName))) return;
    e.preventDefault(); $('q').focus();
  });
  const pick = (txt) => {                                                  // id, then name, then any substring, in fix-first order
    const t = txt.trim().toLowerCase(), all = S.rank.map(byId).filter(Boolean);
    if (!t) return null;
    return all.find((a) => a.id.toLowerCase() === t) || all.find((a) => nameOf(a).toLowerCase() === t)
      || all.find((a) => [a.id, nameOf(a), val(a, 'vendor'), val(a, 'model')].some((v) => v && str(v).toLowerCase().includes(t))) || null;
  };
  $('start').addEventListener('change', () => {
    const a = pick($('start').value);
    if (!$('start').value.trim()) return;
    if (!a) { toast('No asset matches "' + $('start').value.trim() + '"'); return; }
    $('start').value = a.id;
    location.hash = '#/asset/' + encodeURIComponent(a.id);
    centerOn(a.id);
  });
  const go = () => {
    const a = pick($('start').value), b = pick($('target').value);
    if (!a || !b) { toast('Pick a start and a target asset first'); return; }
    S.pathPick = false; S.pathStart = null; $('btn-route').setAttribute('aria-pressed', 'false');
    S.path = findPath(a.id, b.id);
    if (!S.path) toast('No observed conversation path from ' + nameOf(a) + ' to ' + nameOf(b));
    else toast('Path of ' + S.path.edges.length + (S.path.edges.length === 1 ? ' hop' : ' hops') + ' highlighted');
    if (location.hash !== '#/graph') location.hash = '#/graph'; else render();
  };
  $('btn-go').addEventListener('click', go);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  $('btn-back').addEventListener('click', () => { S.path = null; S.pathStart = null; S.pathPick = false; $('btn-route').setAttribute('aria-pressed', 'false'); $('start').value = ''; $('target').value = ''; if (location.hash !== '#/graph') location.hash = '#/graph'; else render(); });
}

function init() {
  $('q').addEventListener('input', (e) => { S.search = e.target.value; render(); });
  // The (i) tooltips are positioned on the page, not inside the panel, so a panel's scroll box or zoom cannot clip them.
  const tip = h('div', { id: 'tip', role: 'tooltip', hidden: true });
  document.body.append(tip);
  const showTip = (e) => {
    const t = e.target.closest && e.target.closest('.inf, .at.muted'), src = t && t.querySelector('.tip');
    tip.hidden = !src;
    if (!src) return;
    tip.textContent = src.textContent;
    const r = t.getBoundingClientRect(), w = tip.offsetWidth, ht = tip.offsetHeight;
    tip.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px';
    tip.style.top = (r.bottom + 6 + ht > innerHeight ? Math.max(8, r.top - ht - 6) : r.bottom + 6) + 'px';
  };
  document.addEventListener('mouseover', showTip);
  document.addEventListener('focusin', showTip);
  document.addEventListener('focusout', () => { tip.hidden = true; });
  initGraph();
  initChrome();
  window.addEventListener('hashchange', () => { refresh(); if (route().name === 'graph') $('graph').focus(); else $('main').focus(); });
  if (!store.get('actor')) toast('Enter your name in Settings: every edit is logged under it.');
  refresh();
}
document.addEventListener('DOMContentLoaded', init);
