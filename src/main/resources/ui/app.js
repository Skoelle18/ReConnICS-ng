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
const ATTRS_EXTRA = [['serial', 'Serial number', 'passive'], ['deviceType', 'Device type', 'passive']];
const IDENTITY_KEYS = ['vendor', 'model', 'os', 'serial', 'deviceType'];
const NO_IDENTITY = 'No identity message observed (needs Modbus FC43 / ENIP ListIdentity / S7 SZL)';
const EXTRA_HINT = { serial: 'Modbus FC43 object, ENIP ListIdentity serial, S7 SZL 0x0011.', deviceType: 'ENIP ListIdentity device type or S7 SZL 0x001C module type.' };
const LEVELS = ['EXACT', 'PROBABLE', 'POSSIBLE', 'NONE'];
const LEVEL_COLOR = { EXACT: '#FF6B61', PROBABLE: '#F59E4B', POSSIBLE: '#E8C84A', NONE: '#8793A5', UNRUN: '#6B7585' };
const ROLE_COLOR = { PLC: '#2DD4BF', Drive: '#4ADE80', 'Comms adapter': '#A78BFA', Network: '#60A5FA', Workstation: '#F5C542', Other: '#94A3B8', Unknown: '#6B7585' };
const PURDUE = [['3', 'Level 3', 'Site operations'], ['2', 'Level 2', 'Supervisory: HMI, EWS'], ['1', 'Level 1', 'Basic control: PLCs, adapters'],
  ['0', 'Level 0', 'Process: drives, I/O'], ['', 'Unplaced', 'Not enough identity yet']];
const LIFECYCLE = ['Acquisition', 'Deployment', 'Commissioning', 'In service', 'Maintenance', 'Decommissioned'];
// What a site field shows before anyone has set it. The edit form must compare against the same value,
// or saving an untouched form would log a change nobody made.
const SITE_DEFAULTS = { lifecycle: 'In service' };

const S = { inv: null, rank: [], site: {}, flows: [], caps: [], changes: [], index: null, search: '', level: 'ALL', kevOnly: false, unvalOnly: false,
  openCap: null, openAdv: null, tab: 'attrs', editing: false, staged: null,
  color: 'role', showAdv: true, layout: 'force', path: null,
  hideUnknown: false, hideScans: false, protoOff: new Set(),
  capAssets: {}, assetCaps: new Map(), capOff: new Set() };

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

function roleGroup(a) {
  const r = (str(val(a, 'role')) + ' ' + str(val(a, 'deviceType'))).toLowerCase();
  if (!r.trim()) return 'Unknown';
  if (/plc|controller|cpu|cip:0x0e/.test(r)) return 'PLC';
  if (/drive|cip:0x0?2\b|0x13|0x25/.test(r)) return 'Drive';
  if (/adapter|0x0c/.test(r)) return 'Comms adapter';
  if (/switch|gateway|router|dns server|dhcp server|ntp server|syslog server|vpn gateway/.test(r)) return 'Network';
  if (/hmi|workstation|ews|client|initiator/.test(r)) return 'Workstation';
  return 'Other';
}
function purdueOf(a) {
  if (siteOf(a).purdue) return siteOf(a).purdue;
  return { PLC: '1', 'Comms adapter': '1', Network: '1', Drive: '0', Workstation: '2' }[roleGroup(a)] || '';
}

// ------------------------------------------------------------------ flows (edges)

const PROTO_NAME = { modbus: 'Modbus', dnp3: 'DNP3', s7comm: 'S7', 'ethernet-ip': 'ENIP', snmp: 'SNMP', unknown: 'Unknown' };
// One colour per protocol on the graph; anything unnamed (including a service name Zeek made up) is grey like unknown.
const PROTO_COLOR = { modbus: '#38BDF8', dnp3: '#F472B6', 'ethernet-ip': '#A3E635', s7comm: '#FB923C', snmp: '#C084FC', unknown: '#7B8696' };
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
const filterActive = () => !!(S.search.trim() || S.level !== 'ALL' || S.kevOnly || S.unvalOnly);
/** The chips (level, KEV, not validated) and the query box together: the table hides what fails, the graph dims it. */
function matches(a) {
  const q = parseQuery(S.search), lv = levelOf(a), kev = !!(a.match && a.match.kevAtModel);
  const hay = [a.id, nameOf(a), val(a, 'vendor'), val(a, 'model'), val(a, 'mac'), val(a, 'hostname')].filter(Boolean).map((v) => str(v).toLowerCase());
  return (S.level === 'ALL' || lv === S.level) && (!S.kevOnly || kev) && (!S.unvalOnly || !isValidated(a))
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
  const low = all.filter((a) => ['vendor', 'model', 'role'].some((k) => a[k] && a[k].confidence === 'LOW'));
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
  S.capAssets = inv.captureAssets || {};
  S.assetCaps = new Map();
  Object.entries(S.capAssets).forEach(([id, ids]) => (ids || []).forEach((a) => {
    const list = S.assetCaps.get(a) || []; list.push(id); S.assetCaps.set(a, list);
  }));
}

// ------------------------------------------------------------------ chrome

function chrome(route) {
  document.querySelectorAll('[data-nav]').forEach((n) => n.classList.toggle('on', n.dataset.nav === route || ((route === 'asset' || route === 'edge') && n.dataset.nav === 'graph')));
  const active = S.caps.filter((c) => c.state === 'queued' || c.state === 'running').length;
  $('n-queue').textContent = active || '';
  $('n-review').textContent = reviewCount() || '';
  $('n-adv').textContent = advisoryRows().length || '';
  $('tb-queue').textContent = active || '';
  $('tb-review-n').textContent = reviewCount() || '';
  $('asset-list').replaceChildren(...S.rank.map(byId).filter(Boolean).slice(0, 500).map((a) => h('option', { value: a.id }, nameOf(a))));
  filterPanel();
  legendPanel();
  const ix = S.index || {};
  const badge = $('idx-badge');
  badge.className = 'badge ' + (!ix.verified ? 'bad' : ix.warning ? 'warn' : 'ok');
  badge.textContent = (ix.verified ? 'Index verified' : 'Index UNVERIFIED') + ' · ' + String(ix.generated || '?').slice(0, 10);
  const banner = $('banner');
  banner.replaceChildren();
  if (!ix.verified) banner.append(h('div', { class: 'banner bad' }, 'Advisory index is UNVERIFIED (no public key). An altered index can hide vulnerable devices.'));
  else if (ix.warning) banner.append(h('div', { class: 'banner warn' }, ix.warning));
}

/** Filter button: the match-level / KEV / validation filters and how the graph is drawn. */
function filterPanel() {
  const p = $('pop-filter');
  const had = [...p.querySelectorAll('button')].indexOf(document.activeElement);   // keep keyboard focus on the same chip after the rebuild
  const on = (label, is, fn) => h('button', { class: 'chip' + (is ? ' on' : ''), 'aria-pressed': String(is), onclick: () => { fn(); render(); } }, label);
  const group = (title, ...kids) => h('div', { class: 'stack', style: { gap: '6px' } }, h('div', { class: 'small strong' }, title), h('div', { class: 'row' }, kids));
  p.replaceChildren(
    group('Advisory match', ['ALL', ...LEVELS].map((l) => on(l === 'ALL' ? 'All levels' : l, S.level === l, () => { S.level = l; }))),
    group('Show only', on('KEV only', S.kevOnly, () => { S.kevOnly = !S.kevOnly; }), on('Not validated', S.unvalOnly, () => { S.unvalOnly = !S.unvalOnly; })),
    group('Show conversations', on('Unknown protocol', !S.hideUnknown, () => { S.hideUnknown = !S.hideUnknown; }), on('Scan attempts', !S.hideScans, () => { S.hideScans = !S.hideScans; })),
    group('Protocols', Object.keys(PROTO_COLOR).filter((k) => k !== 'unknown').map((k) => h('label', { class: 'chip proto' + (S.protoOff.has(k) ? '' : ' on'), style: { borderLeft: '4px solid ' + PROTO_COLOR[k] } },
      h('input', { type: 'checkbox', class: 'sr', checked: S.protoOff.has(k) ? null : true, 'aria-label': 'Show ' + protoName(k) + ' conversations',
        onchange: () => { if (S.protoOff.has(k)) S.protoOff.delete(k); else S.protoOff.add(k); render(); } }), protoName(k)))),
    group('Colour nodes by', on('Role', S.color === 'role', () => { S.color = 'role'; }), on('Advisory risk', S.color === 'risk', () => { S.color = 'risk'; })),
    group('Advisories on the graph', on(S.showAdv ? 'Shown (EXACT, PROBABLE)' : 'Hidden', S.showAdv, () => { S.showAdv = !S.showAdv; })),
    group('Layout', on('Force', S.layout === 'force', () => { S.layout = 'force'; relayoutSoon(); }), on('Purdue levels', S.layout === 'purdue', () => { S.layout = 'purdue'; relayoutSoon(); })),
    doneCaps().length ? group('Captures on the graph', doneCaps().map((c) => on(c.file, !S.capOff.has(c.id), () => toggleCapture(c.id))))
      : group('Captures on the graph', h('span', { class: 'muted small' }, 'No merged captures yet')),
    h('div', { class: 'row' }, h('button', { class: 'btn sm', onclick: resetView }, 'Reset view')),
    h('div', { class: 'muted small' }, 'Filters dim the non-matching assets and conversations on the graph. Capture buttons hide or show everything that capture contributed.'));
  if (had >= 0) p.querySelectorAll('button')[had].focus();
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
  S.search = ''; S.level = 'ALL'; S.kevOnly = false; S.unvalOnly = false;
  S.hideUnknown = false; S.hideScans = false; S.protoOff = new Set(); S.capOff = new Set();
  S.color = 'role'; S.showAdv = true; S.layout = 'force'; S.path = null; S.openCap = null; S.openAdv = null;
  $('q').value = ''; $('start').value = ''; $('target').value = '';
  lastRoute = '';
  if (location.hash && location.hash !== '#/graph') location.hash = '#/graph';
  else { relayoutSoon(); render(); }
}

function legendPanel() {
  const sw = (c, t) => h('span', { class: 'row legend' }, h('span', { class: 'dot', style: { background: c } }), t);
  const ix = S.index || {};
  $('pop-info').replaceChildren(
    h('div', { class: 'strong' }, S.color === 'risk' ? 'Node colour: advisory match' : 'Node colour: role'),
    h('div', { class: 'stack', style: { gap: '4px' } }, S.color === 'risk' ? [...LEVELS, 'UNRUN'].map((l) => sw(LEVEL_COLOR[l], l === 'UNRUN' ? 'NOT RUN' : l)) : Object.keys(ROLE_COLOR).map((g) => sw(ROLE_COLOR[g], g))),
    h('div', { class: 'strong' }, 'Edge colour: protocol'),
    h('div', { class: 'stack', style: { gap: '4px' } }, Object.keys(PROTO_COLOR).map((k) => sw(PROTO_COLOR[k], protoName(k) + (k === 'unknown' ? ' (carried, not decoded)' : '')))),
    h('div', { class: 'small' }, 'Red ring: KEV-listed advisory at model. Check badge: validated. Triangle: advisory (red when KEV-listed). Dashed grey edge: unit or slot behind a gateway.'),
    h('div', { class: 'small' }, 'Arrows run client to server and are labelled with the message kind seen (Modbus FC43/14, ListIdentity, S7 SZL). Thicker means more messages. Click an edge for its operations, rate and times. Unknown edges are host pairs that were counted, not decoded.'),
    h('div', { class: 'small muted' }, 'Keyboard: Tab to a node, Enter opens it. On the graph: arrows pan, + and - zoom, 0 fits.'),
    h('div', { class: 'small' }, 'Advisory index: ' + (ix.verified ? 'signature verified' : 'UNVERIFIED') + ', generated ' + fmtTime(ix.generated) + ', KEV ' + (ix.kevCatalogVersion || '?') + '.'));
}

// ------------------------------------------------------------------ screens

function overview() {
  const all = assets(), sum = S.inv.summary || {}, n = all.length || 1;
  const kev = all.filter((a) => a.match && a.match.kevAtModel).length;
  const lv = Object.fromEntries(LEVELS.map((l) => [l, all.filter((a) => levelOf(a) === l).length]));
  const done = S.caps.filter((c) => c.state === 'done');
  const last = done[done.length - 1];
  const groups = Object.keys(ROLE_COLOR).map((g) => ({ g, n: all.filter((a) => roleGroup(a) === g).length })).filter((x) => x.n);
  const ranked = S.rank.map(byId).filter(Boolean);
  return [
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

function captures() {
  const pick = h('input', { type: 'file', multiple: true, accept: '.pcap,.pcapng,.cap', class: 'sr', id: 'pick', onchange: (e) => upload([...e.target.files]) });
  const drop = h('div', { class: 'drop', ondragover: (e) => { e.preventDefault(); drop.classList.add('over'); }, ondragleave: () => drop.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); drop.classList.remove('over'); upload([...e.dataTransfer.files]); } },
    h('div', {}, h('div', { class: 'strong' }, 'Drop capture files here'),
      h('div', { class: 'muted small' }, 'Classic PCAP or pcapng. Each file is hashed while it streams to disk; the same file twice is refused.')),
    pick, h('label', { for: 'pick', class: 'btn pri', tabindex: '0' }, 'Add PCAPs'));
  const c = S.caps.find((x) => x.id === S.openCap);
  const stateTxt = { done: 'Merged', running: 'Analyzing', queued: 'Queued', failed: 'Failed' };
  return [
    h('div', {}, h('h1', {}, 'Capture queue'), h('div', { class: 'muted' }, 'Captures run one at a time, in order, and merge into the site inventory. Nothing is sent to the plant.')),
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
    h('div', { class: 'row' }, h('a', { class: 'btn sm', href: '#/graph' }, '‹ Graph')),
    h('div', { class: 'card' },
      h('div', { class: 'card-b head', style: { alignItems: 'flex-start' } },
        h('div', { class: 'stack', style: { gap: '6px' } },
          h('div', { class: 'row' }, h('h1', {}, nameOf(a)), levelBadge(levelOf(a)), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV at model') : null,
            h('span', { class: 'badge ' + (isValidated(a) ? 'ok' : 'lv-NONE') }, isValidated(a) ? 'Validated' : 'Pending validation')),
          h('div', { class: 'mono muted' }, a.id + ' · ' + (str(val(a, 'mac')) || 'no MAC (sub-unit or routed)')),
          a.subaddr ? h('div', { class: 'small muted' }, 'Sub-unit ' + a.subaddr + '. Inherits IP, protocols and ports from its parent.') : null,
          h('div', { class: 'small row' }, h('span', { class: 'muted' }, 'Seen in:'), capturesOf(a).length
            ? capturesOf(a).map((cid) => h('button', { class: 'btn sm', title: 'Show only this capture on the graph', onclick: () => focusCapture(cid) }, capFileName(cid)))
            : h('span', { class: 'muted' }, 'no capture provenance')),
          a.match && a.match.matchedAs ? h('div', { class: 'small muted' }, 'Matched as ' + a.match.matchedAs + ' (from the Siemens order number).') : null),
        h('div', { class: 'row', style: { gap: '20px' } },
          fact('Completeness', c.filled + ' / 14'), h('div', {}, h('div', { class: 'muted small' }, 'Match ceiling'), levelBadge(c.matchCeiling)),
          fact('Lifecycle', site.lifecycle || 'In service'))),
      c.nextStep ? h('div', { class: 'note' }, h('strong', {}, 'Next step to raise the match: '), c.nextStep) : null,
      h('div', { class: 'tabs' }, tab('attrs', 'Attributes'), tab('advs', 'Advisories (' + advs.length + ')'), tab('conv', 'Conversations (' + convs.length + ')'), tab('hist', 'History (' + hist.length + ')'))),
    S.tab === 'attrs' ? attrsCard(a, site, role) : S.tab === 'conv' ? convCard(convs, a.id) : S.tab === 'advs' ? h('div', { class: 'card' },
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

/** Observed conversations of one asset (the graph's edges touching it), with the message kinds as evidence. */
const convsOf = (a) => graphModel().edges.filter((e) => e.kind === 'flow' && (e.from === a.id || e.to === a.id));
function convCard(convs, id) {
  return h('div', { class: 'card' }, convs.length ? convs.map((e) => {
    const out = e.from === id, peer = byId(out ? e.to : e.from);
    return h('div', { class: 'card-b stack', style: { gap: '6px', borderBottom: '1px solid var(--line2)' } },
      h('div', { class: 'row' }, h('span', { class: 'badge lv-NONE' }, out ? 'to' : 'from'), h('a', { class: 'strong', href: '#/asset/' + encodeURIComponent(peer.id) }, nameOf(peer)),
        h('span', { class: 'mono small muted' }, peer.id), h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + protoColor(e.f.protocol) } }, e.f.protocol + ' ' + e.f.port + (e.f.portHint ? ' (' + e.f.portHint + '?)' : '')),
        h('span', { class: 'small muted' }, e.n + (e.n === 1 ? ' message' : ' messages') + ' · ' + fmtRate(flowRate(e.f))),
        h('a', { class: 'btn sm', href: '#/edge/' + encodeURIComponent(e.key) }, 'Details')),
      h('div', { class: 'small' }, Object.entries(e.f.labels || {}).map(([k, n]) => k + ' ×' + n).join(' · ') || 'no message kinds recorded'),
      (e.f.operations || []).length ? h('div', { class: 'small muted' }, 'Operations: ' + opsSummary(e.f, 3) + ((e.f.operations || []).length > 3 ? ' · +' + (e.f.operations.length - 3) + ' more' : '')) : null);
  }) : h('div', { class: 'empty' }, 'No conversation seen for this asset yet. Edges come from decoded Modbus, DNP3, EtherNet/IP, S7comm and SNMP messages, and from TCP/UDP host pairs the analyzer could not decode (shown as unknown).'));
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
          h('span', { class: 'small wrap' }, o.function, o.object ? h('span', { class: 'mono muted' }, ' ' + o.object) : null),
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
  return [
    h('div', { class: 'row' }, back),
    h('div', { class: 'card' },
      h('div', { class: 'card-b stack', style: { gap: '8px' } },
        h('h1', {}, endLink(f.client), ' → ', endLink(f.server)),
        h('div', { class: 'row' },
          h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + PROTO_COLOR[pk] } }, pair ? pair.label : protoName(f.protocol)),
          pair ? null : h('span', { class: 'mono small' }, f.port || ''), f.transport && !String(f.port || '').includes('/') ? h('span', { class: 'mono small' }, f.transport) : null,
          f.source ? h('span', { class: 'badge lv-NONE', title: 'which engine produced this conversation' }, f.source) : null,
          isScan(f) ? h('span', { class: 'badge warn' }, 'scan attempts only') : null),
        pair ? h('div', { class: 'small muted' }, 'A busy host pair drawn as one edge: the counters and kinds below add up its ' + pair.members.length + ' conversations, which are listed under them.')
          : pk === 'unknown' ? h('div', { class: 'small muted' }, 'Carried but not decoded: the host pair and port are known, the protocol is not. Messages count data packets.' + (f.portHint ? ' Port ' + f.port + ' is usually ' + f.portHint + ' (a hint from the port number only, not decoded).' : '')) : null),
      h('div', { class: 'card-b facts' },
        fact('Messages', (f.messages || 0).toLocaleString()), pair ? null : fact('Rate', fmtRate(rate)),
        f.packets != null ? fact('Packets', f.packets.toLocaleString()) : null, f.bytes != null ? fact('Bytes', fmtBytes(f.bytes)) : null,
        f.firstSeen ? fact('First seen', fmtStamp(f.firstSeen)) : null, f.lastSeen ? fact('Last seen', fmtStamp(f.lastSeen)) : null,
        fmtSpan(f) ? fact('Span', fmtSpan(f)) : null, f.scanAttempts ? fact('Scan attempts', f.scanAttempts.toLocaleString()) : null)),
    ...kindsAndOps(f),
    pair ? h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Conversations (' + pair.members.length + ')'),
      pair.members.slice().sort((a, b) => (b.messages || 0) - (a.messages || 0)).map((m) => h('div', { class: 'card-b stack', style: { gap: '4px', borderBottom: '1px solid var(--line2)' } },
        h('div', { class: 'row' }, h('span', { class: 'badge c-LOW', style: { borderLeft: '4px solid ' + protoColor(m.protocol) } }, m.protocol + ' ' + m.port),
          h('span', { class: 'small muted' }, (m.messages || 0) + ' messages · ' + fmtRate(flowRate(m))), h('a', { class: 'btn sm', href: '#/edge/' + encodeURIComponent(flowKey(m)) }, 'Details')),
        h('div', { class: 'small' }, Object.entries(m.labels || {}).map(([k, n]) => k + ' ×' + n).join(' · ') || 'no message kinds recorded')))) : null,
  ].filter(Boolean);
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
    role !== 'validator' ? h('div', { class: 'small muted strip-note' }, 'Only a validator can mark an asset validated. Change Role in Settings (the sliders button).') : null,
    h('div', { class: 'scroll' },
      h('div', { class: 'g-attr thead' }, ['Attribute', 'Value', 'Confidence', 'Evidence / how to fill'].map((t) => h('span', {}, t))),
      ATTRS.concat(ATTRS_EXTRA).map(([k, label, by]) => {
        const f = fieldVal(k), person = f && /^entered by /.test(f.evidence || '');
        return h('div', { class: 'g-attr' },
          h('span', { class: 'strong' }, label, h('span', { class: 'muted small', style: { display: 'block', fontWeight: '400' } }, by === 'human' ? 'filled by people' : 'from passive capture')),
          h('span', { class: 'wrap' + (f ? '' : ' muted') }, f ? str(f.value) : noIdentity && IDENTITY_KEYS.includes(k) ? NO_IDENTITY : 'Not filled'),
          h('span', { class: 'stack', style: { gap: '4px', alignItems: 'flex-start' } },
            f ? h('span', { class: 'badge c-' + (person ? 'PERSON' : f.confidence) }, person ? 'PERSON' : f.confidence) : null,
            f && f.conflict ? h('span', { class: 'badge warn' }, 'conflict') : null, f && f.inherited ? h('span', { class: 'badge lv-NONE' }, 'inherited') : null),
          h('span', { class: 'small' + (f ? ' mono' : ' muted') }, f ? f.evidence : (missing[k] ? missing[k].hint : EXTRA_HINT[k] || '')));
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
  const groups = reviewGroups();
  return [
    h('div', {}, h('h1', {}, 'Review queue'), h('div', { class: 'muted' }, 'Cross-check collected data before an owner validates it (CISA: assign roles for collection and validation).')),
    groups.length === 0 ? h('div', { class: 'card empty' }, 'Nothing to review.') : groups.map((g) => h('div', { class: 'card' },
      h('div', { class: 'card-h' }, g.title, h('span', { class: 'badge lv-NONE' }, g.items.length)),
      g.items.map(([a, why]) => h('a', { class: 'rv', href: '#/asset/' + encodeURIComponent(a.id) }, dot(g.color),
        h('span', { style: { flex: '1', minWidth: '0' } }, h('span', { class: 'cell-name' }, nameOf(a), ' ', h('span', { class: 'mono small muted' }, a.id)), h('span', { class: 'small muted' }, why)),
        h('span', { class: 'btn sm' }, 'Open'))))),
  ];
}

function advisories() {
  const rows = advisoryRows();
  return [
    h('div', {}, h('h1', {}, 'Matched advisories'), h('div', { class: 'muted' }, 'CISA CSAF ICS advisories that hit at least one asset. KEV-listed first, then CVSS.')),
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-adv' }, ['Advisory', 'Title', 'CVSS', 'KEV', 'Assets'].map((t) => h('span', {}, t))),
      rows.length === 0 ? h('div', { class: 'empty' }, 'No advisory matches any asset in this index.') : rows.map((r) => [
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
    h('div', {}, h('h1', {}, 'Advisory index'), h('div', { class: 'muted' }, 'Built on the online side from CISA CSAF OT + KEV, signed, and carried across the air gap.')),
    h('div', { class: 'facts' },
      h('div', { class: 'card card-b' }, fact('Generated', fmtTime(ix.generated)), ix.warning ? h('span', { class: 'badge warn' }, 'stale') : h('span', { class: 'badge ok' }, 'current')),
      h('div', { class: 'card card-b' }, fact('KEV catalog', ix.kevCatalogVersion || '?')),
      h('div', { class: 'card card-b' }, fact('Advisories / rows', (ix.advisories || 0).toLocaleString() + ' / ' + (ix.rows || 0).toLocaleString())),
      h('div', { class: 'card card-b' }, fact('Signature', ix.verified ? 'Ed25519 verified' : 'UNVERIFIED'))),
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

function log() {
  return [
    h('div', {}, h('h1', {}, 'Change log'), h('div', { class: 'muted' }, 'Append-only. Every capture merge, human edit and index swap, newest first.')),
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-log' }, ['When', 'Who', 'Asset', 'Field', 'Change', 'Source'].map((t) => h('span', {}, t))),
      S.changes.length === 0 ? h('div', { class: 'empty' }, 'No changes yet.') : S.changes.map((x) => h('div', { class: 'trow g-log' },
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
const ICONS = {   // 24x24 line icons, drawn dark on the bright node colour
  PLC: 'M5 6h14v12H5z M9 10h6 M9 14h6', Workstation: 'M3 5h18v11H3z M8 20h8 M12 16v4', Network: 'M12 4v16 M4 12h16 M12 4l-3 3 M12 4l3 3 M12 20l-3-3 M12 20l3-3 M4 12l3-3 M4 12l3 3 M20 12l-3-3 M20 12l-3 3',
  Drive: 'M12 8a4 4 0 1 0 .01 0 M3 12h3 M18 12h3', 'Comms adapter': 'M4 12h16 M8 8l-4 4 4 4 M16 8l4 4-4 4',
  Other: 'M6 6h12v12H6z', Unknown: 'M9 9a3 3 0 1 1 4.5 2.6c-1 .6-1.5 1.1-1.5 2.4 M12 17.5h.01',
};
const GR = { pos: new Map(), view: { x: 0, y: 0, k: 1 }, fitted: false, sig: '', vp: null, els: null, drag: null, moved: false };

/** "ListIdentity" -> "ENIP ListIdentity"; the top message kind of a conversation, "+n" when there are more. */
function flowLabel(f) {
  const kinds = Object.entries(f.labels || {}).sort((a, b) => b[1] - a[1]).map((x) => x[0]);
  if (isScan(f)) return 'scan ×' + f.scanAttempts;
  if (!kinds.length) return protoKey(f.protocol) === 'unknown' ? (f.port ? f.port + (f.portHint ? ' ' + f.portHint + '?' : '') : 'unknown') : protoName(f.protocol);
  const pre = protoName(f.protocol);
  const top = /^(Modbus|DNP3|SNMP|S7|EtherNet\/IP|CIP)/.test(kinds[0]) ? kinds[0] : pre + ' ' + kinds[0];
  return top + (kinds.length > 1 ? ' +' + (kinds.length - 1) : '');
}

function graphModel() {
  const all = assets().filter(assetVisible), nodes = all.map((a) => ({ id: a.id, a })), edges = [];
  const ipOf = (a) => str(val(a, 'ip')) || a.id.split('/')[0];
  const owner = new Map();                                              // IP -> the asset that owns it (a unit/slot only when nothing else does)
  for (const a of all) if (!a.subaddr) owner.set(ipOf(a), a.id);
  for (const a of all) if (a.subaddr && !owner.has(ipOf(a))) owner.set(ipOf(a), a.id);
  for (const a of all) if (a.subaddr && owner.get(ipOf(a)) !== a.id) edges.push({ id: 'u:' + a.id, kind: 'unit', from: owner.get(ipOf(a)), to: a.id, label: a.subaddr });
  const byPair = new Map();                                             // from>to -> its flows; a busy pair becomes one edge, not one per port
  S.flows.forEach((f, i) => {
    const from = owner.get(f.client), to = owner.get(f.server);
    if (!(from && to && from !== to) || flowHidden(f)) return;
    const k = from + '\n' + to;
    (byPair.get(k) || byPair.set(k, []).get(k)).push({ f, i, from, to });
  });
  for (const g of byPair.values()) {
    if (g.length <= MERGE_AT) { for (const { f, i, from, to } of g) edges.push({ id: 'f' + i, key: flowKey(f), kind: 'flow', from, to, f, n: f.messages || 0, label: flowLabel(f) }); continue; }
    const fs = g.map((x) => x.f), labels = {}, byProto = {};
    for (const f of fs) { for (const [k, c] of Object.entries(f.labels || {})) labels[k] = (labels[k] || 0) + c; byProto[f.protocol] = (byProto[f.protocol] || 0) + (f.messages || 0) + 1; }
    const top = Object.keys(byProto).sort((a, b) => byProto[b] - byProto[a])[0], n = fs.reduce((a, f) => a + (f.messages || 0), 0), scans = fs.reduce((a, f) => a + (f.scanAttempts || 0), 0);
    const f = { client: fs[0].client, server: fs[0].server, protocol: top, port: fs.length + ' ports', labels, messages: n, scanAttempts: scans, operations: fs.flatMap((x) => x.operations || []) };   // synthetic: what the drawing and the cards read
    edges.push({ id: 'm' + g[0].i, key: pairKey(g[0].from, g[0].to), kind: 'flow', from: g[0].from, to: g[0].to, f, n, members: fs, label: fs.length + ' conversations' });
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
        if (e.kind === 'adv') continue;
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
  if (n.adv) return n.adv.kev ? LEVEL_COLOR.EXACT : LEVEL_COLOR.PROBABLE;
  return S.color === 'risk' ? LEVEL_COLOR[levelOf(n.a)] : ROLE_COLOR[roleGroup(n.a)];
}

function pickNode(id) {
  if (id.startsWith('adv:')) { S.openAdv = id.slice(4); location.hash = '#/advisories'; } else location.hash = '#/asset/' + encodeURIComponent(id);
}

function drawGraph() {
  const svg = $('graph'), model = graphModel(), { nodes, edges } = model;
  const ae = document.activeElement, keep = ae && ae.classList && ae.classList.contains('node') ? ae.dataset.id : null;
  const sig = nodes.map((n) => n.id).join(',') + '|' + edges.map((e) => e.id).join(',');
  if (sig !== GR.sig) { const first = GR.sig === ''; GR.sig = sig; layoutGraph(model, !first && GR.pos.size > 0); }
  if (!GR.fitted) fitView();
  $('graph-empty').hidden = nodes.length > 0;

  const r = route(), sel = r.name === 'asset' ? r.arg : null, selEdge = r.name === 'edge' ? r.arg : null, byNode = (id) => (id.startsWith('adv:') ? id.slice(4) : nameOf(byId(id)) === id ? id : nameOf(byId(id)) + ' (' + id + ')');
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
  const edgeEls = edges.map((e) => {
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
  const nodeEls = nodes.map((n) => {
    const a = n.a, dim = !on.has(n.id), kev = n.adv ? n.adv.kev : !!(a.match && a.match.kevAtModel);
    const name = n.adv ? n.adv.id : nameOf(a), short = name.length > 22 ? name.slice(0, 21) + '…' : name;
    const g = sv('g', { class: 'node' + (dim ? ' dim' : '') + (n.id === sel ? ' sel' : '') + (n.adv ? ' adv' : ''), tabindex: '0', role: 'button', 'data-id': n.id, 'aria-label': nodeLabel(n),
      onclick: () => { if (GR.moved) { GR.moved = false; return; } pickNode(n.id); },
      onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pickNode(n.id); } },
      onpointerdown: (ev) => { if (ev.button) return; GR.moved = false; GR.drag = { id: n.id, x: ev.clientX, y: ev.clientY }; ev.stopPropagation(); } },
    sv('title', {}, nodeLabel(n)),
    kev && !n.adv ? sv('circle', { class: 'ring-kev', r: NODE_R + 5 }) : null,
    n.adv ? sv('path', { class: 'disc', d: 'M0 -21 L19 13 L-19 13 Z', fill: nodeColor(n) }) : sv('circle', { class: 'disc', r: NODE_R, fill: nodeColor(n) }),
    sv('path', { class: 'icon', d: n.adv ? 'M0 -6v8M0 6.5h.01' : ICONS[roleGroup(a)], transform: n.adv ? null : 'translate(-9 -9) scale(.75)' }),
    !n.adv && isValidated(a) ? sv('g', { class: 'badge-ok', transform: 'translate(13 -13)' }, sv('circle', { r: 7 }), sv('path', { d: 'M-3.5 0l2.5 2.5 4.5-5' })) : null,
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
  return { name: name === 'inventory' ? 'graph' : name, arg: decodeURIComponent(arg || '') };   // the row table is gone; old bookmarks open the graph
}

let lastRoute = '';
function render() {
  const r = route();
  if (!S.inv) return;
  if (r.name + r.arg !== lastRoute) { S.tab = 'attrs'; S.editing = false; lastRoute = r.name + r.arg; }
  chrome(r.name);
  const screens = { overview, captures, review, advisories, index: indexScreen, log, asset: () => asset(r.arg), edge: () => edgePanel(r.arg) };
  const main = $('main'), open = r.name !== 'graph', side = r.name === 'asset' || r.name === 'edge';
  main.hidden = !open;
  main.className = side ? 'panel' : 'sheet';
  $('stage').toggleAttribute('inert', open && !side);                         // a sheet covers the graph; the side panel does not
  main.replaceChildren(...(open ? [side ? null : h('a', { class: 'close', href: '#/graph', 'aria-label': 'Close and return to the graph', title: 'Close' }, '×'),
    ...[].concat((screens[r.name] || overview)()).flat(Infinity)] : []).filter(Boolean));
  drawGraph();
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
    if (route().name === 'log' || route().name === 'asset') S.changes = await api('GET', 'changes');
  } catch (e) { if (background) { schedulePoll(); return; } toast('Cannot reach the console: ' + e.message); }
  const sig = JSON.stringify([S.inv, S.rank, S.site, S.flows, S.caps, S.index, S.changes]);
  if (!background || sig !== lastSig) { lastSig = sig; if (!S.editing) render(); else chrome(route().name); }
  schedulePoll();
}

/** Search panel, toolbar and popovers: one popover open at a time, Escape closes it (or the sheet). */
function initChrome() {
  const pops = [['menu-btn', 'nav'], ['btn-filter', 'pop-filter'], ['tb-export', 'pop-export'], ['tb-settings', 'pop-settings'], ['tb-info', 'pop-info']];
  const closeAll = (except) => pops.forEach(([b, p]) => { if (p !== except) { $(p).hidden = true; $(b).setAttribute('aria-expanded', 'false'); } });
  pops.forEach(([b, p]) => $(b).addEventListener('click', () => { const open = $(p).hidden; closeAll(p); $(p).hidden = !open; $(b).setAttribute('aria-expanded', String(open)); }));
  $('nav').addEventListener('click', () => closeAll());
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (pops.some(([, p]) => !$(p).hidden)) closeAll(); else if (route().name !== 'graph') location.hash = '#/graph';
  });
  $('rawq-btn').addEventListener('click', () => { const open = $('rawq-body').hidden; $('rawq-body').hidden = !open; $('rawq-btn').setAttribute('aria-expanded', String(open)); if (open) $('q').focus(); });
  $('btn-route').addEventListener('click', () => { const open = $('row-target').hidden; $('row-target').hidden = !open; $('btn-route').setAttribute('aria-expanded', String(open)); });
  $('tb-refresh').addEventListener('click', () => refresh());
  $('tb-import').addEventListener('click', () => $('import-pick').click());
  $('import-pick').addEventListener('change', (e) => { upload([...e.target.files]); e.target.value = ''; });
  $('tb-layout').addEventListener('click', relayout);
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
    S.path = findPath(a.id, b.id);
    if (!S.path) toast('No observed conversation path from ' + nameOf(a) + ' to ' + nameOf(b));
    else toast('Path of ' + S.path.edges.length + (S.path.edges.length === 1 ? ' hop' : ' hops') + ' highlighted');
    if (location.hash !== '#/graph') location.hash = '#/graph'; else render();
  };
  $('btn-go').addEventListener('click', go);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  $('btn-back').addEventListener('click', () => { S.path = null; $('start').value = ''; $('target').value = ''; if (location.hash !== '#/graph') location.hash = '#/graph'; else render(); });
}

function init() {
  const actor = $('actor'), roleSel = $('role');
  actor.value = store.get('actor');
  roleSel.value = store.get('role') || 'collector';
  actor.addEventListener('change', () => store.set('actor', actor.value.trim()));
  roleSel.addEventListener('change', () => { store.set('role', roleSel.value); render(); });
  $('q').addEventListener('input', (e) => { S.search = e.target.value; render(); });
  initGraph();
  initChrome();
  window.addEventListener('hashchange', () => { refresh(); if (route().name === 'graph') $('graph').focus(); else $('main').focus(); });
  if (!store.get('actor')) toast('Enter your name in Settings (the sliders button): every edit is logged under it.');
  refresh();
}
document.addEventListener('DOMContentLoaded', init);
