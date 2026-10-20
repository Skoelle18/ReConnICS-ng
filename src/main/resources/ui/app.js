// ReConICS site console. Plain JS, no build step, served by `serve` from the jar (docs/plans/2026-10-17-ui.md).
// All DOM is built with h() and textContent: device-supplied strings never reach innerHTML.
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
const LEVEL_COLOR = { EXACT: '#B42318', PROBABLE: '#E07B00', POSSIBLE: '#C9A400', NONE: '#9AA3B2', UNRUN: '#9AA3B2' };
const ROLE_COLOR = { PLC: '#0F766E', Drive: '#5EB8AE', 'Comms adapter': '#1D4ED8', Network: '#93B4F5', Workstation: '#14202B', Other: '#7C8798', Unknown: '#CBD2DC' };
const PURDUE = [['3', 'Level 3', 'Site operations'], ['2', 'Level 2', 'Supervisory: HMI, EWS'], ['1', 'Level 1', 'Basic control: PLCs, adapters'],
  ['0', 'Level 0', 'Process: drives, I/O'], ['', 'Unplaced', 'Not enough identity yet']];
const LIFECYCLE = ['Acquisition', 'Deployment', 'Commissioning', 'In service', 'Maintenance', 'Decommissioned'];
// What a site field shows before anyone has set it. The edit form must compare against the same value,
// or saving an untouched form would log a change nobody made.
const SITE_DEFAULTS = { lifecycle: 'In service' };

const S = { inv: null, rank: [], site: {}, caps: [], changes: [], index: null, search: '', level: 'ALL', kevOnly: false, unvalOnly: false,
  openCap: null, openAdv: null, tab: 'attrs', editing: false, staged: null };

// ------------------------------------------------------------------ helpers

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') Object.assign(el.style, v);                 // CSSOM: allowed under the CSP
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
const $ = (id) => document.getElementById(id);
const store = { get(k) { try { return localStorage.getItem(k) || ''; } catch { return ''; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* private window */ } } };
const val = (a, k) => (a && a[k] && a[k].value != null ? a[k].value : null);
const str = (v) => (Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v));
const fmtTime = (iso) => (iso ? String(iso).replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, 'Z') : '');
const fmtSize = (n) => (n > 1 << 30 ? (n / (1 << 30)).toFixed(1) + ' GB' : (n / (1 << 20)).toFixed(1) + ' MB');
const bar = (pct, color) => h('span', { class: 'bar' }, h('span', { style: { width: Math.max(0, Math.min(100, pct)) + '%', background: color || null } }));
const dot = (color) => h('span', { class: 'dot', style: { background: color } });
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

function roleGroup(a) {
  const r = (str(val(a, 'role')) + ' ' + str(val(a, 'deviceType'))).toLowerCase();
  if (!r.trim()) return 'Unknown';
  if (/plc|controller|cpu|cip:0x0e/.test(r)) return 'PLC';
  if (/drive|cip:0x0?2\b|0x13|0x25/.test(r)) return 'Drive';
  if (/adapter|0x0c/.test(r)) return 'Comms adapter';
  if (/switch|gateway|router/.test(r)) return 'Network';
  if (/hmi|workstation|ews|client|initiator/.test(r)) return 'Workstation';
  return 'Other';
}
function purdueOf(a) {
  if (siteOf(a).purdue) return siteOf(a).purdue;
  return { PLC: '1', 'Comms adapter': '1', Network: '1', Drive: '0', Workstation: '2' }[roleGroup(a)] || '';
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
    { title: 'Conflicting values', color: '#B54708', items: conflicts.map((a) => [a, 'Values disagree across observations: ' + Object.keys(a).filter((k) => a[k] && a[k].conflict).join(', ')]) },
    { title: 'Low-confidence identity', color: '#5B6474', items: low.map((a) => [a, 'Role, vendor or model rests on weak evidence. Confirm with the plant engineer.']) },
    { title: 'Awaiting validation', color: '#0F766E', items: all.filter((a) => !isValidated(a)).map((a) => [a, a.completeness.filled + ' of 14 attributes filled']) },
  ].filter((g) => g.items.length);
}
const reviewCount = () => new Set(reviewGroups().flatMap((g) => g.items.map((i) => i[0].id))).size;

async function loadAll() {
  const [inv, caps, idx] = await Promise.all([api('GET', 'inventory'), api('GET', 'captures'), api('GET', 'index')]);
  S.inv = inv.inventory; S.rank = inv.rank; S.site = inv.site; S.caps = caps; S.index = idx;
}

// ------------------------------------------------------------------ chrome

function chrome(route) {
  document.querySelectorAll('[data-nav]').forEach((n) => n.classList.toggle('on', n.dataset.nav === route || (route === 'asset' && n.dataset.nav === 'inventory')));
  const active = S.caps.filter((c) => c.state === 'queued' || c.state === 'running').length;
  $('n-queue').textContent = active || '';
  $('n-assets').textContent = assets().length || '';
  $('n-review').textContent = reviewCount() || '';
  $('n-adv').textContent = advisoryRows().length || '';
  const ix = S.index || {};
  const badge = $('idx-badge');
  badge.className = 'badge ' + (!ix.verified ? 'bad' : ix.warning ? 'warn' : 'ok');
  badge.textContent = (ix.verified ? 'Index verified' : 'Index UNVERIFIED') + ' · ' + String(ix.generated || '?').slice(0, 10);
  const banner = $('banner');
  banner.replaceChildren();
  if (!ix.verified) banner.append(h('div', { class: 'banner bad' }, 'Advisory index is UNVERIFIED (no public key). An altered index can hide vulnerable devices.'));
  else if (ix.warning) banner.append(h('div', { class: 'banner warn' }, ix.warning));
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
          h('span', { class: 'kpi', style: { color: kev ? '#9F1A1A' : null } }, kev), h('span', { class: 'muted small' }, lv.EXACT + ' EXACT · ' + lv.PROBABLE + ' PROBABLE matches')),
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
            h('div', { class: 'card-b stack' }, LEVELS.map((l) => h('a', { href: '#/inventory', class: 'stack', style: { gap: '6px', textDecoration: 'none', color: 'inherit' }, onclick: () => { S.level = l; } },
              h('span', { class: 'head' }, levelBadge(l), h('span', { class: 'muted small' }, lv[l] + ' assets')), bar(lv[l] / n * 100, LEVEL_COLOR[l]))),
              h('div', { class: 'muted small' }, 'NONE means no advisory in this index, not a clean device.'))),
          h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Assets by role'),
            h('div', { class: 'card-b stack' },
              h('div', { class: 'stacked' }, groups.map((x) => h('span', { style: { width: (x.n / n * 100) + '%', background: ROLE_COLOR[x.g] } }))),
              h('div', { class: 'row' }, groups.map((x) => h('span', { class: 'row' }, dot(ROLE_COLOR[x.g]), x.g, h('span', { class: 'muted small' }, x.n)))))))),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'Fix-first ranking', h('a', { class: 'btn sm', href: '#/inventory' }, 'Full inventory')),
          ranked.slice(0, 5).map((a, i) => h('a', { class: 'rv', href: '#/asset/' + encodeURIComponent(a.id) },
            h('span', { class: 'mono muted' }, i + 1), h('span', { style: { flex: '1', minWidth: '0' } }, h('span', { class: 'cell-name' }, nameOf(a)), h('span', { class: 'mono muted small' }, a.id)),
            a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV') : null, levelBadge(levelOf(a)),
            h('span', { class: 'mono small' }, a.match && a.match.maxCvss ? a.match.maxCvss.toFixed(1) : '—')))),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, 'CISA attribute fill rate', h('span', { class: 'muted small' }, '14 high-priority attributes')),
          h('div', { class: 'card-b fill' }, ATTRS.map(([k, label, by]) => {
            const pct = Math.round(parseFloat((sum.fillRate || {})[k] || 0) * 100);
            return h('div', { class: 'stack', style: { gap: '4px' } }, h('span', { class: 'head' }, label, h('span', { class: 'badge ' + (by === 'human' ? 'c-PERSON' : 'c-LOW') }, pct + '%')),
              bar(pct, by === 'human' ? '#6B3FA0' : null));
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
          h('span', {}, h('span', { class: 'cell-name wrap' }, x.file), h('span', { class: 'muted small' }, fmtSize(x.size) + ' · ' + fmtTime(x.at))),
          h('span', {}, h('span', { class: 'badge st-' + x.state }, stateTxt[x.state])),
          h('span', {}, x.by),
          h('span', { class: 'small' }, x.state === 'done' && x.diff ? '+' + x.diff.new + ' new · ' + x.diff.changed + ' changed · ' + x.diff.notSeen + ' not seen'
            : x.state === 'failed' ? 'Exit ' + x.exit : x.state === 'running' ? 'Reading frames…' : 'Waiting for the worker'),
          h('span', { class: 'mono small muted', title: x.sha256 }, x.sha256.slice(0, 8) + '…' + x.sha256.slice(-4)),
          h('span', { class: 'row' },
            x.state === 'queued' || x.state === 'failed' ? h('button', { class: 'btn sm', onclick: () => removeCapture(x) }, 'Remove') : null,
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
          h('div', { class: 'mono code' }, 'editcap -F pcap input.cap output.pcap')) : null) : null,
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
async function removeCapture(c) {
  try { await api('DELETE', 'captures/' + encodeURIComponent(c.id)); toast('Removed ' + c.file); } catch (e) { toast(e.message); }
  await refresh();
}

function inventory() {
  const q = S.search.trim().toLowerCase();
  const ranked = S.rank.map(byId).filter(Boolean);
  const rows = ranked.filter((a) => (S.level === 'ALL' || levelOf(a) === S.level) && (!S.kevOnly || (a.match && a.match.kevAtModel)) && (!S.unvalOnly || !isValidated(a))
    && (!q || [a.id, nameOf(a), val(a, 'vendor'), val(a, 'model'), val(a, 'mac'), val(a, 'hostname')].some((v) => v && str(v).toLowerCase().includes(q))));
  const chip = (label, on, fn) => h('button', { class: 'chip' + (on ? ' on' : ''), 'aria-pressed': String(on), onclick: () => { fn(); render(); } }, label);
  return [
    h('div', { class: 'head' },
      h('div', {}, h('h1', {}, 'Asset inventory'), h('div', { class: 'muted' }, 'Ranked fix-first: KEV at model, match level, criticality, CVSS, then most work left.')),
      h('div', { class: 'row' }, ['inventory.csv', 'inventory.json', 'report.html'].map((f) => h('a', { class: 'btn', href: '/api/v1/export/' + f, download: f }, f)))),
    h('div', { class: 'row' },
      ['ALL', ...LEVELS].map((l) => chip(l === 'ALL' ? 'All levels' : l, S.level === l, () => { S.level = l; })),
      chip('KEV only', S.kevOnly, () => { S.kevOnly = !S.kevOnly; }), chip('Not validated', S.unvalOnly, () => { S.unvalOnly = !S.unvalOnly; }),
      q ? chip('Search: ' + S.search + ' (clear)', true, () => { S.search = ''; $('q').value = ''; }) : null),
    h('div', { class: 'card' }, h('div', { class: 'scroll' },
      h('div', { class: 'trow thead g-inv' }, ['#', 'Asset', 'Role', 'Vendor / model', 'Firmware', 'Completeness', 'Advisory match', 'Validated'].map((t) => h('span', {}, t))),
      rows.length === 0 ? h('div', { class: 'empty' }, assets().length ? 'No assets match these filters.' : 'No assets yet. Queue a capture.') :
        rows.map((a) => h('button', { class: 'trow g-inv', onclick: () => { location.hash = '#/asset/' + encodeURIComponent(a.id); } },
          h('span', { class: 'mono muted' }, S.rank.indexOf(a.id) + 1),
          h('span', {}, h('span', { class: 'cell-name wrap' }, nameOf(a)), h('span', { class: 'mono small muted' }, a.id)),
          h('span', {}, str(val(a, 'role')) || '—'),
          h('span', {}, h('span', { class: 'cell-name', style: { fontWeight: '400' } }, str(val(a, 'vendor')) || '—'), h('span', { class: 'muted small' }, str(val(a, 'model')))),
          h('span', { class: 'mono small' }, str(val(a, 'firmware')) || '—'),
          h('span', { class: 'stack', style: { gap: '4px' } }, h('span', { class: 'small' }, a.completeness.filled + ' / 14'), bar(a.completeness.filled / 14 * 100)),
          h('span', { class: 'row' }, levelBadge(levelOf(a)), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV') : null,
            h('span', { class: 'mono small muted' }, a.match && a.match.maxCvss ? a.match.maxCvss.toFixed(1) : '')),
          h('span', {}, h('span', { class: 'badge ' + (isValidated(a) ? 'ok' : 'lv-NONE') }, isValidated(a) ? 'Validated' : 'Pending'))))),
      h('div', { class: 'card-b head muted small' }, 'Showing ' + rows.length + ' of ' + assets().length + ' assets', 'Port-only observations are not counted as identified devices.')),
  ];
}

function asset(id) {
  const a = byId(id);
  if (!a) return [h('a', { class: 'btn sm', href: '#/inventory' }, '‹ Inventory'), h('div', { class: 'card empty' }, 'No asset ' + id + ' in the current inventory.')];
  const site = siteOf(a), c = a.completeness, role = store.get('role') || 'collector';
  const tab = (k, label) => h('button', { class: 'tab' + (S.tab === k ? ' on' : ''), onclick: () => { S.tab = k; S.editing = false; render(); } }, label);
  const advs = (a.match && a.match.advisories) || [];
  const hist = S.changes.filter((x) => x.asset === a.id);
  return [
    h('a', { class: 'btn sm', href: '#/inventory', style: { alignSelf: 'flex-start' } }, '‹ Inventory'),
    h('div', { class: 'card' },
      h('div', { class: 'card-b head', style: { alignItems: 'flex-start' } },
        h('div', { class: 'stack', style: { gap: '6px' } },
          h('div', { class: 'row' }, h('h1', {}, nameOf(a)), levelBadge(levelOf(a)), a.match && a.match.kevAtModel ? h('span', { class: 'badge kev' }, 'KEV at model') : null,
            h('span', { class: 'badge ' + (isValidated(a) ? 'ok' : 'lv-NONE') }, isValidated(a) ? 'Validated' : 'Pending validation')),
          h('div', { class: 'mono muted' }, a.id + ' · ' + (str(val(a, 'mac')) || 'no MAC (sub-unit or routed)')),
          a.subaddr ? h('div', { class: 'small muted' }, 'Sub-unit ' + a.subaddr + '. Inherits IP, protocols and ports from its parent.') : null,
          a.match && a.match.matchedAs ? h('div', { class: 'small muted' }, 'Matched as ' + a.match.matchedAs + ' (from the Siemens order number).') : null),
        h('div', { class: 'row', style: { gap: '20px' } },
          fact('Completeness', c.filled + ' / 14'), h('div', {}, h('div', { class: 'muted small' }, 'Match ceiling'), levelBadge(c.matchCeiling)),
          fact('Lifecycle', site.lifecycle || 'In service'))),
      c.nextStep ? h('div', { class: 'note' }, h('strong', {}, 'Next step to raise the match: '), c.nextStep) : null,
      h('div', { class: 'tabs' }, tab('attrs', 'Attributes'), tab('advs', 'Advisories (' + advs.length + ')'), tab('hist', 'History (' + hist.length + ')'))),
    S.tab === 'attrs' ? attrsCard(a, site, role) : S.tab === 'advs' ? h('div', { class: 'card' },
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
        h('span', { class: 'mono small muted' }, fmtTime(x.at)), h('span', { class: 'strong' }, x.actor), h('span', {}, x.field + ': ', h('span', { class: 'muted' }, x.from || '∅'), ' → ', x.to || '∅')))
        : h('div', { class: 'empty' }, 'No human changes yet. Capture merges are in the change log.')),
  ];
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
    role !== 'validator' ? h('div', { class: 'small muted', style: { padding: '8px 16px', background: '#FAFAFB', borderBottom: '1px solid var(--line2)' } }, 'Only a validator can mark an asset validated. Change Role in the sidebar.') : null,
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

// ------------------------------------------------------------------ routing, refresh

function route() {
  const [, name, arg] = (location.hash || '#/overview').match(/^#\/([a-z]+)\/?(.*)$/) || [, 'overview', ''];
  return { name, arg: decodeURIComponent(arg || '') };
}

let lastRoute = '';
function render() {
  const r = route();
  if (!S.inv) return;
  if (r.name + r.arg !== lastRoute) { S.tab = 'attrs'; S.editing = false; lastRoute = r.name + r.arg; }
  chrome(r.name);
  const screens = { overview, captures, inventory, review, advisories, index: indexScreen, log, asset: () => asset(r.arg) };
  $('main').replaceChildren(...[].concat((screens[r.name] || overview)()).flat(Infinity).filter(Boolean));
}

let polling = null;
async function refresh() {
  try {
    await loadAll();
    if (route().name === 'log' || route().name === 'asset') S.changes = await api('GET', 'changes');
  } catch (e) { toast('Cannot reach the console: ' + e.message); }
  if (!S.editing) render(); else chrome(route().name);
  const busy = S.caps.some((c) => c.state === 'queued' || c.state === 'running');
  if (busy && !polling) polling = setInterval(refresh, 1500);
  if (!busy && polling) { clearInterval(polling); polling = null; }
}

function init() {
  const actor = $('actor'), roleSel = $('role');
  actor.value = store.get('actor');
  roleSel.value = store.get('role') || 'collector';
  actor.addEventListener('change', () => store.set('actor', actor.value.trim()));
  roleSel.addEventListener('change', () => { store.set('role', roleSel.value); render(); });
  $('q').addEventListener('input', (e) => { S.search = e.target.value; if (route().name !== 'inventory') location.hash = '#/inventory'; else render(); });
  window.addEventListener('hashchange', () => { refresh(); $('main').focus(); });
  if (!store.get('actor')) toast('Enter your name in the sidebar: every edit is logged under it.');
  refresh();
}
document.addEventListener('DOMContentLoaded', init);
