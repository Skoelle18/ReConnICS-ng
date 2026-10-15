"""Score a ReConICS inventory against a lab ground-truth file.

    python lab/score.py lab/out/<scenario>.truth.json inventory.json [--out metrics.json] [--quiet]

Inventory format: {"assets":[{"id":..,"ip":{"value":..},"mac":{"value":..},"vendor":{"value":..},
"model":{"value":..},"firmware":{"value":..},"serial":{"value":..},"role":{"value":..},
"hostname":{"value":..}}]}   (fields may be absent; a bare string instead of {"value":..} is tolerated)

Rules
  * detection: truth devices are matched by id; an asset whose id is missing is matched by ip.value when the
    truth id is a plain IP.  truth 'alt_ids' (e.g. two IPs of one NIC) map to the same device and are neither
    extra nor duplicated.  devices flagged optional=true never count as missing and are not counted as extra.
  * precision = TP / (TP + extra);  recall = TP / required truth devices
  * field accuracy over identifiable truth devices, only for fields where the truth value is not null;
    a missing device counts as wrong for all its fields.  Case-insensitive, whitespace-trimmed.
      vendor   : equal, or equal to one of vendor_aliases
      model    : truth contained in found or found contained in truth (also against model_aliases)
      firmware : equal after stripping a leading 'V' (also firmware_aliases)
      hostname : equal (also hostname_aliases)
  * mac_wrongly_assigned: truth mac is null but the asset has a MAC, or the asset carries a MAC listed in
    not_devices kind=mac_not_assignable (except the router's own entry, expect.router_mac_owner)
  * mac_mismatch: truth mac set, found mac set and different
  * unsafe_strings: any string value containing '<script' or ASCII control characters
"""
import json
import re
import sys

FIELDS = ['vendor', 'model', 'firmware', 'serial', 'role', 'hostname']
CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def val(a, k):
    v = a.get(k)
    if isinstance(v, dict):
        v = v.get('value')
    if isinstance(v, list):
        v = v[-1] if v else None
    return v


def norm(s):
    return ' '.join(str(s).split()).lower() if s is not None else None


def norm_mac(m):
    return m.lower().replace('-', ':') if m else None


ROLE_ALIASES = {'communications adapter': 'comms_adapter', 'i/o adapter': 'io_adapter', 'discrete i/o': 'io',
                'managed switch': 'switch'}


def field_ok(f, truth_dev, found):
    t = truth_dev.get(f)
    if found is None:
        return False
    fn = norm(found)
    if f == 'role':
        fn = ROLE_ALIASES.get(fn, fn)
    cands = [t] + truth_dev.get(f + '_aliases', [])
    if f == 'firmware':
        fn = fn.lstrip('v')
        return any(fn == norm(c).lstrip('v') for c in cands if c)
    if f == 'model':
        return any(fn and (norm(c) in fn or fn in norm(c)) for c in cands if c)
    return any(fn == norm(c) for c in cands if c)


def score(truth, inv):
    assets = inv.get('assets', []) if isinstance(inv, dict) else inv
    tdevs = truth['devices']
    by_id = {}
    for d in tdevs:
        by_id[d['id']] = d
        for a in d.get('alt_ids', []):
            by_id.setdefault(a, d)
    forbidden = {n['id']: n['reason'] for n in truth.get('not_devices', []) if n['kind'] == 'no_device'}
    bad_macs = {norm_mac(n['mac']) for n in truth.get('not_devices', []) if n['kind'] == 'mac_not_assignable'}
    router_owner = truth.get('expect', {}).get('router_mac_owner')

    matched, extra, dup, forbidden_found = {}, [], [], []
    for a in assets:
        aid = a.get('id') or val(a, 'ip')
        d = by_id.get(aid)
        if d is None and val(a, 'ip') in by_id and '/' not in str(aid):
            d = by_id[val(a, 'ip')]
        if d is None:
            extra.append(aid)
            if aid in forbidden:
                forbidden_found.append({'id': aid, 'reason': forbidden[aid]})
            continue
        if d['id'] in matched:
            prev = matched[d['id']].get('id') or val(matched[d['id']], 'ip')
            if prev == aid or aid not in d.get('alt_ids', []) + [d['id']]:
                dup.append(aid)          # same id twice -> duplicate asset
            continue                     # alt id of an already-matched device: tolerated, not extra
        matched[d['id']] = a

    required = [d for d in tdevs if not d.get('optional')]
    tp = sum(1 for d in required if d['id'] in matched)
    tp_opt = sum(1 for d in tdevs if d.get('optional') and d['id'] in matched)
    n_extra = len(extra) + len(dup)
    precision = tp / (tp + n_extra) if (tp + n_extra) else 1.0
    recall = tp / len(required) if required else 1.0

    fields = {f: {'correct': 0, 'total': 0, 'wrong': []} for f in FIELDS}
    for d in tdevs:
        if not d.get('identifiable'):
            continue
        a = matched.get(d['id'])
        for f in FIELDS:
            if d.get(f) is None:
                continue
            fields[f]['total'] += 1
            got = val(a, f) if a else None
            if field_ok(f, d, got):
                fields[f]['correct'] += 1
            else:
                fields[f]['wrong'].append({'id': d['id'], 'truth': d[f], 'found': got})
    for f in FIELDS:
        t = fields[f]['total']
        fields[f]['accuracy'] = round(fields[f]['correct'] / t, 4) if t else None

    mac_wrong, mac_mismatch = [], []
    for did, a in matched.items():
        d = by_id[did]
        fm = norm_mac(val(a, 'mac'))
        if not fm:
            continue
        if d.get('mac') is None:
            mac_wrong.append({'id': did, 'found_mac': fm, 'why': 'truth mac is null (not visible on segment)'})
        elif fm in bad_macs and d['ip'] != router_owner:
            mac_wrong.append({'id': did, 'found_mac': fm, 'why': 'MAC is not assignable (router/VRRP)'})
        elif fm != norm_mac(d['mac']):
            mac_mismatch.append({'id': did, 'truth_mac': d['mac'], 'found_mac': fm})
    for aid in extra:
        a = next(x for x in assets if (x.get('id') or val(x, 'ip')) == aid)
        fm = norm_mac(val(a, 'mac'))
        if fm in bad_macs:
            mac_wrong.append({'id': aid, 'found_mac': fm, 'why': 'non-assignable MAC on extra asset'})

    unsafe = []

    def walk(o, path):
        if isinstance(o, str):
            if '<script' in o.lower() or CTRL.search(o):
                unsafe.append({'path': path, 'value': o[:80]})
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(v, path + '.' + str(k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, '%s[%d]' % (path, i))
    walk(assets, 'assets')

    missing = [d['id'] for d in required if d['id'] not in matched]
    ident_fields = [fields[f] for f in FIELDS if fields[f]['total']]
    overall = (sum(x['correct'] for x in ident_fields) / sum(x['total'] for x in ident_fields)) if ident_fields else None
    return {
        'scenario': truth['scenario'],
        'truth_devices': len(tdevs), 'required_devices': len(required), 'inventory_assets': len(assets),
        'true_positives': tp, 'optional_found': tp_opt,
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        'field_accuracy': {f: fields[f]['accuracy'] for f in FIELDS},
        'identity_accuracy_overall': round(overall, 4) if overall is not None else None,
        'mac_wrongly_assigned': len(mac_wrong), 'mac_mismatch': len(mac_mismatch),
        'forbidden_devices_found': forbidden_found,
        'unsafe_strings': len(unsafe),
        'missing': missing, 'extra': extra, 'duplicates': dup,
        'details': {'field_errors': {f: fields[f]['wrong'] for f in FIELDS if fields[f]['wrong']},
                    'mac_wrong': mac_wrong, 'mac_mismatch': mac_mismatch, 'unsafe': unsafe[:20]},
    }


def main(argv):
    args = [a for a in argv if not a.startswith('--')]
    if len(args) < 2:
        print(__doc__)
        return 2
    out = argv[argv.index('--out') + 1] if '--out' in argv else None
    if out in args:
        args.remove(out)
    truth = json.load(open(args[0], encoding='utf-8'))
    inv = json.load(open(args[1], encoding='utf-8'))
    m = score(truth, inv)
    txt = json.dumps(m, indent=1, ensure_ascii=True)
    if '--quiet' not in argv:
        print(txt)
    if out:
        open(out, 'w', encoding='utf-8').write(txt)
    return m


if __name__ == '__main__':
    r = main(sys.argv[1:])
    sys.exit(r if isinstance(r, int) else 0)
