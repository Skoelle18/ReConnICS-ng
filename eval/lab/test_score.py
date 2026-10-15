"""Scorer sanity test: perfect inventory -> 1.0; corrupted inventory -> expected penalties."""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score import score, FIELDS  # noqa

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')


def perfect(truth):
    assets = []
    for d in truth['devices']:
        a = {'id': d['id'], 'ip': {'value': d['ip']}}
        if d.get('mac'):
            a['mac'] = {'value': d['mac']}
        for f in FIELDS:
            if d.get(f) is not None:
                a[f] = {'value': d[f]}
        assets.append(a)
    return {'assets': assets}


fails = 0
for tp in sorted(glob.glob(os.path.join(OUT, '*.truth.json'))):
    t = json.load(open(tp, encoding='utf-8'))
    m = score(t, perfect(t))
    ok = m['precision'] == 1 and m['recall'] == 1 and m['mac_wrongly_assigned'] == 0 and \
        all(v in (None, 1.0) for v in m['field_accuracy'].values())
    fails += not ok
    print('%-4s perfect %-22s P=%.2f R=%.2f acc=%s' % ('OK' if ok else 'FAIL', t['scenario'], m['precision'],
                                                      m['recall'], m['identity_accuracy_overall']))

t = json.load(open(os.path.join(OUT, 'routed_span.truth.json'), encoding='utf-8'))
inv = perfect(t)
inv['assets'] = [a for a in inv['assets'] if a['id'] != '10.0.1.40']            # missing
rtr = t['expect']['router_mac']
for a in inv['assets']:
    if a['id'] == '10.0.10.5':
        a['mac'] = {'value': rtr}                                               # router MAC wrongly assigned
    if a['id'] == '10.0.1.20':
        a['firmware'] = {'value': 'V1.6.2.0'}                                   # V prefix tolerated
        a['vendor'] = {'value': 'schneider automation'}                         # alias tolerated
        a['model'] = {'value': 'Schneider TM221CE16R controller'}               # containment tolerated
    if a['id'] == '10.0.1.50':
        a['serial'] = {'value': 'WRONG'}
        a['hostname'] = {'value': '<script>x</script>'}
inv['assets'].append({'id': '10.0.1.254', 'mac': {'value': '00:00:5e:00:01:01'}})  # forbidden VIP w/ VRRP mac
m = score(t, inv)
exp = dict(missing=['10.0.1.40'], extra=['10.0.1.254'], mac_wrongly_assigned=2, unsafe_strings=1)
got = {k: m[k] for k in exp}
ok = got == exp and m['field_accuracy']['firmware'] == 0.75 and m['field_accuracy']['vendor'] == 0.75 and m['field_accuracy']['serial'] == 0.0 \
    and len(m['forbidden_devices_found']) == 1
fails += not ok
print('%-4s corrupted routed_span: %s fw_acc=%s vendor_acc=%s serial_acc=%s' % (
    'OK' if ok else 'FAIL', got, m['field_accuracy']['firmware'], m['field_accuracy']['vendor'],
    m['field_accuracy']['serial']))
sys.exit(1 if fails else 0)
