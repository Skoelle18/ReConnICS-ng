// Small helper functions in app.js: formatting and device classification.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadApp } = require('./support/load-app');
const { defaultRoutes, field } = require('./support/fixtures');

test('helper functions', async (t) => {
  const app = await loadApp({ routes: defaultRoutes() });
  t.after(() => app.close());
  const fn = (name) => app.get(name);

  await t.test('fmtSize shows MB below 1 GB and GB above', () => {
    assert.equal(fn('fmtSize')(5 * 1024 * 1024), '5.0 MB');
    assert.equal(fn('fmtSize')(2 * 1024 * 1024 * 1024 + 1), '2.0 GB');
  });

  await t.test('fmtTime reads as a date and a time; fmtDur as the shortest unit', () => {
    assert.match(fn('fmtTime')('2026-10-18T10:20:30Z'), /^\d{1,2} Oct 2026, \d\d:\d\d$/);
    assert.equal(fn('fmtDur')(850), '850 ms');
    assert.equal(fn('fmtDur')(12400), '12.4 s');
    assert.equal(fn('fmtDur')(125000), '2 min 05 s');
    assert.equal(fn('fmtTime')(null), '');
  });

  await t.test('str joins lists and turns null into empty text', () => {
    assert.equal(fn('str')(['enip', 'modbus']), 'enip, modbus');
    assert.equal(fn('str')(null), '');
    assert.equal(fn('str')(502), '502');
  });

  await t.test('roleGroup sorts devices into the right group', () => {
    const roleGroup = fn('roleGroup');
    assert.equal(roleGroup({ role: field('PLC') }), 'PLC');
    assert.equal(roleGroup({ deviceType: field('cip:0x0C') }), 'Comms adapter');
    assert.equal(roleGroup({ role: field('HMI') }), 'Workstation');
    assert.equal(roleGroup({ role: field('router') }), 'Network');
    assert.equal(roleGroup({}), 'Unknown', 'no role means Unknown, never a guess');
  });

  await t.test('purdueOf suggests a level from the role, but a site entry wins', () => {
    const purdueOf = fn('purdueOf');
    const plc = { id: 'x', role: field('PLC') };
    assert.equal(purdueOf(plc), '1');
    app.get('S').site['x'] = { purdue: '2' };
    assert.equal(purdueOf(plc), '2');
    assert.equal(purdueOf({ id: 'y' }), '', 'unknown role is left unplaced');
  });
});
