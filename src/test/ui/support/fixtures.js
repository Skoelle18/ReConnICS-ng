// Fake server answers for the UI tests.
// The assets come from the repo's real example output (docs/examples/inventory.json);
// match data is added on top, because that example was produced without an advisory index.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const EXAMPLE = path.resolve(__dirname, '../../../../docs/examples/inventory.json');

function exampleInventory() {
  return JSON.parse(fs.readFileSync(EXAMPLE, 'utf8'));          // fresh copy for every test
}

/** A synthetic advisory. The ID is made up and never refers to a real CISA advisory. */
const TEST_ADVISORY = {
  advisory: 'TEST-ADVISORY-0001', title: 'Synthetic test advisory', level: 'EXACT',
  cvss: 9.8, kev: ['CVE-0000-00001'], cves: ['CVE-0000-00001'], affected: '6ES7 515 < V9.9',
};

/** Conversations between the example assets (client 10.0.1.50 polls three servers; two protocols between the same pair). */
const EXAMPLE_FLOWS = [
  { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', messages: 12, labels: { 'Modbus FC43/14 request': 4, 'Modbus FC43/14 response': 4, 'Modbus FC=0x3': 4 } },
  { client: '10.0.1.50', server: '10.0.1.40', protocol: 'ethernet-ip', port: '44818/tcp', messages: 2, labels: { 'ListIdentity': 2 } },
  { client: '10.0.1.50', server: '10.0.1.10', protocol: 'ethernet-ip', port: '44818/tcp', messages: 3, labels: { 'CIP Get_Attributes_All Identity request': 3 } },
  { client: '10.0.1.20', server: '10.0.1.40', protocol: 's7comm', port: '102/tcp', messages: 5, labels: { 'S7 SZL read request': 5 } },
];

/** Conversations with the optional fields: times, counters, operations, a DNP3 edge, an undecoded host pair and a scan-only one. */
const RICH_FLOWS = [
  { client: '10.0.1.50', server: '10.0.1.40', protocol: 'modbus', port: '502/tcp', transport: 'tcp', messages: 1200, packets: 2400, bytes: 98000,
    firstSeen: '2015-10-22T09:00:01Z', lastSeen: '2015-10-22T10:00:00Z', labels: { 'Modbus FC3': 1100, 'Modbus FC16': 100 }, source: 'zeek+native',
    operations: [
      { function: 'FC3 read holding registers', access: 'read', address: 40001, quantity: 10, count: 1100, sampleValues: [12, 0, 7] },
      { function: 'FC16 write multiple registers', access: 'write', address: 40100, quantity: 2, count: 100, sampleValues: [1, 2] },
    ] },
  { client: '10.0.1.20', server: '10.0.1.10', protocol: 'dnp3', port: '20000/tcp', transport: 'tcp', messages: 30, packets: 90, bytes: 4000,
    firstSeen: '2015-10-22T09:00:00Z', lastSeen: '2015-10-22T09:10:00Z', labels: { 'DNP3 FC1 READ': 20, 'DNP3 FC129 RESPONSE': 10 }, source: 'native' },
  { client: '10.0.1.50', server: '10.0.1.60', protocol: 'unknown', port: '80/tcp', transport: 'tcp', messages: 4, packets: 9, bytes: 600,
    firstSeen: '2015-10-22T09:00:00Z', lastSeen: '2015-10-22T09:00:00.500Z', labels: {}, source: 'native' },
  { client: '10.0.1.60', server: '10.0.1.20', protocol: 'unknown', port: '23/tcp', transport: 'tcp', messages: 0, scanAttempts: 4, labels: {}, source: 'native' },
];

/** Default fake API: real example assets, ranked as listed, index verified. */
function defaultRoutes({ inventory, rank, site = {}, index, captures = [], changes = [], flows = EXAMPLE_FLOWS } = {}) {
  const inv = inventory || exampleInventory();
  // Give two assets a match result so advisory screens have something to show.
  const plc = inv.assets.find((a) => a.id === '10.0.1.40');
  plc.match = { level: 'EXACT', kevAtModel: true, maxCvss: 9.8, advisories: [TEST_ADVISORY] };
  const adapter = inv.assets.find((a) => a.id === '10.0.1.10');
  adapter.match = { level: 'NONE', kevAtModel: false, maxCvss: 0, advisories: [] };
  return {
    'GET inventory': { inventory: inv, rank: rank || inv.assets.map((a) => a.id), site, flows },
    'GET captures': captures,
    'GET index': index || { verified: true, generated: '2026-10-01T00:00:00Z', warning: null, kevCatalogVersion: '2026.10.01', advisories: 3100, rows: 52000 },
    'GET changes': changes,
  };
}

/** One asset field in the shape the server sends. */
const field = (value, confidence = 'HIGH', evidence = 'pcap#1') => ({ value, confidence, evidence });

module.exports = { exampleInventory, defaultRoutes, field, TEST_ADVISORY, RICH_FLOWS };
