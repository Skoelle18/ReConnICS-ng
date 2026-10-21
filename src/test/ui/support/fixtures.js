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

module.exports = { exampleInventory, defaultRoutes, field, TEST_ADVISORY };
