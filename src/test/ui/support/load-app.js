// Loads the real site console (index.html + app.js) into a fake browser (jsdom),
// with a fake server answering the /api/v1/* calls. No real server, no network.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const UI_DIR = path.resolve(__dirname, '../../../main/resources/ui');

/**
 * Start the console.
 *   routes   - { 'GET inventory': {...}, 'PATCH assets/x': fn(req) } fake API answers
 *   hash     - starting page, e.g. '#/inventory'
 *   storage  - localStorage values, e.g. { actor: 'Vineeth', role: 'validator' }
 */
async function loadApp({ routes = {}, hash = '#/overview', storage = {} } = {}) {
  const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(UI_DIR, 'app.js'), 'utf8');

  // Swap the external <script src="app.js"> for the same code inline, so jsdom runs it.
  const page = html.replace(/<script src="app\.js"[^>]*><\/script>/, () => '<script>' + appJs + '</script>');
  if (page === html) throw new Error('index.html no longer loads app.js the expected way');

  const calls = [];
  const dom = new JSDOM(page, {
    url: 'http://127.0.0.1:8088/' + hash,
    runScripts: 'dangerously',
    beforeParse(window) {
      for (const [k, v] of Object.entries(storage)) window.localStorage.setItem(k, v);
      window.fetch = async (url, opts = {}) => {
        const method = opts.method || 'GET';
        const route = String(url).replace(/^\/api\/v1\//, '');
        const req = { method, route, headers: opts.headers || {}, body: opts.body };
        calls.push(req);
        const key = method + ' ' + route.split('?')[0];
        if (!(key in routes)) return fakeResponse(404, { error: 'no fake route for ' + key });
        let answer = routes[key];
        if (typeof answer === 'function') answer = await answer(req);
        if (answer && answer.__status) return fakeResponse(answer.__status, answer.body);
        return fakeResponse(200, answer);
      };
    },
  });

  const app = {
    window: dom.window,
    document: dom.window.document,
    calls,
    /** Read anything app.js defines, including const/let (e.g. app.get('S')). */
    get: (name) => dom.window.eval(name),
    $: (sel) => dom.window.document.querySelector(sel),
    $$: (sel) => [...dom.window.document.querySelectorAll(sel)],
    text: (sel = '#main') => (dom.window.document.querySelector(sel) || {}).textContent || '',
    /** Go to another screen, as clicking a link would. */
    async go(hash) {
      dom.window.location.hash = hash;
      await waitFor(() => app.get('route()').name === hash.split('/')[1]);
      await settle();
    },
    close: () => dom.window.close(),
  };

  await waitFor(() => app.get('S').inv !== null, 'the console never loaded its data');
  await settle();
  return app;
}

function fakeResponse(status, body) {
  const text = body == null ? '' : JSON.stringify(body);
  return { ok: status >= 200 && status < 300, status, statusText: String(status), text: async () => text };
}

async function waitFor(check, message = 'condition not met in time', ms = 2000) {
  const end = Date.now() + ms;
  for (;;) {
    try { if (check()) return; } catch { /* not ready yet */ }
    if (Date.now() > end) throw new Error(message);
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** Let pending promises (fake fetch, refresh) finish. */
const settle = () => new Promise((r) => setTimeout(r, 20));

module.exports = { loadApp, waitFor, settle };
