# UI unit tests

Unit tests for the site console JavaScript (`src/main/resources/ui/app.js`).

The tests load the real `index.html` and `app.js` into a fake browser ([jsdom](https://github.com/jsdom/jsdom)) and answer the `/api/v1/*` calls with fake data. No server, no real browser and no network are needed.

Node is used **only for these tests**. The UI itself still ships as plain HTML/CSS/JS with no build step.

## Run

Needs Node 18 or newer.

```bash
cd src/test/ui
npm ci        # first time only
npm test
```

## Files

| File | What it tests |
|---|---|
| `helpers.test.js` | Formatting and device-role helpers |
| `screens.test.js` | What each screen shows: inventory, filters, index warnings, advisory wording, review queue, failed captures |
| `safety-and-edits.test.js` | XSS safety, request headers, validation rules, edit form behaviour |
| `support/load-app.js` | Starts the console in jsdom with a fake API |
| `support/fixtures.js` | Fake API data, built from `docs/examples/inventory.json` |

## Known bugs

None. A test marked `todo` documents a bug that is not fixed yet: it is reported but does not fail the run. Remove the `todo` once the bug is fixed.
