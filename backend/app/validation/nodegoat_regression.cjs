// Focused application regression, not a full NodeGoat security or MongoDB test.
// Only harmless numeric inputs are sent to NodeGoat's deliberately vulnerable handler.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const parser = require('body-parser');
// NodeGoat logs its full configuration at import; keep it out of validation artifacts.
const originalLog = console.log;
let Handler;
try { console.log = () => {}; Handler = require('./app/routes/contributions'); }
finally { console.log = originalLog; }
let server, base, saved;
const db = { collection(name) { return {
  update(query, value, options, callback) { saved = { ...value }; callback(null); },
  findOne(query, callback) { callback(null, { userName: 'review-test', firstName: 'Test', lastName: 'User' }); },
}; } };
before(async () => {
  const app = express();
  app.use(parser.json());
  app.use(parser.urlencoded({ extended: false })); // same configuration as server.js
  app.use((req, res, next) => {
    req.session = { userId: 7 };
    res.render = (view, data) => res.json({ view, ...data });
    next();
  });
  app.post('/contributions', new Handler(db).handleContributionsUpdate);
  app.use((error, req, res, next) => res.status(error.status || 500).json({ error: 'request rejected' }));
  await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { if (server) await new Promise(resolve => server.close(resolve)); });
async function post(body, type = 'application/x-www-form-urlencoded') {
  return fetch(base + '/contributions', { method: 'POST', headers: { 'content-type': type }, body });
}
test('form parser and real contribution route persist valid percentages', async () => {
  const res = await post('preTax=5&afterTax=3&roth=2');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).updateSuccess, true);
  assert.deepEqual(saved, { userId: 7, preTax: 5, afterTax: 3, roth: 2 });
});
test('real route rejects negative percentages', async () => {
  const res = await post('preTax=-1&afterTax=3&roth=2');
  assert.equal((await res.json()).updateError, 'Invalid contribution percentages');
});
test('real route enforces total contribution limit', async () => {
  const res = await post('preTax=20&afterTax=20&roth=2');
  assert.equal((await res.json()).updateError, 'Contribution percentages cannot exceed 30 %');
});
test('JSON parser accepts valid numeric contribution request', async () => {
  const res = await post(JSON.stringify({ preTax: 2, afterTax: 2, roth: 2 }), 'application/json');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).updateSuccess, true);
});
test('parser rejects malformed JSON before application handler', async () => {
  assert.equal((await post('{', 'application/json')).status, 400);
});
test('parser enforces default body size limit', async () => {
  assert.equal((await post('preTax=' + '1'.repeat(110000))).status, 413);
});
