// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };

function register() {
  const key = Q.generateKey();
  return { key, env: Q.register({ key, objectName: 'Quantova Sat 1', cosparId: '2026-001A', regime: 'leo' }) };
}

test('replay as another record type is refused', async () => {
  const { env } = register();
  const forged = JSON.parse(JSON.stringify(env));
  forged.type = 'launch';
  const r = await Q.verify(forged, Object.assign({ type: 'launch' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another orbit id is refused', async () => {
  const { env } = register();
  const forged = JSON.parse(JSON.stringify(env));
  forged.statement.orbitId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { env } = register();
  const mutations = [
    (s) => { s.objectName = 'Other Sat'; },
    (s) => { s.cosparId = '2026-002A'; },
    (s) => { s.regime = 'geo'; },
    (s) => { s.registeredAt = '2000-01-01T00:00:00.000Z'; },
    (s) => { s.note = 'added'; },
  ];
  for (const mutate of mutations) {
    const forged = JSON.parse(JSON.stringify(env));
    mutate(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from a key other than the named signer does not verify', async () => {
  const a = register();
  const b = register();
  const forged = JSON.parse(JSON.stringify(a.env));
  forged.signer = b.env.signer;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('a non canonical base64 public key or signature is rejected at parse', async () => {
  const { env } = register();
  for (const field of ['publicKey']) {
    const forged = JSON.parse(JSON.stringify(env));
    forged.signer[field] = forged.signer[field].slice(0, -2) + '==';
    const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
    assert.strictEqual(r.status, 'invalid');
  }
  const bad = JSON.parse(JSON.stringify(env));
  bad.signature = bad.signature.slice(0, -4) + 'AAAA';
  const r = await Q.verify(bad, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('an envelope with an unexpected field is refused', async () => {
  const { env } = register();
  const forged = JSON.parse(JSON.stringify(env));
  forged.extra = 1;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const withStatementExtra = JSON.parse(JSON.stringify(env));
  withStatementExtra.statement.extra = 1;
  const r2 = await Q.verify(withStatementExtra, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('a statement carrying a prototype polluting key is refused', async () => {
  const { env } = register();
  const forged = JSON.parse(JSON.stringify(env));
  forged.statement = JSON.parse('{"__proto__":{"polluted":true},"orbitId":"' + env.statement.orbitId + '"}');
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised by the SDK', () => {
  const key = Q.generateKey();
  assert.strictEqual(JSON.stringify({ key }), '{"key":"SecretKey [hidden]"}');
  assert.strictEqual(String(key), 'SecretKey [hidden]');
  assert.strictEqual(require('util').inspect(key), 'SecretKey [hidden]');
});

test('an anchor recorded under another record kind is not accepted', async () => {
  const { env } = register();
  const anchored = JSON.parse(JSON.stringify(env));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, Object.assign({ type: 'register', requireAnchor: true }, { network: 'testnet', strict: false }));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => /anchor/.test(c.name) && !c.ok));
});
