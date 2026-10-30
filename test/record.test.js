// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function registerObject(key) {
  return Q.register({ key, objectName: 'Quantova Sat 1', cosparId: '2026-001A', regime: 'leo', operatorLabel: 'Quantova Space' });
}

test('a registered object is a well formed signed record of the operator', () => {
  const operator = freshKey();
  const obj = registerObject(operator);
  assert.strictEqual(obj.format, 'qorbit/1');
  assert.strictEqual(obj.type, 'register');
  assert.strictEqual(obj.algorithm, 'ML-DSA-65');
  assert.strictEqual(obj.signer.id, Q.keyId(operator));
  assert.strictEqual(obj.statement.operatorKeyId, Q.keyId(operator));
  assert.match(obj.statement.orbitId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(obj.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(obj.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the launch, maneuver and transfer records chain to the same object', () => {
  const operator = freshKey();
  const authority = freshKey();
  const controller = freshKey();
  const buyer = freshKey();
  const obj = registerObject(operator);
  const lau = Q.launch({ key: authority, register: obj, noradId: '54321', launchSite: 'Kourou ELA 4' });
  const man = Q.maneuver({ key: controller, record: obj, maneuverKind: 'stationkeeping' });
  const moved = Q.transfer({ key: operator, record: man, to: Q.keyId(buyer), toLabel: 'Orbital Holdings Ltd' });
  assert.strictEqual(lau.statement.orbitId, obj.statement.orbitId);
  assert.strictEqual(lau.statement.registerRef, Q.recordRef(obj));
  assert.strictEqual(man.statement.priorRef, Q.recordRef(obj));
  assert.strictEqual(moved.statement.orbitId, obj.statement.orbitId);
  assert.strictEqual(moved.statement.fromKeyId, Q.keyId(operator));
  assert.strictEqual(moved.statement.toKeyId, Q.keyId(buyer));
  assert.strictEqual(moved.statement.priorRef, Q.recordRef(man));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const base = { key, objectName: 'S', cosparId: 'C1', regime: 'leo' };
  assert.throws(() => Q.register(Object.assign({}, base, { regime: 'interstellar' })), /regime must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { objectName: '' })), /objectName cannot be empty/);
  assert.throws(() => Q.register(Object.assign({}, base, { cosparId: '' })), /cosparId is 1 to/);
  assert.throws(() => Q.register(Object.assign({}, base, { unknownField: 1 })), /is not an option of register/);
  const obj = registerObject(key);
  assert.throws(() => Q.maneuver({ key, record: obj, maneuverKind: 'warp' }), /maneuverKind must be one of/);
  assert.throws(() => Q.deorbit({ key, record: obj, disposal: 'vaporise' }), /disposal must be one of/);
});

test('a transfer refuses a recipient equal to the sender', () => {
  const holder = freshKey();
  const obj = registerObject(holder);
  assert.throws(() => Q.transfer({ key: holder, record: obj, to: Q.keyId(holder) }), /the receiving key must differ/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => registerObject(new Uint8Array(16)), /32 byte Uint8Array seed/);
  assert.throws(() => registerObject(new Uint8Array(32)), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const operator = freshKey();
  const obj = registerObject(operator);
  const ok = await Q.verify(obj, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'register');
  assert.strictEqual(ok.orbitId, obj.statement.orbitId);
  const wrongType = await Q.verify(obj, { type: 'launch', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(obj, { type: 'register', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const operator = freshKey();
  const obj = registerObject(operator);
  const forged = JSON.parse(JSON.stringify(obj));
  forged.statement.regime = 'geo';
  const r = await Q.verify(forged, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a record to the record before it', async () => {
  const operator = freshKey();
  const controller = freshKey();
  const obj = registerObject(operator);
  const man = Q.maneuver({ key: controller, record: obj, maneuverKind: 'raising' });
  const good = await Q.verify(man, { type: 'maneuver', network: 'testnet', requireAnchor: false, strict: false, prior: obj });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherObj = registerObject(operator);
  const bad = await Q.verify(man, { type: 'maneuver', network: 'testnet', requireAnchor: false, strict: false, prior: otherObj });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('objectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.objectRef(secret, '2026-001A');
  const b = Q.objectRef(secret, '2026-001A');
  const c = Q.objectRef(secret, '2026-001B');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the orbital line', () => {
  assert.strictEqual(Q.KIND, 1407);
  assert.strictEqual(Q.FORMAT, 'qorbit/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'launch', 'maneuver', 'transfer', 'deorbit']);
  assert.deepStrictEqual([...Q.REGIMES], ['leo', 'meo', 'geo', 'heo', 'other']);
  assert.deepStrictEqual([...Q.DISPOSALS], ['reentry', 'graveyard', 'retrieval']);
});
