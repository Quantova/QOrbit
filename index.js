// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const B = require('./lib/orbit');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: B.generateKey,
  publicKey: B.publicKey,
  keyId: B.keyId,
  describeKey: B.describeKey,
  objectRef: B.objectRef,
  register: B.register,
  launch: B.launch,
  maneuver: B.maneuver,
  transfer: B.transfer,
  deorbit: B.deorbit,
  anchor: B.anchor,
  complete: B.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  REGIMES: F.REGIMES,
  MANEUVERS: F.MANEUVERS,
  DISPOSALS: F.DISPOSALS,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
