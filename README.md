# QOrbit

QOrbit is a live production post quantum registration and custody record tool for orbital objects and satellites on the Quantova network. It proves the registration, launch, maneuver, transfer and deorbit of an orbital object, and it lets any third party confirm that history without trusting the party that created it.

QOrbit proves records without disclosing them. Object identities and operator details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no sensitive detail is ever published.

## What it records

Each record is a signed envelope of one of five types.

1. register, an operator states the name, international designator and orbital regime of an orbital object.
2. launch, a launch authority records the catalogue number and launch site of the object.
3. maneuver, the controller records an orbit maneuver of a stated kind.
4. transfer, the operator of an object moves it to another party.
5. deorbit, the holder records the end of life disposal of the object.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of an object forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qorbit
```

## Use

```js
const qorbit = require('@quantovainc/qorbit');

const operator = qorbit.generateKey();
const object = qorbit.register({
  key: operator,
  objectName: 'Quantova Sat 1',
  cosparId: '2026-001A',
  regime: 'leo',
  operatorLabel: 'Quantova Space',
});

const anchored = await qorbit.anchor(object, { seed, index: 0, network: 'testnet' });
const result = await qorbit.verify(anchored[0], { type: 'register', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to an operator, authority or controller is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
