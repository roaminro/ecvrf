Verifiable Random Function (VRF)
------------------

This library has an implementation of an ECVRF based on the [IETF draft 05](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-05.html) using the secp256k1 curve, `SHA256` as hash function and `try-and-increment` as hash to curve method (cipher suite `SECP256K1_SHA256_TAI`). The cipher suite code used is `0xFE` for compatibility with other implementations.

### Node
```sh
# with npm
npm install @roamin/ecvrf

# with yarn
yarn add @roamin/ecvrf
```

### Usage

```js
const { prove, proofToHash, verify } = require('@roamin/ecvrf');
const elliptic = require('elliptic');

const EC = new elliptic.ec('secp256k1');

const SECRET = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex' });

const msg = Buffer.from('sample').toString('hex');

// VRF proof and hash output
const proof = prove(SECRET.getPrivate(), msg);
const hash = proofToHash(proof);

// VRF proof verification (returns VRF hash output)
const beta = verify(SECRET.getPublic('hex'), proof, msg);
```