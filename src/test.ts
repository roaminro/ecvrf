import { prove, proof_to_hash, verify, keygen, validate_key } from './index';
const elliptic = require("elliptic");
const EC = new elliptic.ec("secp256k1");
// const secret_key =
//   'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
// const public_key =
//   '0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6';
// const { public_key, secret_key } = keygen();
// const pk = EC.keyPair({ priv: 'bab7fd6e5bd624f4ea0c33f7e7219262a6fa93a945a8964d9f110148286b7b37', privEnc: 'hex'})
const pk = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex'})
const secret_key = pk.getPrivate('hex')
const public_key = pk.getPublic('hex')

validate_key(public_key)
const alpha = '73616d706c65';

const pi = prove(secret_key, alpha);
const beta = proof_to_hash(pi);
const res = verify(public_key, pi, alpha);
console.log('pi', pi);
console.log('pi', new Uint8Array(Buffer.from(pi, 'hex')));
console.log('beta', beta);
console.log('beta', new Uint8Array(Buffer.from(beta, 'hex')));
console.log('res', res);
