import BN from 'bn.js';
import { sha256 } from 'js-sha256';
import * as elliptic from 'elliptic';
import * as utils from 'minimalistic-crypto-utils';

type Point = elliptic.curve.base.BasePoint;

const EC = new elliptic.ec('secp256k1');
const suite = [0xfe];

function stringToPoint(s: Uint8Array): Point | 'INVALID' {
  try {
    return EC.curve.decodePoint(s);
  } catch {
    return 'INVALID';
  }
}

function arbitraryStringToPoint(s: Uint8Array): Point | 'INVALID' {
  if (s.length !== 32) {
    throw new Error('s should be 32 byte');
  }
  return stringToPoint(new Uint8Array([2, ...s]));
}

function hashToCurve(publicKey: Point, alpha: Uint8Array) {
  let hash: Point | 'INVALID' = 'INVALID';
  let ctr = 0;
  while ((hash == 'INVALID' || hash.isInfinity()) && ctr < 256) {
    const hash_string = sha256
      .create()
      .update(suite)
      .update([0x01])
      .update(publicKey.encode('array', true))
      .update(alpha)
      .update([ctr])
      .digest();
    // @ts-ignore hash_string is a number[]
    hash = arbitraryStringToPoint(hash_string); // cofactor = 1, skip multiply
    ctr += 1;
  }
  if (hash == 'INVALID') {
    throw new Error('hashToCurve failed');
  }
  return hash;
}

export function nonceGeneration(secretKey: BN, h_string: Uint8Array) {
  const h1 = sha256.array(h_string);

  let K = new Array(32).fill(0);
  let V = new Array(32).fill(1);

  K = sha256.hmac
    // @ts-ignore
    .create(K)
    .update(V)
    .update([0x00])
    .update(secretKey.toArray())
    .update(h1)
    .digest();

  V = sha256.hmac
    // @ts-ignore
    .create(K)
    .update(new Uint8Array(32).fill(1))
    .digest();

  K = sha256.hmac
    // @ts-ignore
    .create(K)
    .update(V)
    .update([0x01])
    .update(secretKey.toArray())
    .update(h1)
    .digest();

  V = sha256.hmac
    // @ts-ignore
    .create(K)
    .update(V)
    .digest();

  V = sha256.hmac
    // @ts-ignore
    .create(K)
    .update(V)
    .digest(); // qLen = hLen = 32, skip loop

  return new BN(V, 'hex');
}

function hashPoints(...points: Point[]) {
  const str = [...suite, 0x02];
  for (const point of points) {
    str.push(...point.encode('array', true));
  }

  const c_string = sha256.digest(str);
  const truncated_c_string = c_string.slice(0, 16);
  const c = new BN(truncated_c_string);

  return c;
}

function decodeProof(pi: Uint8Array) {
  const gamma_string = pi.slice(0, 33);
  const c_string = pi.slice(33, 33 + 16);
  const s_string = pi.slice(33 + 16, 33 + 16 + 32);
  const Gamma = stringToPoint(gamma_string);
  if (Gamma == 'INVALID') {
    return 'INVALID';
  }

  const c = new BN(c_string);
  const s = new BN(s_string);

  return {
    Gamma,
    c,
    s,
  };
}

function _prove(secretKey: BN, alpha: Uint8Array): number[] {
  const publicKey = EC.keyFromPrivate(secretKey.toArray()).getPublic();
  const H = hashToCurve(publicKey, alpha);
  const h_string = H.encode('array', true);
  const Gamma = H.mul(secretKey);
  // @ts-ignore h_string is a number[]
  const k = nonceGeneration(secretKey, h_string);
  const c = hashPoints(H, Gamma, EC.g.mul(k), H.mul(k));
  const s = k.add(c.mul(secretKey)).umod(EC.n);
  const pi = [
    ...Gamma.encode('array', true),
    ...c.toArray('be', 16),
    ...s.toArray('be', 32),
  ];
  return pi;
}

function _proofToHash(pi: Uint8Array): number[] {
  const D = decodeProof(pi);
  if (D == 'INVALID') {
    throw new Error('Invalid proof');
  }
  const { Gamma } = D;
  const beta = sha256
    .create()
    .update(suite)
    .update([0x03])
    .update(Gamma.encode('array', true))
    .digest();

  return beta;
}

function _verify(publicKey: Point, pi: Uint8Array, alpha: Uint8Array) {
  const D = decodeProof(pi);
  if (D == 'INVALID') {
    throw new Error('Invalid proof');
  }
  const { Gamma, c, s } = D;
  const H = hashToCurve(publicKey, alpha);
  const U = EC.g.mul(s).add(publicKey.mul(c).neg());
  const V = H.mul(s).add(Gamma.mul(c).neg());
  const c2 = hashPoints(H, Gamma, U, V);
  if (!c.eq(c2)) {
    throw new Error('Invalid proof');
  }
  return _proofToHash(pi);
}

function _validateKey(publicKey_string: Uint8Array) {
  const publicKey = stringToPoint(publicKey_string);
  if (publicKey == 'INVALID' || publicKey.isInfinity()) {
    throw new Error('Invalid public key');
  }
  return publicKey;
}

export function keygen() {
  const keypair = EC.genKeyPair();
  const secretKey = keypair.getPrivate('hex');
  const publicKey = keypair.getPublic('hex');
  return {
    secretKey,
    publicKey,
  };
}

/**
  * Generates proof from a secret key and message
  * @param secretKey the secret key to use to generate the proof (hex string)
  * @param alpha the message to use to generate the proof (hex string)
  * @returns the proof as an hex string
  * @example
  * ```js
  * const { prove, proofToHash, verify } = require('@roamin/ecvrf');
  * const elliptic = require('elliptic');
  *
  * const EC = new elliptic.ec('secp256k1');
  *
  * const SECRET = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex' });
  *
  * const msg = Buffer.from('sample').toString('hex');
  *
  * // VRF proof and hash output
  * const proof = prove(SECRET.getPrivate(), msg);
  * ```
  */
export function prove(secretKey: string, alpha: string): string {
  const pi = _prove(new BN(secretKey, 'hex'), utils.toArray(alpha, 'hex'));
  return utils.toHex(pi);
}

/**
  * Generates the hash of a proof
  * @param pi the proof to hash (hex string)
  * @returns the hash proof as an hex string
  * @example
  * ```js
  * const { prove, proofToHash, verify } = require('@roamin/ecvrf');
  * const elliptic = require('elliptic');
  *
  * const EC = new elliptic.ec('secp256k1');
  *
  * const SECRET = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex' });
  *
  * const msg = Buffer.from('sample').toString('hex');
  *
  * // VRF proof and hash output
  * const proof = prove(SECRET.getPrivate(), msg);
  * const hash = proofToHash(proof);
  * ```
  */
export function proofToHash(pi: string): string {
  const beta = _proofToHash(utils.toArray(pi, 'hex'));
  return utils.toHex(beta);
}

/**
  * Verifies the provided VRF proof and computes the VRF hash output
  * @param publicKey the public key to use to verify the proof (hex string)
  * @param pi the proof to verify (hex string)
  * @param alpha the message to verify (hex string)
  * @returns the hash proof as an hex string
  * @example
  * ```js
  * const { prove, proofToHash, verify } = require('@roamin/ecvrf');
  * const elliptic = require('elliptic');
  *
  * const EC = new elliptic.ec('secp256k1');
  *
  * const SECRET = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex' });
  *
  * const msg = Buffer.from('sample').toString('hex');
  *
  * // VRF proof and hash output
  * const proof = prove(SECRET.getPrivate(), msg);
  * const hash = proofToHash(proof);
  * 
  * // VRF proof verification (returns VRF hash output)
  * const beta = verify(SECRET.getPublic('hex'), proof, msg);
  * ```
  */
export function verify(publicKey: string, pi: string, alpha: string): string {
  const beta = _verify(
    EC.curve.decodePoint(publicKey, 'hex'),
    utils.toArray(pi, 'hex'),
    utils.toArray(alpha, 'hex')
  );
  return utils.toHex(beta);
}

export function validateKey(publicKey: string) {
  _validateKey(utils.toArray(publicKey, 'hex'));
  return;
}
