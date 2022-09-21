/* eslint-disable @typescript-eslint/ban-ts-comment */
import { prove, proofToHash, verify, nonceGeneration } from '../src/index';
import elliptic from 'elliptic';
const EC = new elliptic.ec('secp256k1');

// @ts-ignore priv can be an hex string here
const SECRET = EC.keyPair({ priv: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', privEnc: 'hex' });

const msg = Buffer.from('sample').toString('hex');

describe('vrf tests', () => {

  test('nonce generation', () => {
    const nonce = nonceGeneration(SECRET.getPrivate(), Buffer.from(msg, 'hex'));
    expect(nonce.toString('hex')).toStrictEqual('a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60');
  });

  test('prove', () => {
    const proof = prove(SECRET.getPrivate('hex'), msg);
    expect(proof).toStrictEqual('031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9');
  });

  test('proof to hash', () => {
    const proof = prove(SECRET.getPrivate('hex'), msg);
    const hash = proofToHash(proof);

    expect(hash).toStrictEqual('612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81');
  });

  test('verify', () => {
    const proof = prove(SECRET.getPrivate('hex'), msg);

    const hash = verify(SECRET.getPublic('hex'), proof, msg);

    expect(hash).toStrictEqual('612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81');
  });
});