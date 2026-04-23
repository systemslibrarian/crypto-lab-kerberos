import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { ctsCbcDecrypt, ctsCbcEncrypt } from './cts';
import { dk, usageConstant } from './simplified-profile';

const CONFOUNDER_SIZE = 16;
const HMAC_SIZE = 12;

export type ETypeCipherText = {
  body: Uint8Array;
  checksum: Uint8Array;
  raw: Uint8Array;
};

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a[i] ^ b[i];
  }
  return mismatch === 0;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function deriveKeKi(baseKey: Uint8Array, usage: number): Promise<{ ke: Uint8Array; ki: Uint8Array }> {
  const ke = await dk(baseKey, usageConstant(usage, 0xaa));
  const ki = await dk(baseKey, usageConstant(usage, 0x55));
  return { ke, ki };
}

export async function encryptAes256CtsHmacSha196(baseKey: Uint8Array, usage: number, plaintext: Uint8Array): Promise<ETypeCipherText> {
  const { ke, ki } = await deriveKeKi(baseKey, usage);
  const confounder = randomBytes(CONFOUNDER_SIZE);
  const clear = concat(confounder, plaintext);
  const body = await ctsCbcEncrypt(ke, clear);
  const fullMac = hmac(sha1, ki, clear);
  const checksum = fullMac.slice(0, HMAC_SIZE);
  return { body, checksum, raw: concat(body, checksum) };
}

export async function decryptAes256CtsHmacSha196(baseKey: Uint8Array, usage: number, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length <= HMAC_SIZE + CONFOUNDER_SIZE) {
    throw new Error('ciphertext too short');
  }
  const body = ciphertext.slice(0, ciphertext.length - HMAC_SIZE);
  const sentMac = ciphertext.slice(ciphertext.length - HMAC_SIZE);
  const { ke, ki } = await deriveKeKi(baseKey, usage);
  const clear = await ctsCbcDecrypt(ke, body);
  const localMac = hmac(sha1, ki, clear).slice(0, HMAC_SIZE);
  if (!bytesEqual(sentMac, localMac)) {
    throw new Error('HMAC verification failed');
  }
  return clear.slice(CONFOUNDER_SIZE);
}
