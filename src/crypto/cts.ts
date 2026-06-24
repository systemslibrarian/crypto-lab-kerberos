import { unsafe } from '@noble/ciphers/aes.js';

const BLOCK_SIZE = 16;

/**
 * AES-CBC with ciphertext stealing (CS3, the variant RFC 3962 uses for
 * Kerberos): the last two cipher blocks are swapped and the final block is
 * truncated so the ciphertext is exactly the length of the plaintext — no
 * padding, no expansion.
 *
 * The block primitive is @noble/ciphers' raw (unpadded) AES block cipher. We
 * deliberately do NOT use WebCrypto's AES-CBC here: it always applies PKCS#7
 * padding, and on decrypt it validates that padding, so using it for the raw
 * single-block operations CTS needs throws "bad decrypt" whenever a recovered
 * block doesn't happen to end in valid padding bytes. The block cipher is
 * verified against the FIPS-197 AES-256 known-answer vector in test/cts.test.ts.
 *
 * noble mutates the block in place and reuses the key schedule across calls, so
 * each operation gets a fresh copy of its input block.
 */
function aesBlock(key: Uint8Array): { encrypt(b: Uint8Array): Uint8Array<ArrayBuffer>; decrypt(b: Uint8Array): Uint8Array<ArrayBuffer> } {
  const encKey = unsafe.expandKeyLE(key);
  const decKey = unsafe.expandKeyDecLE(key);
  // noble mutates the block in place; copy first so the input is untouched and
  // the result is a fresh, owned buffer.
  return {
    encrypt: (b) => {
      const blk = Uint8Array.from(b);
      unsafe.encryptBlock(encKey, blk);
      return blk;
    },
    decrypt: (b) => {
      const blk = Uint8Array.from(b);
      unsafe.decryptBlock(decKey, blk);
      return blk;
    },
  };
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

export async function ctsCbcEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (plaintext.length < BLOCK_SIZE) {
    throw new Error('CTS requires at least one full block');
  }
  const aes = aesBlock(key);
  const m = plaintext.length;
  const r = m % BLOCK_SIZE;

  // Exact multiple of the block size (including a single block): plain CBC,
  // zero IV, no stealing and no padding.
  if (r === 0) {
    const out = new Uint8Array(m);
    let prev = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < m; i += BLOCK_SIZE) {
      prev = aes.encrypt(xor(plaintext.subarray(i, i + BLOCK_SIZE), prev));
      out.set(prev, i);
    }
    return out;
  }

  const n = Math.ceil(m / BLOCK_SIZE);
  const c = new Uint8Array(m);

  let prev = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < n - 2; i += 1) {
    prev = aes.encrypt(xor(plaintext.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE), prev));
    c.set(prev, i * BLOCK_SIZE);
  }

  const penult = plaintext.subarray((n - 2) * BLOCK_SIZE, (n - 1) * BLOCK_SIZE);
  const last = plaintext.subarray((n - 1) * BLOCK_SIZE);

  const yN1 = aes.encrypt(xor(penult, prev));

  const padded = new Uint8Array(BLOCK_SIZE);
  padded.set(last, 0);
  const yN = aes.encrypt(xor(padded, yN1));

  // Swap: the full final block goes in the penultimate slot, the truncated
  // previous block goes last (CS3 ordering).
  c.set(yN, (n - 2) * BLOCK_SIZE);
  c.set(yN1.subarray(0, r), (n - 1) * BLOCK_SIZE);

  return c;
}

export async function ctsCbcDecrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < BLOCK_SIZE) {
    throw new Error('CTS requires at least one full block');
  }
  const aes = aesBlock(key);
  const m = ciphertext.length;
  const r = m % BLOCK_SIZE;

  if (r === 0) {
    const out = new Uint8Array(m);
    let prev: Uint8Array = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < m; i += BLOCK_SIZE) {
      const cblk = ciphertext.subarray(i, i + BLOCK_SIZE);
      out.set(xor(aes.decrypt(cblk), prev), i);
      prev = cblk;
    }
    return out;
  }

  const n = Math.ceil(m / BLOCK_SIZE);
  const p = new Uint8Array(m);

  let prev: Uint8Array = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < n - 2; i += 1) {
    const block = ciphertext.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    p.set(xor(aes.decrypt(block), prev), i * BLOCK_SIZE);
    prev = block;
  }

  const cN1Prime = ciphertext.subarray((n - 2) * BLOCK_SIZE, (n - 1) * BLOCK_SIZE); // = yN
  const cNPrime = ciphertext.subarray((n - 1) * BLOCK_SIZE); // = yN1[0:r]

  const x = aes.decrypt(cN1Prime); // = padded ⊕ yN1
  const pN = new Uint8Array(r);
  for (let i = 0; i < r; i += 1) pN[i] = x[i] ^ cNPrime[i];

  // Reconstruct the full penultimate ciphertext block yN1 = cNPrime || x[r:].
  const cN1 = new Uint8Array(BLOCK_SIZE);
  cN1.set(cNPrime, 0);
  cN1.set(x.subarray(r), r);

  const pN1 = xor(aes.decrypt(cN1), prev);

  p.set(pN1, (n - 2) * BLOCK_SIZE);
  p.set(pN, (n - 1) * BLOCK_SIZE);

  return p;
}
