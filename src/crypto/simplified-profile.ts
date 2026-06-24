const BLOCK_SIZE = 16;

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

/**
 * n-fold, as defined in RFC 3961 §5.3 (originally Blumenthal & Bellovin).
 *
 * Replicates `input` while rotating each copy right by 13 bits, then folds the
 * pieces together with 1's-complement (end-around-carry) addition to produce
 * exactly `size` bytes. This is a direct port of MIT krb5's `krb5int_nfold`
 * (`nfold.c`) — the reference implementation — and is verified against the
 * RFC 3961 §A.1 known-answer vectors in test/nfold.test.ts.
 *
 * `size` is the output length in bytes (the RFC quotes it in bits).
 */
export function nFold(input: Uint8Array, size: number): Uint8Array {
  if (input.length === 0) {
    throw new Error('n-fold input must be non-empty');
  }

  const inBytes = input.length;
  const outBytes = size;

  // lcm(outBytes, inBytes) via Euclid's gcd.
  let a = outBytes;
  let b = inBytes;
  while (b !== 0) {
    const c = b;
    b = a % b;
    a = c;
  }
  const lcm = (outBytes * inBytes) / a;

  const out = new Uint8Array(outBytes);
  let acc = 0;

  for (let i = lcm - 1; i >= 0; i -= 1) {
    // Most-significant bit position in `input` that contributes to this byte.
    const msbit = (
      ((inBytes << 3) - 1)
      + (((inBytes << 3) + 13) * Math.floor(i / inBytes))
      + ((inBytes - (i % inBytes)) << 3)
    ) % (inBytes << 3);

    acc += (
      (
        (input[((inBytes - 1) - (msbit >> 3)) % inBytes] << 8)
        | input[(inBytes - (msbit >> 3)) % inBytes]
      ) >> ((msbit & 7) + 1)
    ) & 0xff;

    acc += out[i % outBytes];
    out[i % outBytes] = acc & 0xff;
    acc >>= 8; // carry into the next byte
  }

  // Fold any leftover carry back in (the end-around part of 1's-complement add).
  if (acc !== 0) {
    for (let i = outBytes - 1; i >= 0; i -= 1) {
      acc += out[i];
      out[i] = acc & 0xff;
      acc >>= 8;
    }
  }

  return out;
}

/**
 * Encrypt exactly one 16-byte block under AES with a zero IV. WebCrypto's
 * AES-CBC always appends a PKCS#7 padding block, so a single-block plaintext
 * comes back as two ciphertext blocks; the first is the true E(block) we want
 * (the second is E(padding ⊕ C1) and must be discarded).
 */
async function aesEncryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-CBC' }, false, ['encrypt']);
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(zeroIv) }, cryptoKey, toArrayBuffer(block));
  return new Uint8Array(encrypted).slice(0, BLOCK_SIZE);
}

export function randomToKey(input: Uint8Array): Uint8Array {
  if (input.length !== 32) {
    throw new Error('random-to-key for aes256 requires 32 bytes');
  }
  return input.slice();
}

/**
 * DR (derive-random), RFC 3961 §5.1. n-fold the constant to one cipher block,
 * then run AES in ciphertext-feedback with a zero IV — each ciphertext block
 * becomes the next plaintext block — concatenating output until we have at
 * least the key length, then truncating. For aes256 that is two 16-byte
 * blocks (K1 = E(n-fold(constant)), K2 = E(K1)) → 32 bytes.
 *
 * Verified against RFC 3962 §B string-to-key vectors in test/string2key.test.ts.
 */
export async function dr(baseKey: Uint8Array, constant: Uint8Array): Promise<Uint8Array> {
  if (baseKey.length !== 32) {
    throw new Error('DR requires a 32-byte aes256 key');
  }

  const output = new Uint8Array(32);
  let block = nFold(constant, BLOCK_SIZE);
  for (let i = 0; i < 2; i += 1) {
    block = await aesEncryptBlock(baseKey, block);
    output.set(block, i * BLOCK_SIZE);
  }

  return output;
}

export async function dk(baseKey: Uint8Array, constant: Uint8Array): Promise<Uint8Array> {
  const seed = await dr(baseKey, constant);
  return randomToKey(seed);
}

export function usageConstant(usage: number, trailer: number): Uint8Array {
  const c = new Uint8Array(5);
  const view = new DataView(c.buffer);
  view.setUint32(0, usage >>> 0, false);
  c[4] = trailer & 0xff;
  return c;
}

export function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(input: string): Uint8Array {
  const clean = input.trim().toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
