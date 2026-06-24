import { describe, expect, it } from 'vitest';
import {
  decryptAes256CtsHmacSha196,
  deriveKeKi,
  encryptAes256CtsHmacSha196,
} from '../src/crypto/etype-aes256';
import { toHex } from './helpers';

/**
 * aes256-cts-hmac-sha1-96 (etype 18), the encryption profile every Kerberos
 * ticket and authenticator in the demo rides on. The encryption uses a random
 * 16-byte confounder, so these are structural / round-trip / integrity tests
 * rather than fixed known-answer vectors (the confounder makes ciphertext
 * non-deterministic by design).
 */
function randomKey(): Uint8Array {
  const k = new Uint8Array(32);
  crypto.getRandomValues(k);
  return k;
}

const enc = new TextEncoder();

describe('aes256-cts-hmac-sha1-96 round-trip', () => {
  it('decrypts what it encrypts, for several plaintext sizes', async () => {
    const key = randomKey();
    for (const msg of ['', 'a', 'the quick brown fox', 'x'.repeat(200)]) {
      const pt = enc.encode(msg);
      const ct = await encryptAes256CtsHmacSha196(key, 11, pt);
      const back = await decryptAes256CtsHmacSha196(key, 11, ct.raw);
      expect(new TextDecoder().decode(back)).toBe(msg);
    }
  });

  it('is non-deterministic (fresh confounder per call)', async () => {
    const key = randomKey();
    const pt = enc.encode('same plaintext');
    const a = await encryptAes256CtsHmacSha196(key, 11, pt);
    const b = await encryptAes256CtsHmacSha196(key, 11, pt);
    expect(toHex(a.raw)).not.toBe(toHex(b.raw));
  });

  it('appends a 12-byte (HMAC-SHA1-96) truncated checksum', async () => {
    const key = randomKey();
    const pt = enc.encode('check the tag length');
    const ct = await encryptAes256CtsHmacSha196(key, 11, pt);
    expect(ct.checksum).toHaveLength(12);
    expect(ct.raw.length).toBe(ct.body.length + 12);
    // confounder (16) + plaintext, then CTS preserves length, plus 12 tag.
    expect(ct.body.length).toBe(16 + pt.length);
  });
});

describe('integrity protection', () => {
  it('rejects a flipped bit in the HMAC tag', async () => {
    const key = randomKey();
    const ct = await encryptAes256CtsHmacSha196(key, 11, enc.encode('payload'));
    const tampered = ct.raw.slice();
    tampered[tampered.length - 1] ^= 0x01;
    await expect(decryptAes256CtsHmacSha196(key, 11, tampered)).rejects.toThrow(/HMAC/);
  });

  it('rejects a flipped bit in the ciphertext body', async () => {
    const key = randomKey();
    const ct = await encryptAes256CtsHmacSha196(key, 11, enc.encode('a longer payload to span blocks'));
    const tampered = ct.raw.slice();
    tampered[0] ^= 0x01;
    await expect(decryptAes256CtsHmacSha196(key, 11, tampered)).rejects.toThrow(/HMAC/);
  });

  it('rejects the wrong key', async () => {
    const ct = await encryptAes256CtsHmacSha196(randomKey(), 11, enc.encode('secret'));
    await expect(decryptAes256CtsHmacSha196(randomKey(), 11, ct.raw)).rejects.toThrow();
  });

  it('rejects the wrong key usage (different Ke/Ki)', async () => {
    const key = randomKey();
    const ct = await encryptAes256CtsHmacSha196(key, 11, enc.encode('usage-bound'));
    await expect(decryptAes256CtsHmacSha196(key, 12, ct.raw)).rejects.toThrow();
  });

  it('rejects truncated ciphertext', async () => {
    const key = randomKey();
    await expect(decryptAes256CtsHmacSha196(key, 11, new Uint8Array(10))).rejects.toThrow();
  });
});

describe('key-usage key derivation', () => {
  it('derives distinct Ke and Ki', async () => {
    const key = randomKey();
    const { ke, ki } = await deriveKeKi(key, 11);
    expect(ke).toHaveLength(32);
    expect(ki).toHaveLength(32);
    expect(toHex(ke)).not.toBe(toHex(ki));
  });

  it('derives different keys for different usages', async () => {
    const key = randomKey();
    const a = await deriveKeKi(key, 11);
    const b = await deriveKeKi(key, 12);
    expect(toHex(a.ke)).not.toBe(toHex(b.ke));
  });
});
