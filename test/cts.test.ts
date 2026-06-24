import { describe, expect, it } from 'vitest';
import { ctsCbcDecrypt, ctsCbcEncrypt } from '../src/crypto/cts';
import { toHex } from './helpers';

/**
 * AES-CBC with ciphertext stealing (RFC 3962 / NIST SP 800-38A Addendum).
 * The defining property: ciphertext length exactly equals plaintext length
 * for any input of at least one block, with no padding expansion.
 */
function fixedKey(): Uint8Array {
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) k[i] = (i * 7 + 1) & 0xff;
  return k;
}

function pattern(len: number): Uint8Array {
  const p = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) p[i] = (i * 13 + 5) & 0xff;
  return p;
}

describe('CTS-CBC round-trips across lengths', () => {
  const key = fixedKey();
  // 16 = exactly one block; 17/31/33/47 exercise the stealing path; 32/48 are
  // exact multiples (plain CBC); 100 is a long mixed case.
  for (const len of [16, 17, 31, 32, 33, 47, 48, 64, 100]) {
    it(`length ${len} round-trips and preserves length`, async () => {
      const pt = pattern(len);
      const ct = await ctsCbcEncrypt(key, pt);
      expect(ct.length).toBe(len);
      const back = await ctsCbcDecrypt(key, ct);
      expect(toHex(back)).toBe(toHex(pt));
    });
  }
});

describe('CTS-CBC edge behaviour', () => {
  it('rejects input shorter than one block on encrypt', async () => {
    await expect(ctsCbcEncrypt(fixedKey(), new Uint8Array(15))).rejects.toThrow();
  });

  it('rejects input shorter than one block on decrypt', async () => {
    await expect(ctsCbcDecrypt(fixedKey(), new Uint8Array(15))).rejects.toThrow();
  });

  it('a single bit flip in the ciphertext changes the recovered plaintext', async () => {
    const key = fixedKey();
    const pt = pattern(40);
    const ct = await ctsCbcEncrypt(key, pt);
    ct[0] ^= 0x80;
    const back = await ctsCbcDecrypt(key, ct);
    expect(toHex(back)).not.toBe(toHex(pt));
  });
});
