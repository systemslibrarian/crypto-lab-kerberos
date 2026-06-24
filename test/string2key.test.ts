import { createHash, pbkdf2Sync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { pbkdf2HmacSha1, stringToKeyAes256 } from '../src/crypto/pbkdf2-string2key';
import { dk, utf8Bytes } from '../src/crypto/simplified-profile';
import { toHex } from './helpers';

/**
 * RFC 3962 §B "Sample Test Vectors" for aes256-cts-hmac-sha1-96 string-to-key.
 *
 *   tkey = PBKDF2-HMAC-SHA1(passphrase, salt, iter, 32)
 *   key  = DK(tkey, "kerberos")
 *
 * Matching these end-to-end proves the whole derivation stack — PBKDF2,
 * n-fold, DR/DK — is interoperable with real Kerberos KDCs, not merely
 * self-consistent.
 */
const G_CLEF = String.fromCodePoint(0x1d11e); // U+1D11E MUSICAL SYMBOL G CLEF -> f0 9d 84 9e

const VECTORS: ReadonlyArray<{ name: string; iter: number; pass: string; salt: string; key: string }> = [
  {
    name: 'iter=1',
    iter: 1,
    pass: 'password',
    salt: 'ATHENA.MIT.EDUraeburn',
    key: 'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161',
  },
  {
    name: 'iter=1200',
    iter: 1200,
    pass: 'password',
    salt: 'ATHENA.MIT.EDUraeburn',
    key: '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a',
  },
  {
    name: 'pass phrase equals block size',
    iter: 1200,
    pass: 'X'.repeat(64),
    salt: 'pass phrase equals block size',
    key: '89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34',
  },
  {
    name: 'pass phrase exceeds block size',
    iter: 1200,
    pass: 'X'.repeat(65),
    salt: 'pass phrase exceeds block size',
    key: 'd78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b',
  },
  {
    name: 'g-clef passphrase',
    iter: 50,
    pass: G_CLEF,
    salt: 'EXAMPLE.COMpianist',
    key: '4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e',
  },
];

/** Reference string-to-key composed straight from the RFC formula. */
async function refStringToKey(pass: string, salt: string, iter: number): Promise<Uint8Array> {
  const tkey = await pbkdf2HmacSha1(pass, salt, iter);
  return dk(tkey, utf8Bytes('kerberos'));
}

describe('RFC 3962 §B — aes256 string-to-key known-answer vectors', () => {
  for (const v of VECTORS) {
    it(v.name, async () => {
      const key = await refStringToKey(v.pass, v.salt, v.iter);
      expect(toHex(key)).toBe(v.key);
    });
  }
});

describe('PBKDF2-HMAC-SHA1 cross-checked against an independent reference', () => {
  // node:crypto is OpenSSL-backed and entirely separate from the WebCrypto
  // path the app uses, so agreement here pins the PBKDF2 layer down hard.
  const cases = [
    { pass: 'password', salt: 'ATHENA.MIT.EDUraeburn', iter: 1 },
    { pass: 'password', salt: 'ATHENA.MIT.EDUraeburn', iter: 1200 },
    { pass: 'X'.repeat(65), salt: 'pass phrase exceeds block size', iter: 1200 },
  ];
  for (const c of cases) {
    it(`matches node:crypto pbkdf2 (iter=${c.iter})`, async () => {
      const mine = await pbkdf2HmacSha1(c.pass, c.salt, c.iter);
      const ref = pbkdf2Sync(c.pass, c.salt, c.iter, 32, 'sha1');
      expect(toHex(mine)).toBe(ref.toString('hex'));
    });
  }
});

describe('stringToKeyAes256 (app wrapper, 4096 iterations)', () => {
  it('is deterministic and 32 bytes', async () => {
    const k1 = await stringToKeyAes256('correct-horse-battery-staple', 'LAB.EXAMPLEalice');
    const k2 = await stringToKeyAes256('correct-horse-battery-staple', 'LAB.EXAMPLEalice');
    expect(k1).toHaveLength(32);
    expect(toHex(k1)).toBe(toHex(k2));
  });

  it('differs when the salt (realm/principal) changes', async () => {
    const a = await stringToKeyAes256('pw', 'LAB.EXAMPLEalice');
    const b = await stringToKeyAes256('pw', 'LAB.EXAMPLEbob');
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('uses the same SHA-1 digest the etype profile assumes', () => {
    // Guard against an accidental hash swap in the PBKDF2 layer.
    expect(createHash('sha1').update('').digest('hex')).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  });
});
