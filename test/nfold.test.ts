import { describe, expect, it } from 'vitest';
import { nFold, utf8Bytes } from '../src/crypto/simplified-profile';
import { fromHex, toHex } from './helpers';

/**
 * Known-answer tests for the n-fold primitive, taken verbatim from
 * RFC 3961 §A.1 "n-fold". n-fold is the heart of the simplified-profile
 * DR/DK key-derivation function, so getting these exactly right is what
 * makes every derived key in the demo RFC-correct.
 *
 * Sizes in the RFC are quoted in bits; nFold() takes a byte length.
 */
const VECTORS: ReadonlyArray<{ input: string; bits: number; expected: string }> = [
  { input: '012345', bits: 64, expected: 'be072631276b1955' },
  { input: 'password', bits: 56, expected: '78a07b6caf85fa' },
  { input: 'Rough Consensus, and Running Code', bits: 64, expected: 'bb6ed30870b7f0e0' },
  { input: 'password', bits: 168, expected: '59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e' },
  { input: 'MASSACHVSETTS INSTITVTE OF TECHNOLOGY', bits: 192, expected: 'db3b0d8f0b061e603282b308a50841229ad798fab9540c1b' },
  { input: 'Q', bits: 168, expected: '518a54a215a8452a518a54a215a8452a518a54a215' },
  { input: 'ba', bits: 168, expected: 'fb25d531ae8974499f52fd92ea9857c4ba24cf297e' },
  { input: 'kerberos', bits: 64, expected: '6b65726265726f73' },
  { input: 'kerberos', bits: 128, expected: '6b65726265726f737b9b5b2b93132b93' },
  { input: 'kerberos', bits: 168, expected: '8372c236344e5f1550cd0747e15d62ca7a5a3bcea4' },
  { input: 'kerberos', bits: 256, expected: '6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4' },
];

describe('RFC 3961 §A.1 — n-fold known-answer vectors', () => {
  for (const { input, bits, expected } of VECTORS) {
    it(`${bits}-fold("${input}")`, () => {
      const out = nFold(utf8Bytes(input), bits / 8);
      expect(toHex(out)).toBe(expected);
    });
  }

  it('rejects empty input', () => {
    expect(() => nFold(new Uint8Array(0), 16)).toThrow();
  });

  it('is deterministic', () => {
    const a = nFold(utf8Bytes('kerberos'), 16);
    const b = nFold(utf8Bytes('kerberos'), 16);
    expect(toHex(a)).toBe(toHex(b));
  });

  it('produces the requested length for non-divisible sizes', () => {
    expect(nFold(utf8Bytes('abc'), 21)).toHaveLength(21);
    expect(fromHex('00')).toHaveLength(1); // helper sanity
  });
});
