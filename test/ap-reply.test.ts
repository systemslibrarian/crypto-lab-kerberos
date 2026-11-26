import { expect, it, vi } from 'vitest';
import * as etype from '../src/crypto/etype-aes256';
import { KeyDistributionCenter } from '../src/principals/kdc';
import { ServicePrincipal } from '../src/principals/service';
import { encryptAes256CtsHmacSha196 } from '../src/crypto/etype-aes256';
import { runKerberosV5, verifyApReply } from '../src/protocols/kerberos-v5';

it('checks reply integrity and both fields from the client authenticator', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const sent = { ctime: 1_700_000_000_000, cusec: 27 };
  const clear = new TextEncoder().encode(JSON.stringify(sent));
  const reply = (await encryptAes256CtsHmacSha196(key, 12, clear)).raw;

  expect(await verifyApReply(key, reply, sent)).toBe(true);
  expect(await verifyApReply(key, reply, { ...sent, ctime: sent.ctime + 1 })).toBe(false);
  expect(await verifyApReply(key, reply, { ...sent, cusec: sent.cusec + 1 })).toBe(false);
  const damaged = reply.slice();
  damaged[damaged.length - 1] ^= 1;
  expect(await verifyApReply(key, damaged, sent)).toBe(false);
});

it('withholds mutual authentication when the client cannot open the AP-REP', async () => {
  const kdc = new KeyDistributionCenter('CLASS.EXAMPLE');
  await kdc.registerUser('reader', 'classroom password');
  const key = kdc.registerService('library');
  const keyHex = Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('');
  const service = new ServicePrincipal('library', 'CLASS.EXAMPLE', keyHex);
  const decrypt = etype.decryptAes256CtsHmacSha196;
  const spy = vi.spyOn(etype, 'decryptAes256CtsHmacSha196').mockImplementation(
    (sessionKey, usage, bytes) => {
      if (usage === 12) throw new Error('reply could not be opened');
      return decrypt(sessionKey, usage, bytes);
    },
  );
  try {
    const result = await runKerberosV5(kdc, service, 'reader', 'classroom password', 1_700_000_000_000);
    expect(result.records.at(-1)?.label).toBe('AP-REP');
    expect(result.apAccepted).toBe(false);
    expect(result.apReason).toBe('client could not authenticate AP-REP');
  } finally {
    spy.mockRestore();
  }
});
