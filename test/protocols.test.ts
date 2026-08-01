import { beforeEach, describe, expect, it } from 'vitest';
import { buildNsKeys, runNeedhamSchroeder } from '../src/protocols/needham-schroeder';
import { runLoweAttackAgainstFix, runNeedhamSchroederWithLoweFix } from '../src/protocols/lowe-fix';
import { runLoweAttack } from '../src/attacks/lowe-attack';
import { KDC_ERR_PREAUTH_REQUIRED, KeyDistributionCenter } from '../src/principals/kdc';
import { ServicePrincipal } from '../src/principals/service';
import { replayApReq, runKerberosV5 } from '../src/protocols/kerberos-v5';
import { decryptAes256CtsHmacSha196 } from '../src/crypto/etype-aes256';
import { stringToKeyAes256 } from '../src/crypto/pbkdf2-string2key';
import { toHex } from './helpers';

const MIN = 60 * 1000;

function freshService(kdc: KeyDistributionCenter): ServicePrincipal {
  const key = kdc.registerService('http/web.lab.example');
  return new ServicePrincipal('http/web.lab.example', 'LAB.EXAMPLE', toHex(key));
}

async function freshKdc(): Promise<KeyDistributionCenter> {
  const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
  await kdc.registerUser('alice', 'correct-horse-battery-staple');
  return kdc;
}

describe('Needham-Schroeder public-key', () => {
  it('authenticates on a clean run (no attacker)', async () => {
    const ns = await runNeedhamSchroeder(await buildNsKeys());
    expect(ns.accepted).toBe(true);
    expect(ns.messages).toHaveLength(3);
  });
});

describe('Lowe man-in-the-middle attack (1995)', () => {
  it('makes Bob accept a run he believes is from Alice, who never contacted him', async () => {
    const lowe = await runLoweAttack(await buildNsKeys());
    expect(lowe.bobAccepted).toBe(true);
    expect(lowe.aliceBelievesPeer).toBe('Mallory');
    expect(lowe.bobBelievesPeer).toBe('Alice');
    expect(lowe.messages).toHaveLength(6);
  });
});

describe('Lowe fix (identity binding in message 2)', () => {
  it('accepts an honest direct run and binds Bob’s identity into message 2', async () => {
    const fixed = await runNeedhamSchroederWithLoweFix(await buildNsKeys());
    expect(fixed.accepted).toBe(true);
    expect(fixed.rejectedReason).toBeNull();
    const m2 = fixed.messages.find((m) => m.step === 2);
    expect(m2?.decoded.B).toBe('Bob'); // the one-line patch
  });

  it('blocks the Lowe relay that the unpatched protocol accepts (both directions)', async () => {
    const keys = await buildNsKeys();

    // Same attacker, same relay, same keys — only the protocol differs.
    const unpatched = await runLoweAttack(keys);
    const patched = await runLoweAttackAgainstFix(keys);

    // Direction 1: without the fix the attack works.
    expect(unpatched.bobAccepted, 'unpatched NS must still be vulnerable').toBe(true);

    // Direction 2: with the fix Alice aborts and Bob is never fooled.
    expect(patched.aliceAborted, 'Lowe fix must abort the relayed run').toBe(true);
    expect(patched.bobAccepted, 'Bob must not authenticate the forged run').toBe(false);
    expect(patched.rejectedReason).toMatch(/identity mismatch/i);
  });

  it('runs Mallory’s real relay against the fix, and dies at the identity check', async () => {
    const run = await runLoweAttackAgainstFix(await buildNsKeys());

    // Mallory is genuinely on the wire: Alice talks to her, she re-seals for Bob.
    expect(run.aliceIntendedPeer).toBe('Mallory');
    expect(run.messages.some((m) => m.from === 'Mallory' && m.to === 'Bob')).toBe(true);

    // Bob's reply names him — that name is what Alice checks.
    const m3 = run.messages.find((m) => m.step === 3);
    expect(m3?.decoded.B).toBe('Bob');

    // The run stops at step 4: Nb is never returned, so there is no step 5 or 6.
    expect(run.messages.map((m) => m.step)).toEqual([1, 2, 3, 4]);
    expect(run.messages.some((m) => m.label.includes('{Nb}'))).toBe(false);
  });
});

describe('Kerberos v5 AS / TGS / AP', () => {
  let kdc: KeyDistributionCenter;
  let service: ServicePrincipal;
  let now: number;

  beforeEach(async () => {
    kdc = await freshKdc();
    service = freshService(kdc);
    now = 1_700_000_000_000; // fixed, deterministic wall clock for the test
  });

  it('completes the full exchange and mutually authenticates', async () => {
    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    expect(run.apAccepted).toBe(true);
    expect(run.apReason).toBeUndefined();
    // AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP
    expect(run.records.map((r) => r.label)).toEqual(['AS-REQ', 'AS-REP', 'TGS-REQ', 'TGS-REP', 'AP-REQ', 'AP-REP']);
    expect(run.apRep).toBeDefined();
  });

  it('rejects the wrong password at the AS exchange', async () => {
    await expect(runKerberosV5(kdc, service, 'alice', 'wrong-password', now)).rejects.toThrow();
  });

  it('accepts a client clock within +/-5 minutes of the KDC', async () => {
    for (const off of [-4, 0, 4]) {
      const k = await freshKdc();
      const s = freshService(k);
      const run = await runKerberosV5(k, s, 'alice', 'correct-horse-battery-staple', now + off * MIN, now);
      expect(run.apAccepted, `offset ${off}min`).toBe(true);
    }
  });

  it('rejects a client clock skewed beyond 5 minutes', async () => {
    for (const off of [6, 15, -6, -30]) {
      const k = await freshKdc();
      const s = freshService(k);
      const run = await runKerberosV5(k, s, 'alice', 'correct-horse-battery-staple', now + off * MIN, now);
      expect(run.apAccepted, `offset ${off}min`).toBe(false);
      expect(run.apReason).toMatch(/skew/i);
    }
  });

  it('rejects a replayed AP-REQ (same cname/ctime/cusec)', async () => {
    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    expect(run.apAccepted).toBe(true);
    const { cname, ctime, cusec } = run.lastAuth;
    const replayKey = `${cname}:${ctime}:${cusec}`;
    // The accepted AP-REQ is now in the replay cache; the exact same authenticator must be refused.
    expect(service.hasReplay(replayKey)).toBe(true);
  });

  it('re-submits the captured AP-REQ bytes: the crypto verifies, freshness refuses', async () => {
    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    expect(run.apAccepted).toBe(true);
    expect(run.lastApReq).toBeDefined();

    const replayed = await replayApReq(
      service,
      run.serviceTicket,
      run.lastAuth.cname,
      run.clientSvcKey,
      run.lastApReq as Uint8Array,
      run.serviceNowMs,
    );

    // The service really decrypted the resubmitted ciphertext and its HMAC
    // verified — the rejection is a freshness decision, not a crypto failure.
    expect(replayed.cryptoVerified).toBe(true);
    expect(replayed.accepted).toBe(false);
    expect(replayed.reason).toBe('replay cache hit');
    // And the bytes really were the captured ones, not a fresh authenticator.
    expect(replayed.apReqCipher).toEqual(run.lastApReq);
    expect(replayed.records[0].bytesHex).toBe(
      Array.from(run.lastApReq as Uint8Array).map((b) => b.toString(16).padStart(2, '0')).join(''),
    );
  });

  it('accepts the same ciphertext against a service that has not seen it', async () => {
    // Control for the test above: the bytes are valid, so a service with an
    // empty replay cache accepts them. The rejection above is the cache, not
    // a mangled ciphertext.
    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    const twin = new ServicePrincipal(service.name, service.realm, service.keyHex);
    const replayed = await replayApReq(
      twin,
      run.serviceTicket,
      run.lastAuth.cname,
      run.clientSvcKey,
      run.lastApReq as Uint8Array,
      run.serviceNowMs,
    );
    expect(replayed.cryptoVerified).toBe(true);
    expect(replayed.accepted).toBe(true);
  });
});

describe('Pre-authentication (PA-ENC-TIMESTAMP)', () => {
  const now = 1_700_000_000_000;
  const HOUR = 60 * 60 * 1000;

  it('refuses an AS-REQ with no PA-DATA when the account requires pre-auth', async () => {
    const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
    await kdc.registerUser('alice', 'correct-horse-battery-staple');
    expect(kdc.requiresPreauth('alice')).toBe(true);
    await expect(kdc.issueAsRep('alice', 'n', now, 8 * HOUR)).rejects.toThrow(KDC_ERR_PREAUTH_REQUIRED);
  });

  it('sets pre-authent on the TGT only when pre-auth actually happened', async () => {
    const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
    await kdc.registerUser('alice', 'correct-horse-battery-staple');
    await kdc.registerUser('legacy', 'weak', { requirePreauth: false });
    const service = freshService(kdc);

    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    expect(run.preauthenticated).toBe(true);
    const tgtBody = await kdc.decryptTgt(run.tgt);
    expect(tgtBody.flags).toContain('pre-authent');

    // The pre-auth-less path must not claim the flag it did not earn.
    const roastable = await kdc.issueAsRep('legacy', 'n', now, 8 * HOUR);
    expect(roastable.preauthenticated).toBe(false);
    const roastableBody = await kdc.decryptTgt(roastable.tgt);
    expect(roastableBody.flags).not.toContain('pre-authent');
  });

  it('propagates pre-authent to the service ticket instead of asserting it', async () => {
    const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
    await kdc.registerUser('alice', 'correct-horse-battery-staple');
    const service = freshService(kdc);
    const run = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', now);
    const stClear = await decryptAes256CtsHmacSha196(
      Uint8Array.from((service.keyHex.match(/../g) ?? []).map((h) => Number.parseInt(h, 16))),
      2,
      run.serviceTicket.cipher,
    );
    const stBody = JSON.parse(new TextDecoder().decode(stClear)) as { flags: string[] };
    expect(stBody.flags).toContain('pre-authent');
  });

  it('is what stands between an account and AS-REP roasting', async () => {
    // With pre-auth off, an unauthenticated request yields password-derived
    // ciphertext, and the right password is confirmed by the HMAC verifying.
    const realm = 'LEGACY.EXAMPLE';
    const kdc = new KeyDistributionCenter(realm);
    await kdc.registerUser('svc-legacy', 'weak-password', { requirePreauth: false });

    const rep = await kdc.issueAsRep('svc-legacy', 'attacker-nonce', now, 8 * HOUR);
    const wrong = await stringToKeyAes256('not-the-password', `${realm}svc-legacy`);
    await expect(decryptAes256CtsHmacSha196(wrong, 3, rep.encPartForClient)).rejects.toThrow();

    const right = await stringToKeyAes256('weak-password', `${realm}svc-legacy`);
    await expect(decryptAes256CtsHmacSha196(right, 3, rep.encPartForClient)).resolves.toBeDefined();
  });
});
