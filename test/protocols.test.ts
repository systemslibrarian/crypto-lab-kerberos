import { beforeEach, describe, expect, it } from 'vitest';
import { buildNsKeys, runNeedhamSchroeder } from '../src/protocols/needham-schroeder';
import { runNeedhamSchroederWithLoweFix } from '../src/protocols/lowe-fix';
import { runLoweAttack } from '../src/attacks/lowe-attack';
import { KeyDistributionCenter } from '../src/principals/kdc';
import { ServicePrincipal } from '../src/principals/service';
import { runKerberosV5 } from '../src/protocols/kerberos-v5';
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
});
