import type { NSMessage, NSPrincipalName } from './needham-schroeder';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

type KeyPairMap = Record<NSPrincipalName, CryptoKeyPair>;

async function encryptJson(pub: CryptoKey, obj: Record<string, string>): Promise<Uint8Array> {
  const plain = encoder.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, plain);
  return new Uint8Array(cipher);
}

async function decryptJson(priv: CryptoKey, data: Uint8Array): Promise<Record<string, string>> {
  const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, toArrayBuffer(data));
  return JSON.parse(decoder.decode(new Uint8Array(plain)));
}

/**
 * The honest, attacker-free run of the patched protocol: Alice really is
 * talking to Bob, so the name sealed into message 2 matches her intended peer
 * and the run completes. This shows the fix does not break normal operation —
 * it is NOT a test of the fix. For that, see runLoweAttackAgainstFix below,
 * which puts Mallory back on the wire.
 */
export async function runNeedhamSchroederWithLoweFix(keys: KeyPairMap): Promise<{ messages: NSMessage[]; accepted: boolean; rejectedReason: string | null }> {
  const intendedPeer: NSPrincipalName = 'Bob';
  const na = randomNonce();
  const nb = randomNonce();

  const m1Obj = { Na: na, A: 'Alice' };
  const m1Cipher = await encryptJson(keys.Bob.publicKey, m1Obj);

  const m2Obj = { Na: na, Nb: nb, B: 'Bob' };
  const m2Cipher = await encryptJson(keys.Alice.publicKey, m2Obj);
  const m2Recv = await decryptJson(keys.Alice.privateKey, m2Cipher);

  let rejectedReason: string | null = null;
  if (m2Recv.B !== intendedPeer) {
    rejectedReason = `identity mismatch: message 2 names "${m2Recv.B}", Alice called ${intendedPeer}`;
  }

  const messages: NSMessage[] = [
    {
      from: 'Alice',
      to: 'Bob',
      step: 1,
      label: 'A -> B: {Na, A}_pkB',
      payloadHex: toHex(m1Cipher),
      decoded: m1Obj,
    },
    {
      from: 'Bob',
      to: 'Alice',
      step: 2,
      label: 'B -> A: {Na, Nb, B}_pkA',
      payloadHex: toHex(m2Cipher),
      decoded: m2Obj,
    },
  ];

  if (!rejectedReason) {
    const m3Obj = { Nb: nb };
    const m3Cipher = await encryptJson(keys.Bob.publicKey, m3Obj);
    messages.push({
      from: 'Alice',
      to: 'Bob',
      step: 3,
      label: 'A -> B: {Nb}_pkB',
      payloadHex: toHex(m3Cipher),
      decoded: m3Obj,
    });
    return { messages, accepted: true, rejectedReason: null };
  }

  return { messages, accepted: false, rejectedReason };
}

export type LoweAttackAgainstFixRun = {
  messages: NSMessage[];
  /** The peer Alice deliberately chose to call — Mallory, a legitimate act. */
  aliceIntendedPeer: NSPrincipalName;
  aliceAborted: boolean;
  rejectedReason: string | null;
  bobAccepted: boolean;
};

/**
 * Gavin Lowe's 1995 relay, replayed against the PATCHED protocol.
 *
 * Mallory does exactly what she does in `runLoweAttack`: Alice legitimately
 * initiates with her, and Mallory re-seals the identical inner payload for Bob
 * to impersonate Alice. The single difference is Bob's reply, which now names
 * him inside the envelope. Alice compares that name against the peer she
 * actually dialled and stops.
 *
 * The abort is a real branch, not a rail: if the identity check is removed the
 * code below carries the run through steps 5 and 6 and Bob is fooled exactly as
 * he is in 1978. That is what makes the accompanying test bite in both
 * directions.
 */
export async function runLoweAttackAgainstFix(keys: KeyPairMap): Promise<LoweAttackAgainstFixRun> {
  const aliceIntendedPeer: NSPrincipalName = 'Mallory';
  const na = randomNonce();

  // 1. Alice initiates with Mallory — she is allowed to talk to anyone.
  const m1Obj = { Na: na, A: 'Alice' };
  const m1Cipher = await encryptJson(keys.Mallory.publicKey, m1Obj);

  // 2. Mallory opens it (sealed under her own key) and re-seals the identical
  //    {Na, A} under Bob's key, so Bob believes Alice is calling him.
  const mRecv = await decryptJson(keys.Mallory.privateKey, m1Cipher);
  const m2Obj = { Na: mRecv.Na, A: 'Alice' };
  const m2Cipher = await encryptJson(keys.Bob.publicKey, m2Obj);

  // 3. Bob answers. THE FIX: he names himself inside the envelope.
  const bRecv = await decryptJson(keys.Bob.privateKey, m2Cipher);
  const nb = randomNonce();
  const m3Obj = { Na: bRecv.Na, Nb: nb, B: 'Bob' };
  const m3Cipher = await encryptJson(keys.Alice.publicKey, m3Obj);

  // 4. Mallory cannot open this (it is under Alice's key) so she relays it
  //    byte-for-byte, which is all the 1978 attack ever needed.
  const m4Cipher = m3Cipher;
  const aRecv = await decryptJson(keys.Alice.privateKey, m4Cipher);

  const messages: NSMessage[] = [
    { from: 'Alice', to: 'Mallory', step: 1, label: 'A -> M: {Na, A}_pkM', payloadHex: toHex(m1Cipher), decoded: m1Obj },
    { from: 'Mallory', to: 'Bob', step: 2, label: 'M -> B: {Na, A}_pkB', payloadHex: toHex(m2Cipher), decoded: m2Obj },
    { from: 'Bob', to: 'Mallory', step: 3, label: 'B -> M: {Na, Nb, B}_pkA', payloadHex: toHex(m3Cipher), decoded: m3Obj },
    { from: 'Mallory', to: 'Alice', step: 4, label: 'M -> A: {Na, Nb, B}_pkA', payloadHex: toHex(m4Cipher), decoded: m3Obj },
  ];

  // Alice's check — the whole of Lowe's fix, on the receiving side.
  if (aRecv.B !== aliceIntendedPeer) {
    return {
      messages,
      aliceIntendedPeer,
      aliceAborted: true,
      rejectedReason: `identity mismatch: message 2 names "${aRecv.B}", Alice called ${aliceIntendedPeer}`,
      bobAccepted: false,
    };
  }

  // Reached only if the identity binding is not enforced: Alice hands Nb to
  // Mallory, Mallory re-seals it for Bob, and Bob authenticates the run as Alice.
  const m5Obj = { Nb: aRecv.Nb };
  const m5Cipher = await encryptJson(keys.Mallory.publicKey, m5Obj);
  const mRecv2 = await decryptJson(keys.Mallory.privateKey, m5Cipher);
  const m6Obj = { Nb: mRecv2.Nb };
  const m6Cipher = await encryptJson(keys.Bob.publicKey, m6Obj);
  const bFinal = await decryptJson(keys.Bob.privateKey, m6Cipher);

  messages.push(
    { from: 'Alice', to: 'Mallory', step: 5, label: 'A -> M: {Nb}_pkM', payloadHex: toHex(m5Cipher), decoded: m5Obj },
    { from: 'Mallory', to: 'Bob', step: 6, label: 'M -> B: {Nb}_pkB', payloadHex: toHex(m6Cipher), decoded: m6Obj },
  );

  return {
    messages,
    aliceIntendedPeer,
    aliceAborted: false,
    rejectedReason: null,
    bobAccepted: bFinal.Nb === nb,
  };
}
