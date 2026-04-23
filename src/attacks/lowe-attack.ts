import type { NSMessage, NSPrincipalName } from '../protocols/needham-schroeder';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

type KeyPairMap = Record<NSPrincipalName, CryptoKeyPair>;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function nonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return toHex(b);
}

async function encrypt(pub: CryptoKey, obj: Record<string, string>): Promise<Uint8Array> {
  const raw = encoder.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw);
  return new Uint8Array(cipher);
}

async function decrypt(priv: CryptoKey, cipher: Uint8Array): Promise<Record<string, string>> {
  const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, toArrayBuffer(cipher));
  return JSON.parse(decoder.decode(new Uint8Array(plain)));
}

export type LoweAttackRun = {
  messages: NSMessage[];
  aliceBelievesPeer: 'Mallory';
  bobBelievesPeer: 'Alice';
  bobAccepted: boolean;
};

export async function runLoweAttack(keys: KeyPairMap): Promise<LoweAttackRun> {
  const na = nonce();
  const m1AtoMObj = { Na: na, A: 'Alice' };
  const m1AtoM = await encrypt(keys.Mallory.publicKey, m1AtoMObj);

  const m2MtoBObj = m1AtoMObj;
  const m2MtoB = await encrypt(keys.Bob.publicKey, m2MtoBObj);

  const bRecv = await decrypt(keys.Bob.privateKey, m2MtoB);
  const nb = nonce();
  const m3BtoAObj = { Na: bRecv.Na, Nb: nb };
  const m3BtoA = await encrypt(keys.Alice.publicKey, m3BtoAObj);

  const m4MtoA = m3BtoA;
  const aRecv = await decrypt(keys.Alice.privateKey, m4MtoA);
  const m5AtoMObj = { Nb: aRecv.Nb };
  const m5AtoM = await encrypt(keys.Mallory.publicKey, m5AtoMObj);

  const m6MtoBObj = { Nb: aRecv.Nb };
  const m6MtoB = await encrypt(keys.Bob.publicKey, m6MtoBObj);
  const bFinal = await decrypt(keys.Bob.privateKey, m6MtoB);

  const messages: NSMessage[] = [
    { from: 'Alice', to: 'Mallory', step: 1, label: 'A -> M: {Na, A}_pkM', payloadHex: toHex(m1AtoM), decoded: m1AtoMObj },
    { from: 'Mallory', to: 'Bob', step: 2, label: 'M -> B: {Na, A}_pkB', payloadHex: toHex(m2MtoB), decoded: m2MtoBObj },
    { from: 'Bob', to: 'Mallory', step: 3, label: 'B -> M: {Na, Nb}_pkA', payloadHex: toHex(m3BtoA), decoded: m3BtoAObj },
    { from: 'Mallory', to: 'Alice', step: 4, label: 'M -> A: {Na, Nb}_pkA', payloadHex: toHex(m4MtoA), decoded: m3BtoAObj },
    { from: 'Alice', to: 'Mallory', step: 5, label: 'A -> M: {Nb}_pkM', payloadHex: toHex(m5AtoM), decoded: m5AtoMObj },
    { from: 'Mallory', to: 'Bob', step: 6, label: 'M -> B: {Nb}_pkB', payloadHex: toHex(m6MtoB), decoded: m6MtoBObj },
  ];

  return {
    messages,
    aliceBelievesPeer: 'Mallory',
    bobBelievesPeer: 'Alice',
    bobAccepted: bFinal.Nb === nb,
  };
}
