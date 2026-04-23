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

export async function runNeedhamSchroederWithLoweFix(keys: KeyPairMap): Promise<{ messages: NSMessage[]; accepted: boolean; rejectedReason: string | null }> {
  const na = randomNonce();
  const nb = randomNonce();

  const m1Obj = { Na: na, A: 'Alice' };
  const m1Cipher = await encryptJson(keys.Bob.publicKey, m1Obj);

  const m2Obj = { Na: na, Nb: nb, B: 'Bob' };
  const m2Cipher = await encryptJson(keys.Alice.publicKey, m2Obj);
  const m2Recv = await decryptJson(keys.Alice.privateKey, m2Cipher);

  let rejectedReason: string | null = null;
  if (m2Recv.B !== 'Bob') {
    rejectedReason = 'identity mismatch';
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
