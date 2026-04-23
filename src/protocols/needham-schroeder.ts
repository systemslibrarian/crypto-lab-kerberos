export type NSPrincipalName = 'Alice' | 'Bob' | 'Mallory';

export type NSMessage = {
  from: NSPrincipalName;
  to: NSPrincipalName;
  step: number;
  label: string;
  payloadHex: string;
  decoded: Record<string, string>;
};

type KeyPairMap = Record<NSPrincipalName, CryptoKeyPair>;

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

async function generatePair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

async function encryptJson(pub: CryptoKey, obj: Record<string, string>): Promise<Uint8Array> {
  const plain = encoder.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, plain);
  return new Uint8Array(cipher);
}

async function decryptJson(priv: CryptoKey, data: Uint8Array): Promise<Record<string, string>> {
  const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, toArrayBuffer(data));
  return JSON.parse(decoder.decode(new Uint8Array(plain)));
}

export async function buildNsKeys(): Promise<KeyPairMap> {
  return {
    Alice: await generatePair(),
    Bob: await generatePair(),
    Mallory: await generatePair(),
  };
}

export async function runNeedhamSchroeder(keys: KeyPairMap): Promise<{ messages: NSMessage[]; accepted: boolean }> {
  const na = randomNonce();

  const m1Obj = { Na: na, A: 'Alice' };
  const m1Cipher = await encryptJson(keys.Bob.publicKey, m1Obj);
  const m1: NSMessage = {
    from: 'Alice',
    to: 'Bob',
    step: 1,
    label: 'A -> B: {Na, A}_pkB',
    payloadHex: toHex(m1Cipher),
    decoded: m1Obj,
  };

  const m1Recv = await decryptJson(keys.Bob.privateKey, m1Cipher);
  const nb = randomNonce();

  const m2Obj = { Na: m1Recv.Na, Nb: nb };
  const m2Cipher = await encryptJson(keys.Alice.publicKey, m2Obj);
  const m2: NSMessage = {
    from: 'Bob',
    to: 'Alice',
    step: 2,
    label: 'B -> A: {Na, Nb}_pkA',
    payloadHex: toHex(m2Cipher),
    decoded: m2Obj,
  };

  const m2Recv = await decryptJson(keys.Alice.privateKey, m2Cipher);
  const m3Obj = { Nb: m2Recv.Nb };
  const m3Cipher = await encryptJson(keys.Bob.publicKey, m3Obj);
  const m3: NSMessage = {
    from: 'Alice',
    to: 'Bob',
    step: 3,
    label: 'A -> B: {Nb}_pkB',
    payloadHex: toHex(m3Cipher),
    decoded: m3Obj,
  };

  const m3Recv = await decryptJson(keys.Bob.privateKey, m3Cipher);
  const accepted = m3Recv.Nb === nb;

  return { messages: [m1, m2, m3], accepted };
}
