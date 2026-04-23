const BLOCK_SIZE = 16;

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

async function importAesKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-CBC' }, false, [usage]);
}

async function aesCbc(key: Uint8Array, iv: Uint8Array, data: Uint8Array, mode: 'encrypt' | 'decrypt'): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key, mode);
  const result = mode === 'encrypt'
    ? await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, cryptoKey, toArrayBuffer(data))
    : await crypto.subtle.decrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, cryptoKey, toArrayBuffer(data));
  return new Uint8Array(result);
}

async function aesEcbBlockEncrypt(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const encrypted = await aesCbc(key, zeroIv, block, 'encrypt');
  return encrypted.slice(0, BLOCK_SIZE);
}

async function aesEcbBlockDecrypt(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const decrypted = await aesCbc(key, zeroIv, block, 'decrypt');
  return decrypted.slice(0, BLOCK_SIZE);
}

export async function ctsCbcEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (plaintext.length < BLOCK_SIZE) {
    throw new Error('CTS requires at least one full block');
  }
  if (plaintext.length % BLOCK_SIZE === 0) {
    return aesCbc(key, new Uint8Array(BLOCK_SIZE), plaintext, 'encrypt');
  }

  const m = plaintext.length;
  const r = m % BLOCK_SIZE;
  const n = Math.ceil(m / BLOCK_SIZE);
  const c = new Uint8Array(m);

  let prev = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < n - 2; i += 1) {
    const block = plaintext.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const x = xor(block, prev);
    const y = await aesEcbBlockEncrypt(key, x);
    c.set(y, i * BLOCK_SIZE);
    prev = new Uint8Array(y);
  }

  const penult = plaintext.slice((n - 2) * BLOCK_SIZE, (n - 1) * BLOCK_SIZE);
  const last = plaintext.slice((n - 1) * BLOCK_SIZE);

  const xN1 = xor(penult, prev);
  const yN1 = await aesEcbBlockEncrypt(key, xN1);

  const padded = new Uint8Array(BLOCK_SIZE);
  padded.set(last, 0);
  const xN = xor(padded, yN1);
  const yN = await aesEcbBlockEncrypt(key, xN);

  c.set(yN, (n - 2) * BLOCK_SIZE);
  c.set(yN1.slice(0, r), (n - 1) * BLOCK_SIZE);

  return c;
}

export async function ctsCbcDecrypt(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < BLOCK_SIZE) {
    throw new Error('CTS requires at least one full block');
  }
  if (ciphertext.length % BLOCK_SIZE === 0) {
    return aesCbc(key, new Uint8Array(BLOCK_SIZE), ciphertext, 'decrypt');
  }

  const m = ciphertext.length;
  const r = m % BLOCK_SIZE;
  const n = Math.ceil(m / BLOCK_SIZE);
  const p = new Uint8Array(m);

  let prev = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < n - 2; i += 1) {
    const block = ciphertext.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const x = await aesEcbBlockDecrypt(key, block);
    const y = xor(x, prev);
    p.set(y, i * BLOCK_SIZE);
    prev = block;
  }

  const cN1Prime = ciphertext.slice((n - 2) * BLOCK_SIZE, (n - 1) * BLOCK_SIZE);
  const cNPrime = ciphertext.slice((n - 1) * BLOCK_SIZE);

  const x = await aesEcbBlockDecrypt(key, cN1Prime);
  const pN = new Uint8Array(r);
  for (let i = 0; i < r; i += 1) {
    pN[i] = x[i] ^ cNPrime[i];
  }

  const cN1 = new Uint8Array(BLOCK_SIZE);
  cN1.set(cNPrime, 0);
  cN1.set(x.slice(r), r);

  const y = await aesEcbBlockDecrypt(key, cN1);
  const pN1 = xor(y, prev);

  p.set(pN1, (n - 2) * BLOCK_SIZE);
  p.set(pN, (n - 1) * BLOCK_SIZE);

  return p;
}
