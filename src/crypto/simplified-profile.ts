const BLOCK_SIZE = 16;

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

function rotateRight(input: Uint8Array, bits: number): Uint8Array {
  const totalBits = input.length * 8;
  const normalizedBits = ((bits % totalBits) + totalBits) % totalBits;
  if (normalizedBits === 0) {
    return input.slice();
  }

  const result = new Uint8Array(input.length);
  for (let i = 0; i < totalBits; i += 1) {
    const srcBit = (i + normalizedBits) % totalBits;
    const srcByte = Math.floor(srcBit / 8);
    const srcOffset = 7 - (srcBit % 8);
    const dstByte = Math.floor(i / 8);
    const dstOffset = 7 - (i % 8);
    const bit = (input[srcByte] >> srcOffset) & 1;
    result[dstByte] |= bit << dstOffset;
  }
  return result;
}

export function nFold(input: Uint8Array, size: number): Uint8Array {
  if (input.length === 0) {
    throw new Error('n-fold input must be non-empty');
  }

  const result = new Uint8Array(size);
  const lcm = (a: number, b: number): number => {
    const gcd = (x: number, y: number): number => (y === 0 ? x : gcd(y, x % y));
    return (a * b) / gcd(a, b);
  };

  const total = lcm(input.length, size);
  const repetitions = total / input.length;

  for (let i = 0; i < repetitions; i += 1) {
    const rotated = rotateRight(input, 13 * i);
    for (let j = 0; j < size; j += 1) {
      result[j] = (result[j] + rotated[(j + i) % rotated.length]) & 0xff;
    }
  }

  return result;
}

function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

async function aesCbcEncryptBlocks(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-CBC' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toArrayBuffer(iv) }, cryptoKey, toArrayBuffer(data));
  return new Uint8Array(encrypted);
}

export function randomToKey(input: Uint8Array): Uint8Array {
  if (input.length !== 32) {
    throw new Error('random-to-key for aes256 requires 32 bytes');
  }
  return input.slice();
}

export async function dr(baseKey: Uint8Array, constant: Uint8Array): Promise<Uint8Array> {
  if (baseKey.length !== 32) {
    throw new Error('DR requires a 32-byte aes256 key');
  }

  const folded = nFold(constant, BLOCK_SIZE);
  let state = folded;
  const zeroIv = new Uint8Array(BLOCK_SIZE);
  const output = new Uint8Array(32);

  for (let i = 0; i < 2; i += 1) {
    const encrypted = await aesCbcEncryptBlocks(baseKey, zeroIv, state);
    const block = encrypted.slice(encrypted.length - BLOCK_SIZE);
    output.set(block, i * BLOCK_SIZE);
    state = xorBlock(state, block);
  }

  return output;
}

export async function dk(baseKey: Uint8Array, constant: Uint8Array): Promise<Uint8Array> {
  const seed = await dr(baseKey, constant);
  return randomToKey(seed);
}

export function usageConstant(usage: number, trailer: number): Uint8Array {
  const c = new Uint8Array(5);
  const view = new DataView(c.buffer);
  view.setUint32(0, usage >>> 0, false);
  c[4] = trailer & 0xff;
  return c;
}

export function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(input: string): Uint8Array {
  const clean = input.trim().toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
