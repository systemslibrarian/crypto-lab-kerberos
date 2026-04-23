import { dk, utf8Bytes } from './simplified-profile';

const PBKDF2_ITERATIONS = 4096;
const DERIVED_LENGTH = 32;

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

export async function pbkdf2HmacSha1(password: string, salt: string, iterations = PBKDF2_ITERATIONS): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey('raw', toArrayBuffer(utf8Bytes(password)), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-1',
      salt: toArrayBuffer(utf8Bytes(salt)),
      iterations,
    },
    keyMaterial,
    DERIVED_LENGTH * 8,
  );
  return new Uint8Array(bits);
}

export async function stringToKeyAes256(password: string, salt: string): Promise<Uint8Array> {
  const tkey = await pbkdf2HmacSha1(password, salt, PBKDF2_ITERATIONS);
  return dk(tkey, utf8Bytes('kerberos'));
}
