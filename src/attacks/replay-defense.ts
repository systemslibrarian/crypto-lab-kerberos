import { encryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { decryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type ReplayCache = Map<string, number>;

function parse<T>(bytes: Uint8Array): T {
  return JSON.parse(decoder.decode(bytes)) as T;
}

function jsonBytes(v: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(v));
}

export async function detectReplay(
  sessionKey: Uint8Array,
  authenticatorPlain: { cname: string; ctime: number; cusec: number },
  cache: ReplayCache,
  nowMs: number,
  skewMs: number,
): Promise<{ accepted: boolean; reason: string; replayKey: string; authenticatorCipher: Uint8Array }> {
  for (const [key, ts] of cache.entries()) {
    if (nowMs - ts > skewMs) {
      cache.delete(key);
    }
  }

  const cipher = await encryptAes256CtsHmacSha196(sessionKey, 11, jsonBytes(authenticatorPlain));
  const clear = await decryptAes256CtsHmacSha196(sessionKey, 11, cipher.raw);
  const auth = parse<{ cname: string; ctime: number; cusec: number }>(clear);
  const replayKey = `${auth.cname}:${auth.ctime}:${auth.cusec}`;

  if (cache.has(replayKey)) {
    return { accepted: false, reason: 'replay cache hit', replayKey, authenticatorCipher: cipher.raw };
  }

  cache.set(replayKey, nowMs);
  return { accepted: true, reason: 'fresh authenticator', replayKey, authenticatorCipher: cipher.raw };
}
