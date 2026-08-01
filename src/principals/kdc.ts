import { decryptAes256CtsHmacSha196, encryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { stringToKeyAes256 } from '../crypto/pbkdf2-string2key';

export type EncTicket = {
  etype: 18;
  kvno: number;
  cipher: Uint8Array;
};

export type TicketBody = {
  client_principal: string;
  realm: string;
  session_key_hex: string;
  starttime: number;
  endtime: number;
  authtime: number;
  flags: string[];
  sname: string;
};

/**
 * PA-ENC-TIMESTAMP (RFC 4120 §5.2.7.2, padata-type 2): the client's proof that
 * it already holds the long-term key, sent *with* the AS-REQ so the KDC never
 * hands password-derived ciphertext to an unauthenticated requester.
 */
export type PaEncTimestamp = {
  padataType: 2;
  cipher: Uint8Array;
};

export const KDC_ERR_PREAUTH_REQUIRED = 'KDC_ERR_PREAUTH_REQUIRED';
export const KDC_ERR_PREAUTH_FAILED = 'KDC_ERR_PREAUTH_FAILED';

// RFC 4120 §7.5.1 key usage 1 — PA-ENC-TIMESTAMP encrypted with the client key.
const KU_PA_ENC_TIMESTAMP = 1;
const PREAUTH_SKEW_MS = 5 * 60 * 1000;

export type AsRep = {
  tgt: EncTicket;
  encPartForClient: Uint8Array;
  nonce: string;
  endtime: number;
  realm: string;
  sname: string;
  preauthenticated: boolean;
};

type UserAccount = {
  password: string;
  requirePreauth: boolean;
};

export type TgsRep = {
  serviceTicket: EncTicket;
  encPartForClient: Uint8Array;
  endtime: number;
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(input: string): Uint8Array {
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function jsonBytes(obj: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(obj));
}

function parseJson<T>(bytes: Uint8Array): T {
  return JSON.parse(decoder.decode(bytes)) as T;
}

export class KeyDistributionCenter {
  readonly realm: string;
  readonly tgsPrincipal: string;
  readonly tgsKey: Uint8Array;
  readonly users = new Map<string, UserAccount>();
  readonly services = new Map<string, Uint8Array>();

  constructor(realm: string) {
    this.realm = realm;
    this.tgsPrincipal = `krbtgt/${realm}`;
    this.tgsKey = randomBytes(32);
  }

  /**
   * Register a principal. `requirePreauth` defaults to true, matching a modern
   * KDC. Setting it false is what produces an AS-REP-roastable account — the
   * exhibit the threat panel cracks live.
   */
  async registerUser(name: string, password: string, options: { requirePreauth?: boolean } = {}): Promise<void> {
    this.users.set(name, { password, requirePreauth: options.requirePreauth ?? true });
  }

  requiresPreauth(name: string): boolean {
    return this.users.get(name)?.requirePreauth ?? true;
  }

  registerService(serviceName: string, keyHex?: string): Uint8Array {
    const key = keyHex ? fromHex(keyHex) : randomBytes(32);
    this.services.set(serviceName, key);
    return key;
  }

  async buildClientKey(name: string): Promise<Uint8Array> {
    const account = this.users.get(name);
    if (!account) {
      throw new Error('unknown user');
    }
    return stringToKeyAes256(account.password, `${this.realm}${name}`);
  }

  /**
   * Verify a PA-ENC-TIMESTAMP. The client encrypted a timestamp under its own
   * long-term key; if it decrypts and the HMAC verifies, the requester really
   * does hold that key. Throws otherwise — nothing password-derived is emitted.
   */
  private async verifyPreauth(clientKey: Uint8Array, padata: PaEncTimestamp, nowMs: number): Promise<void> {
    let stamp: { patimestamp: number; pausec: number };
    try {
      const clear = await decryptAes256CtsHmacSha196(clientKey, KU_PA_ENC_TIMESTAMP, padata.cipher);
      stamp = parseJson<{ patimestamp: number; pausec: number }>(clear);
    } catch {
      throw new Error(`${KDC_ERR_PREAUTH_FAILED}: PA-ENC-TIMESTAMP did not decrypt under the client key`);
    }
    if (Math.abs(nowMs - stamp.patimestamp) > PREAUTH_SKEW_MS) {
      throw new Error(`${KDC_ERR_PREAUTH_FAILED}: PA-ENC-TIMESTAMP outside the ±5 minute window`);
    }
  }

  async issueAsRep(
    client: string,
    nonce: string,
    nowMs: number,
    lifetimeMs: number,
    padata?: PaEncTimestamp,
  ): Promise<AsRep> {
    const clientKey = await this.buildClientKey(client);

    // Pre-authentication, for real: without it the KDC would hand a
    // password-derived enc-part to anyone who asks (AS-REP roasting).
    if (!padata && this.requiresPreauth(client)) {
      throw new Error(`${KDC_ERR_PREAUTH_REQUIRED}: ${client} requires PA-ENC-TIMESTAMP in the AS-REQ`);
    }
    if (padata) {
      await this.verifyPreauth(clientKey, padata, nowMs);
    }
    const preauthenticated = padata !== undefined;

    const ksessionTgs = randomBytes(32);
    const starttime = nowMs;
    const endtime = nowMs + lifetimeMs;

    const tgtBody: TicketBody = {
      client_principal: client,
      realm: this.realm,
      session_key_hex: toHex(ksessionTgs),
      starttime,
      endtime,
      authtime: nowMs,
      // Every flag here has to be earned by something this protocol actually
      // did (RFC 4120 §2.1): 'initial' because the ticket came from an AS
      // exchange rather than a TGS one, 'pre-authent' only when the
      // PA-ENC-TIMESTAMP above really verified. 'forwardable' is absent
      // because nothing in this demo requests or honours forwarding.
      flags: preauthenticated ? ['initial', 'pre-authent'] : ['initial'],
      sname: this.tgsPrincipal,
    };

    const tgtCipher = await encryptAes256CtsHmacSha196(this.tgsKey, 2, jsonBytes(tgtBody));
    const clientPart = await encryptAes256CtsHmacSha196(
      clientKey,
      3,
      jsonBytes({
        ksession_tgs_hex: toHex(ksessionTgs),
        nonce,
        endtime,
        realm: this.realm,
        sname: this.tgsPrincipal,
      }),
    );

    return {
      tgt: { etype: 18, kvno: 1, cipher: tgtCipher.raw },
      encPartForClient: clientPart.raw,
      nonce,
      endtime,
      realm: this.realm,
      sname: this.tgsPrincipal,
      preauthenticated,
    };
  }

  async decryptTgt(tgt: EncTicket): Promise<TicketBody> {
    const clear = await decryptAes256CtsHmacSha196(this.tgsKey, 2, tgt.cipher);
    return parseJson<TicketBody>(clear);
  }

  async issueTgsRep(
    tgt: EncTicket,
    authenticatorCipher: Uint8Array,
    serviceName: string,
    nowMs: number,
    lifetimeMs: number,
  ): Promise<TgsRep> {
    const tgtBody = await this.decryptTgt(tgt);
    if (nowMs < tgtBody.starttime || nowMs > tgtBody.endtime) {
      throw new Error('TGT expired or not yet valid');
    }

    const sessionTgs = fromHex(tgtBody.session_key_hex);
    const authClear = await decryptAes256CtsHmacSha196(sessionTgs, 7, authenticatorCipher);
    const auth = parseJson<{ cname: string; ctime: number; cusec: number }>(authClear);
    if (auth.cname !== tgtBody.client_principal) {
      throw new Error('authenticator cname mismatch');
    }

    const serviceKey = this.services.get(serviceName);
    if (!serviceKey) {
      throw new Error('unknown service');
    }

    const ksessionSvc = randomBytes(32);
    const starttime = nowMs;
    const endtime = nowMs + lifetimeMs;

    const serviceTicketBody: TicketBody = {
      client_principal: tgtBody.client_principal,
      realm: this.realm,
      session_key_hex: toHex(ksessionSvc),
      starttime,
      endtime,
      authtime: tgtBody.authtime,
      // Inherited from the TGT, not asserted: a service ticket may only claim
      // 'pre-authent' if the AS exchange that produced the TGT verified it.
      flags: tgtBody.flags.filter((f) => f === 'pre-authent'),
      sname: serviceName,
    };

    const serviceTicketCipher = await encryptAes256CtsHmacSha196(serviceKey, 2, jsonBytes(serviceTicketBody));
    const clientPartCipher = await encryptAes256CtsHmacSha196(
      sessionTgs,
      8,
      jsonBytes({
        ksession_svc_hex: toHex(ksessionSvc),
        sname: serviceName,
        endtime,
      }),
    );

    return {
      serviceTicket: { etype: 18, kvno: 1, cipher: serviceTicketCipher.raw },
      encPartForClient: clientPartCipher.raw,
      endtime,
    };
  }
}
