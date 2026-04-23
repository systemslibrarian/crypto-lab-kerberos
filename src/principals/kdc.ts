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

export type AsRep = {
  tgt: EncTicket;
  encPartForClient: Uint8Array;
  nonce: string;
  endtime: number;
  realm: string;
  sname: string;
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
  readonly users = new Map<string, string>();
  readonly services = new Map<string, Uint8Array>();

  constructor(realm: string) {
    this.realm = realm;
    this.tgsPrincipal = `krbtgt/${realm}`;
    this.tgsKey = randomBytes(32);
  }

  async registerUser(name: string, password: string): Promise<void> {
    this.users.set(name, password);
  }

  registerService(serviceName: string, keyHex?: string): Uint8Array {
    const key = keyHex ? fromHex(keyHex) : randomBytes(32);
    this.services.set(serviceName, key);
    return key;
  }

  async buildClientKey(name: string): Promise<Uint8Array> {
    const password = this.users.get(name);
    if (!password) {
      throw new Error('unknown user');
    }
    return stringToKeyAes256(password, `${this.realm}${name}`);
  }

  async issueAsRep(client: string, nonce: string, nowMs: number, lifetimeMs: number): Promise<AsRep> {
    const clientKey = await this.buildClientKey(client);
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
      flags: ['initial', 'forwardable'],
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
      flags: ['pre-authenticated'],
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
