import { decryptAes256CtsHmacSha196, encryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { stringToKeyAes256 } from '../crypto/pbkdf2-string2key';
import { KeyDistributionCenter, type AsRep, type EncTicket, type PaEncTimestamp, type TicketBody, type TgsRep } from '../principals/kdc';
import { ServicePrincipal } from '../principals/service';

export type KerberosParty = 'Client' | 'KDC' | 'Service';

export type FlowRecord = {
  label: string;
  from: KerberosParty;
  to: KerberosParty;
  bytesHex: string;
  decoded: Record<string, string | number | string[]>;
};

export type KerberosRun = {
  records: FlowRecord[];
  apAccepted: boolean;
  apReason?: string;
  apRep?: Uint8Array;
  tgt: EncTicket;
  serviceTicket: EncTicket;
  clientSvcKey: Uint8Array;
  lastAuth: { cname: string; ctime: number; cusec: number };
  /**
   * The exact AP-REQ authenticator ciphertext that went over the wire, kept so
   * the UI can re-submit these *bytes* — not a lookup key — and watch the
   * service decrypt them successfully and refuse them anyway.
   */
  lastApReq?: Uint8Array;
  /** The service/KDC clock this run was judged against. */
  serviceNowMs: number;
  /** True only if the AS exchange verified a PA-ENC-TIMESTAMP. */
  preauthenticated: boolean;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function jsonBytes(obj: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(obj));
}

function parse<T>(bytes: Uint8Array): T {
  return JSON.parse(decoder.decode(bytes)) as T;
}

function randomUsec(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return Number(buf[0] % 1_000_000);
}

export const DEFAULT_SKEW_MS = 5 * 60 * 1000;

// RFC 4120 §7.5.1 key usage 1 — PA-ENC-TIMESTAMP under the client long-term key.
const KU_PA_ENC_TIMESTAMP = 1;

export async function asExchange(
  kdc: KeyDistributionCenter,
  clientName: string,
  password: string,
  kdcNowMs: number,
): Promise<{ asRep: AsRep; clientTgsKey: Uint8Array; records: FlowRecord[] }> {
  const nonce = `${kdcNowMs}-${clientName}`;
  const clientLongTerm = await stringToKeyAes256(password, `${kdc.realm}${clientName}`);

  // Pre-authentication: the client encrypts a timestamp under its own long-term
  // key and sends it *with* the AS-REQ. Only after this verifies does the KDC
  // emit an enc-part derived from the password — which is exactly the step whose
  // absence makes an account AS-REP-roastable.
  const paCipher = await encryptAes256CtsHmacSha196(
    clientLongTerm,
    KU_PA_ENC_TIMESTAMP,
    jsonBytes({ patimestamp: kdcNowMs, pausec: randomUsec() }),
  );
  const padata: PaEncTimestamp = { padataType: 2, cipher: paCipher.raw };

  const asRep = await kdc.issueAsRep(clientName, nonce, kdcNowMs, 8 * 60 * 60 * 1000, padata);
  const clear = await decryptAes256CtsHmacSha196(clientLongTerm, 3, asRep.encPartForClient);
  const part = parse<{ ksession_tgs_hex: string; nonce: string; endtime: number; realm: string; sname: string }>(clear);

  // The client must confirm the KDC echoed the nonce it sent, binding this
  // reply to this request (RFC 4120 §3.1.5) — defeats AS-REP replay/substitution.
  if (part.nonce !== nonce) {
    throw new Error('AS-REP nonce mismatch');
  }

  const records: FlowRecord[] = [
    {
      label: 'AS-REQ',
      from: 'Client',
      to: 'KDC',
      bytesHex: toHex(jsonBytes({ client: clientName, realm: kdc.realm, nonce, padata: toHex(padata.cipher) })),
      decoded: {
        client: clientName,
        realm: kdc.realm,
        nonce,
        'padata-type': '2 (PA-ENC-TIMESTAMP)',
        'padata (enc-ts)': toHex(padata.cipher),
      },
    },
    {
      label: 'AS-REP',
      from: 'KDC',
      to: 'Client',
      bytesHex: toHex(asRep.tgt.cipher),
      decoded: {
        nonce: asRep.nonce,
        endtime: asRep.endtime,
        sname: asRep.sname,
        etype: '18',
        'pre-authenticated': String(asRep.preauthenticated),
      },
    },
  ];

  return { asRep, clientTgsKey: fromHex(part.ksession_tgs_hex), records };
}

export async function tgsExchange(
  kdc: KeyDistributionCenter,
  asRep: AsRep,
  clientName: string,
  clientTgsKey: Uint8Array,
  serviceName: string,
  clientNowMs: number,
  kdcNowMs: number,
): Promise<{ tgsRep: TgsRep; clientSvcKey: Uint8Array; records: FlowRecord[] }> {
  // The authenticator carries the client's (possibly skewed) clock; the KDC
  // mints the service ticket against its own clock.
  const auth = { cname: clientName, ctime: clientNowMs, cusec: randomUsec() };
  const authCipher = await encryptAes256CtsHmacSha196(clientTgsKey, 7, jsonBytes(auth));
  const tgsRep = await kdc.issueTgsRep(asRep.tgt, authCipher.raw, serviceName, kdcNowMs, 4 * 60 * 60 * 1000);

  const encClient = await decryptAes256CtsHmacSha196(clientTgsKey, 8, tgsRep.encPartForClient);
  const clear = parse<{ ksession_svc_hex: string }>(encClient);

  const records: FlowRecord[] = [
    {
      label: 'TGS-REQ',
      from: 'Client',
      to: 'KDC',
      bytesHex: toHex(authCipher.raw),
      decoded: auth as unknown as Record<string, string | number>,
    },
    {
      label: 'TGS-REP',
      from: 'KDC',
      to: 'Client',
      bytesHex: toHex(tgsRep.serviceTicket.cipher),
      decoded: { endtime: tgsRep.endtime, etype: '18', sname: serviceName },
    },
  ];

  return { tgsRep, clientSvcKey: fromHex(clear.ksession_svc_hex), records };
}

export type ApResult = {
  accepted: boolean;
  apRep?: Uint8Array;
  records: FlowRecord[];
  reason?: string;
  /** The authenticator ciphertext the service actually processed. */
  apReqCipher?: Uint8Array;
  /** True once the service decrypted the AP-REQ and its HMAC verified. */
  cryptoVerified: boolean;
};

export async function apExchange(
  service: ServicePrincipal,
  serviceTicket: EncTicket,
  clientName: string,
  clientSvcKey: Uint8Array,
  clientNowMs: number,
  serviceNowMs: number,
  skewMs = DEFAULT_SKEW_MS,
  /**
   * When supplied, these exact bytes are submitted instead of minting a fresh
   * authenticator — that is what makes "replay" a real replay: the service
   * still runs AES-256-CTS decryption and HMAC-SHA1-96 verification over them
   * before any freshness check gets a say.
   */
  resubmitAuthCipher?: Uint8Array,
): Promise<ApResult> {
  const ticketClear = await decryptAes256CtsHmacSha196(fromHex(service.keyHex), 2, serviceTicket.cipher);
  const ticket = parse<TicketBody>(ticketClear);

  // The service validates the ticket lifetime against its own clock.
  if (serviceNowMs < ticket.starttime || serviceNowMs > ticket.endtime) {
    return { accepted: false, reason: 'ticket expired', records: [], cryptoVerified: false };
  }

  // The client stamps the authenticator with its own (possibly skewed) clock —
  // unless we were handed captured bytes to resubmit verbatim.
  let authCipherRaw: Uint8Array;
  if (resubmitAuthCipher) {
    authCipherRaw = resubmitAuthCipher;
  } else {
    const auth = {
      cname: clientName,
      ctime: clientNowMs,
      cusec: randomUsec(),
      cksum: toHex(encoder.encode('ap-req')),
    };
    authCipherRaw = (await encryptAes256CtsHmacSha196(clientSvcKey, 11, jsonBytes(auth))).raw;
  }

  // Everything below this line is the SERVICE's view. The decrypt throws if the
  // HMAC does not verify, so reaching the next statement is proof the cipher and
  // tag were good — including on the replay path.
  const authClear = await decryptAes256CtsHmacSha196(fromHex(ticket.session_key_hex), 11, authCipherRaw);
  const authOnService = parse<{ cname: string; ctime: number; cusec: number; cksum?: string }>(authClear);
  const record: FlowRecord = {
    label: 'AP-REQ',
    from: 'Client',
    to: 'Service',
    bytesHex: toHex(authCipherRaw),
    decoded: authOnService as unknown as Record<string, string | number>,
  };
  const base = { apReqCipher: authCipherRaw, cryptoVerified: true };

  const replayKey = `${authOnService.cname}:${authOnService.ctime}:${authOnService.cusec}`;
  service.pruneReplay(skewMs, serviceNowMs);
  if (service.hasReplay(replayKey)) {
    return { ...base, accepted: false, reason: 'replay cache hit', records: [record] };
  }

  if (Math.abs(serviceNowMs - authOnService.ctime) > skewMs) {
    return { ...base, accepted: false, reason: 'clock skew exceeded', records: [record] };
  }

  service.rememberReplay(replayKey, serviceNowMs);

  const apRepPlain = jsonBytes({ ctime: authOnService.ctime, cusec: authOnService.cusec, subkey: 'none', seq: 1 });
  const apRep = await encryptAes256CtsHmacSha196(fromHex(ticket.session_key_hex), 12, apRepPlain);

  return {
    ...base,
    accepted: true,
    apRep: apRep.raw,
    records: [
      record,
      {
        label: 'AP-REP',
        from: 'Service',
        to: 'Client',
        bytesHex: toHex(apRep.raw),
        decoded: { ctime: authOnService.ctime, cusec: authOnService.cusec, seq: 1, subkey: 'none' },
      },
    ],
  };
}

/**
 * Re-submit a captured AP-REQ authenticator, byte for byte, to the same
 * service. Nothing is looked up: the service decrypts the ciphertext under the
 * ticket session key and verifies the HMAC first — that part succeeds — and the
 * request is refused afterwards, purely on freshness.
 */
export async function replayApReq(
  service: ServicePrincipal,
  serviceTicket: EncTicket,
  clientName: string,
  clientSvcKey: Uint8Array,
  apReqCipher: Uint8Array,
  serviceNowMs: number,
  skewMs = DEFAULT_SKEW_MS,
): Promise<ApResult> {
  return apExchange(service, serviceTicket, clientName, clientSvcKey, serviceNowMs, serviceNowMs, skewMs, apReqCipher);
}

/**
 * Run the full AS / TGS / AP exchange.
 *
 * `clientNowMs` is the client's wall clock (what its authenticators are stamped
 * with); `serviceNowMs` is the true KDC/service clock used to mint tickets and
 * to judge replay and clock skew. They default to equal — no skew — and diverge
 * only when the UI slides the client's clock, which is what lets the skew
 * defense actually fire.
 */
export async function runKerberosV5(
  kdc: KeyDistributionCenter,
  service: ServicePrincipal,
  clientName: string,
  password: string,
  clientNowMs: number,
  serviceNowMs: number = clientNowMs,
): Promise<KerberosRun> {
  const as = await asExchange(kdc, clientName, password, serviceNowMs);
  const tgs = await tgsExchange(kdc, as.asRep, clientName, as.clientTgsKey, service.name, clientNowMs, serviceNowMs);
  const ap = await apExchange(service, tgs.tgsRep.serviceTicket, clientName, tgs.clientSvcKey, clientNowMs, serviceNowMs);

  // Recover the authenticator we just sent so the UI can replay it on demand.
  const lastAuthRecord = ap.records.find((r) => r.label === 'AP-REQ');
  const lastAuth = lastAuthRecord
    ? (lastAuthRecord.decoded as unknown as { cname: string; ctime: number; cusec: number })
    : { cname: clientName, ctime: clientNowMs, cusec: 0 };

  return {
    records: [...as.records, ...tgs.records, ...ap.records],
    apAccepted: ap.accepted,
    apReason: ap.reason,
    apRep: ap.apRep,
    tgt: as.asRep.tgt,
    serviceTicket: tgs.tgsRep.serviceTicket,
    clientSvcKey: tgs.clientSvcKey,
    lastAuth,
    lastApReq: ap.apReqCipher,
    serviceNowMs,
    preauthenticated: as.asRep.preauthenticated,
  };
}
