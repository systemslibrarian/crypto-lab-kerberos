import { decryptAes256CtsHmacSha196, encryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { stringToKeyAes256 } from '../crypto/pbkdf2-string2key';
import { KeyDistributionCenter, type AsRep, type EncTicket, type TicketBody, type TgsRep } from '../principals/kdc';
import { ServicePrincipal } from '../principals/service';

export type FlowRecord = {
  label: string;
  bytesHex: string;
  decoded: Record<string, string | number | string[]>;
};

export type KerberosRun = {
  records: FlowRecord[];
  apAccepted: boolean;
  apRep?: Uint8Array;
  tgt: EncTicket;
  serviceTicket: EncTicket;
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

export async function asExchange(
  kdc: KeyDistributionCenter,
  clientName: string,
  password: string,
  nowMs: number,
): Promise<{ asRep: AsRep; clientTgsKey: Uint8Array; records: FlowRecord[] }> {
  const nonce = `${nowMs}-${clientName}`;
  const asRep = await kdc.issueAsRep(clientName, nonce, nowMs, 8 * 60 * 60 * 1000);
  const clientLongTerm = await stringToKeyAes256(password, `${kdc.realm}${clientName}`);
  const clear = await decryptAes256CtsHmacSha196(clientLongTerm, 3, asRep.encPartForClient);
  const part = parse<{ ksession_tgs_hex: string; nonce: string; endtime: number; realm: string; sname: string }>(clear);

  const records: FlowRecord[] = [
    {
      label: 'AS-REQ',
      bytesHex: toHex(jsonBytes({ client: clientName, realm: kdc.realm, nonce })),
      decoded: { client: clientName, realm: kdc.realm, nonce },
    },
    {
      label: 'AS-REP',
      bytesHex: toHex(asRep.tgt.cipher),
      decoded: { nonce: asRep.nonce, endtime: asRep.endtime, sname: asRep.sname, etype: '18' },
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
  nowMs: number,
): Promise<{ tgsRep: TgsRep; clientSvcKey: Uint8Array; records: FlowRecord[] }> {
  const auth = { cname: clientName, ctime: nowMs, cusec: randomUsec() };
  const authCipher = await encryptAes256CtsHmacSha196(clientTgsKey, 7, jsonBytes(auth));
  const tgsRep = await kdc.issueTgsRep(asRep.tgt, authCipher.raw, serviceName, nowMs, 4 * 60 * 60 * 1000);

  const encClient = await decryptAes256CtsHmacSha196(clientTgsKey, 8, tgsRep.encPartForClient);
  const clear = parse<{ ksession_svc_hex: string }>(encClient);

  const records: FlowRecord[] = [
    {
      label: 'TGS-REQ',
      bytesHex: toHex(authCipher.raw),
      decoded: auth as unknown as Record<string, string | number>,
    },
    {
      label: 'TGS-REP',
      bytesHex: toHex(tgsRep.serviceTicket.cipher),
      decoded: { endtime: tgsRep.endtime, etype: '18', sname: serviceName },
    },
  ];

  return { tgsRep, clientSvcKey: fromHex(clear.ksession_svc_hex), records };
}

export async function apExchange(
  service: ServicePrincipal,
  serviceTicket: EncTicket,
  clientName: string,
  clientSvcKey: Uint8Array,
  nowMs: number,
  skewMs = DEFAULT_SKEW_MS,
): Promise<{ accepted: boolean; apRep?: Uint8Array; records: FlowRecord[]; reason?: string }> {
  const ticketClear = await decryptAes256CtsHmacSha196(fromHex(service.keyHex), 2, serviceTicket.cipher);
  const ticket = parse<TicketBody>(ticketClear);

  if (nowMs < ticket.starttime || nowMs > ticket.endtime) {
    return { accepted: false, reason: 'ticket expired', records: [] };
  }

  const auth = {
    cname: clientName,
    ctime: nowMs,
    cusec: randomUsec(),
    cksum: toHex(encoder.encode('ap-req')),
  };
  const authCipher = await encryptAes256CtsHmacSha196(clientSvcKey, 11, jsonBytes(auth));

  const authClear = await decryptAes256CtsHmacSha196(fromHex(ticket.session_key_hex), 11, authCipher.raw);
  const authOnService = parse<{ cname: string; ctime: number; cusec: number }>(authClear);

  const replayKey = `${authOnService.cname}:${authOnService.ctime}:${authOnService.cusec}`;
  service.pruneReplay(skewMs, nowMs);
  if (service.hasReplay(replayKey)) {
    return {
      accepted: false,
      reason: 'replay cache hit',
      records: [
        {
          label: 'AP-REQ',
          bytesHex: toHex(authCipher.raw),
          decoded: auth as unknown as Record<string, string | number>,
        },
      ],
    };
  }

  if (Math.abs(nowMs - authOnService.ctime) > skewMs) {
    return {
      accepted: false,
      reason: 'clock skew exceeded',
      records: [
        {
          label: 'AP-REQ',
          bytesHex: toHex(authCipher.raw),
          decoded: auth as unknown as Record<string, string | number>,
        },
      ],
    };
  }

  service.rememberReplay(replayKey, nowMs);

  const apRepPlain = jsonBytes({ ctime: authOnService.ctime, cusec: authOnService.cusec, subkey: 'none', seq: 1 });
  const apRep = await encryptAes256CtsHmacSha196(fromHex(ticket.session_key_hex), 12, apRepPlain);

  return {
    accepted: true,
    apRep: apRep.raw,
    records: [
      {
        label: 'AP-REQ',
        bytesHex: toHex(authCipher.raw),
        decoded: auth as unknown as Record<string, string | number>,
      },
      {
        label: 'AP-REP',
        bytesHex: toHex(apRep.raw),
        decoded: { ctime: authOnService.ctime, cusec: authOnService.cusec, seq: 1, subkey: 'none' },
      },
    ],
  };
}

export async function runKerberosV5(kdc: KeyDistributionCenter, service: ServicePrincipal, clientName: string, password: string, nowMs: number): Promise<KerberosRun> {
  const as = await asExchange(kdc, clientName, password, nowMs);
  const tgs = await tgsExchange(kdc, as.asRep, clientName, as.clientTgsKey, service.name, nowMs);
  const ap = await apExchange(service, tgs.tgsRep.serviceTicket, clientName, tgs.clientSvcKey, nowMs);

  return {
    records: [...as.records, ...tgs.records, ...ap.records],
    apAccepted: ap.accepted,
    apRep: ap.apRep,
    tgt: as.asRep.tgt,
    serviceTicket: tgs.tgsRep.serviceTicket,
  };
}
