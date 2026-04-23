export type ReplayKey = string;

export type ServiceTicket = {
  client: string;
  realm: string;
  sessionKeyHex: string;
  starttime: number;
  endtime: number;
  authtime: number;
  flags: string[];
};

export class ServicePrincipal {
  readonly name: string;
  readonly realm: string;
  keyHex: string;
  replayCache = new Map<ReplayKey, number>();

  constructor(name: string, realm: string, keyHex: string) {
    this.name = name;
    this.realm = realm;
    this.keyHex = keyHex;
  }

  rememberReplay(key: ReplayKey, nowMs: number): void {
    this.replayCache.set(key, nowMs);
  }

  hasReplay(key: ReplayKey): boolean {
    return this.replayCache.has(key);
  }

  pruneReplay(skewMs: number, nowMs: number): void {
    for (const [k, ts] of this.replayCache.entries()) {
      if (nowMs - ts > skewMs) {
        this.replayCache.delete(k);
      }
    }
  }
}
