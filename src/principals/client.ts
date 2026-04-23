export type ClientIdentity = {
  realm: string;
  name: string;
  password: string;
  nowMs: number;
};

export class ClientPrincipal {
  identity: ClientIdentity;

  constructor(identity: ClientIdentity) {
    this.identity = identity;
  }

  setClock(nowMs: number): void {
    this.identity.nowMs = nowMs;
  }
}
