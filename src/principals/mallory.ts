export class MalloryPrincipal {
  readonly name = 'Mallory';
  stolenTgt: Uint8Array | null = null;

  stealTgt(ticket: Uint8Array): void {
    this.stolenTgt = ticket.slice();
  }
}
