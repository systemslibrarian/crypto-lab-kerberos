export function validateTimeWindow(starttime: number, endtime: number, clientNowMs: number, skewMs: number): { accepted: boolean; reason: string } {
  if (clientNowMs < starttime - skewMs) {
    return { accepted: false, reason: 'ticket not yet valid for client clock' };
  }
  if (clientNowMs > endtime + skewMs) {
    return { accepted: false, reason: 'ticket expired for client clock' };
  }
  return { accepted: true, reason: 'within time window' };
}

export function detectClockSkew(clientNowMs: number, serviceNowMs: number, skewMs: number): { accepted: boolean; driftMs: number; reason: string } {
  const driftMs = clientNowMs - serviceNowMs;
  if (Math.abs(driftMs) > skewMs) {
    return { accepted: false, driftMs, reason: 'clock skew exceeded' };
  }
  return { accepted: true, driftMs, reason: 'clock skew acceptable' };
}

export function passTheTicket(endtime: number, attackerNowMs: number): { accepted: boolean; reason: string } {
  if (attackerNowMs <= endtime) {
    return { accepted: true, reason: 'ticket still valid for attacker use' };
  }
  return { accepted: false, reason: 'ticket expired for attacker use' };
}
