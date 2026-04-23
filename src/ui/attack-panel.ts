import { runLoweAttack } from '../attacks/lowe-attack';
import { detectReplay } from '../attacks/replay-defense';
import { detectClockSkew, passTheTicket, validateTimeWindow } from '../attacks/skew-attack';
import { buildNsKeys } from '../protocols/needham-schroeder';

function item(name: string, result: string): string {
  return `<div class="attack-item"><h4>${name}</h4><p>${result}</p></div>`;
}

export async function renderAttackPanel(nowMs: number, serviceEndtime: number): Promise<string> {
  const keys = await buildNsKeys();
  const lowe = await runLoweAttack(keys);

  const sessionKey = new Uint8Array(32);
  crypto.getRandomValues(sessionKey);
  const cache = new Map<string, number>();
  const auth = { cname: 'alice', ctime: nowMs, cusec: 777 };
  const first = await detectReplay(sessionKey, auth, cache, nowMs, 5 * 60 * 1000);
  const second = await detectReplay(sessionKey, auth, cache, nowMs + 500, 5 * 60 * 1000);

  const skew = detectClockSkew(nowMs + 10 * 60 * 1000, nowMs, 5 * 60 * 1000);
  const validity = validateTimeWindow(nowMs - 60_000, serviceEndtime, nowMs + 10 * 60 * 1000, 5 * 60 * 1000);
  const ptt = passTheTicket(serviceEndtime, nowMs + 2 * 60 * 1000);

  const roastNote = 'AS-REP roasting path: pre-auth disabled account enables offline password guessing against enc-part.';

  return `<section class="panel"><h3>Attack Panel</h3>
    ${item('Lowe attack acceptance', lowe.bobAccepted ? 'Bob accepted forged run as Alice.' : 'Bob rejected.')}
    ${item('Replay attempt #1', first.reason)}
    ${item('Replay attempt #2', second.reason)}
    ${item('Clock skew', skew.reason)}
    ${item('Ticket time window', validity.reason)}
    ${item('Pass-the-ticket', ptt.reason)}
    ${item('AS-REP roasting', roastNote)}
  </section>`;
}
