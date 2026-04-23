import { renderAttackPanel } from './ui/attack-panel';
import { renderETypePanel } from './ui/etype-panel';
import { renderKerberosFlow, renderNsFlow } from './ui/message-flow';
import { renderTicketInspector } from './ui/ticket-inspector';
import { buildNsKeys, runNeedhamSchroeder } from './protocols/needham-schroeder';
import { runNeedhamSchroederWithLoweFix } from './protocols/lowe-fix';
import { runLoweAttack } from './attacks/lowe-attack';
import { KeyDistributionCenter } from './principals/kdc';
import { ServicePrincipal } from './principals/service';
import { runKerberosV5 } from './protocols/kerberos-v5';

function byId<T extends Element>(id: string): T {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Missing element ${id}`);
  }
  return el as unknown as T;
}

function randomHex(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b)
    .map((v) => v.toString(16).padStart(2, '0'))
    .join('');
}

export async function renderApp(root: HTMLElement): Promise<void> {
  root.innerHTML = `
  <header class="page-header">
    <h1>crypto-lab-kerberos</h1>
    <p>Needham-Schroeder (1978) → Lowe attack (1995) → Kerberos v5 (RFC 4120)</p>
    <button id="theme-toggle" class="theme-toggle" style="position: absolute; top: 0; right: 0" aria-label="Switch to light mode">🌙</button>
  </header>

  <section class="panel controls">
    <label for="scenario">Scenario</label>
    <select id="scenario">
      <option value="ns">Needham-Schroeder</option>
      <option value="lowe-attack">Lowe attack</option>
      <option value="lowe-fix">Lowe fix</option>
      <option value="kerberos">Kerberos v5</option>
    </select>
    <label for="clock">Clock offset (minutes)</label>
    <input id="clock" type="range" min="-15" max="15" step="1" value="0" />
    <output id="clock-value">0 min</output>
    <button id="run">Run flow</button>
  </section>

  <section id="flow" class="panel"></section>
  <section id="inspectors" class="grid"></section>
  <section id="etype"></section>
  <section id="attacks"></section>
`;

  const scenario = byId<HTMLSelectElement>('scenario');
  const clock = byId<HTMLInputElement>('clock');
  const clockValue = byId<HTMLOutputElement>('clock-value');
  const flow = byId<HTMLElement>('flow');
  const inspectors = byId<HTMLElement>('inspectors');
  const etype = byId<HTMLElement>('etype');
  const attacks = byId<HTMLElement>('attacks');

  const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
  await kdc.registerUser('alice', 'correct-horse-battery-staple');
  const serviceKey = kdc.registerService('http/web.lab.example', randomHex(32));
  const service = new ServicePrincipal('http/web.lab.example', 'LAB.EXAMPLE', Array.from(serviceKey).map((v) => v.toString(16).padStart(2, '0')).join(''));

  async function runScenario(): Promise<void> {
    const baseNow = Date.now();
    const offset = Number.parseInt(clock.value, 10) * 60 * 1000;
    const nowMs = baseNow + offset;
    clockValue.textContent = `${clock.value} min`;

    if (scenario.value === 'ns') {
      const keys = await buildNsKeys();
      const ns = await runNeedhamSchroeder(keys);
      flow.innerHTML = `<h3>Needham-Schroeder (1978)</h3>${renderNsFlow(ns.messages)}<p>Accepted: ${ns.accepted}</p>`;
      inspectors.innerHTML = '';
      return;
    }

    if (scenario.value === 'lowe-attack') {
      const keys = await buildNsKeys();
      const lowe = await runLoweAttack(keys);
      flow.innerHTML = `<h3>Lowe Attack Run</h3>${renderNsFlow(lowe.messages)}<p>Bob accepted forged run: ${lowe.bobAccepted}</p><p>Bob thinks peer=${lowe.bobBelievesPeer}, Alice thinks peer=${lowe.aliceBelievesPeer}</p>`;
      inspectors.innerHTML = '';
      return;
    }

    if (scenario.value === 'lowe-fix') {
      const keys = await buildNsKeys();
      const fixed = await runNeedhamSchroederWithLoweFix(keys);
      flow.innerHTML = `<h3>Lowe Fix (1995)</h3>${renderNsFlow(fixed.messages)}<p>Accepted: ${fixed.accepted}</p><p>Identity binding in message 2 blocks substitution.</p>`;
      inspectors.innerHTML = '';
      return;
    }

    const kerberos = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', nowMs);
    flow.innerHTML = `<h3>Kerberos v5 AS/TGS/AP</h3>${renderKerberosFlow(kerberos.records)}<p>AP accepted: ${kerberos.apAccepted}</p>`;
    inspectors.innerHTML = `${renderTicketInspector('TGT', kerberos.tgt.cipher)}${renderTicketInspector('Service Ticket', kerberos.serviceTicket.cipher)}`;
    etype.innerHTML = await renderETypePanel(serviceKey);
    attacks.innerHTML = await renderAttackPanel(nowMs, Date.now() + 4 * 60 * 60 * 1000);
  }

  byId<HTMLButtonElement>('run').addEventListener('click', () => {
    void runScenario();
  });
  clock.addEventListener('input', () => {
    void runScenario();
  });
  scenario.addEventListener('change', () => {
    void runScenario();
  });

  await runScenario();
}
