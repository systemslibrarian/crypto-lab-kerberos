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

type ScenarioKey = 'ns' | 'lowe-attack' | 'lowe-fix' | 'kerberos';

interface ScenarioMeta {
  key: ScenarioKey;
  label: string;
  year: string;
  blurb: string;
}

const SCENARIOS: ScenarioMeta[] = [
  { key: 'ns', label: 'Needham-Schroeder', year: '1978', blurb: 'Original public-key protocol — vulnerable to identity substitution.' },
  { key: 'lowe-attack', label: 'Lowe Attack', year: '1995', blurb: 'Gavin Lowe\u2019s 17-year-late man-in-the-middle on NSPK.' },
  { key: 'lowe-fix', label: 'Lowe Fix', year: '1995', blurb: 'Identity binding in message 2 — the one-line patch that closed it.' },
  { key: 'kerberos', label: 'Kerberos v5', year: 'RFC 4120', blurb: 'AS / TGS / AP exchanges with real AES-256-CTS-HMAC-SHA1-96.' },
];

function byId<T extends Element>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element ${id}`);
  return el as unknown as T;
}

function randomHex(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b).map((v) => v.toString(16).padStart(2, '0')).join('');
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function resultLine(ok: boolean, message: string): string {
  return `<div class="flow-result ${ok ? 'ok' : 'bad'}">${escape(message)}</div>`;
}

export async function renderApp(root: HTMLElement): Promise<void> {
  root.innerHTML = `
  <section class="hero" aria-labelledby="hero-title">
    <span class="eyebrow">Authentication Protocol Lab</span>
    <h1 id="hero-title">Forty-seven years of <span>authentication</span>.</h1>
    <p>Walk the arc from Needham-Schroeder (1978) through Gavin Lowe\u2019s man-in-the-middle (1995) to Kerberos v5 (RFC 4120), with real AES-256-CTS-HMAC-SHA1-96 encryption running in your browser via WebCrypto. Watch tickets get issued, replays get caught, and clock skew kill an exchange.</p>
    <div class="hero-stats">
      <span class="hero-stat">RFC 3961 / 3962</span>
      <span class="hero-stat">RFC 4120</span>
      <span class="hero-stat">AES-256-CTS-HMAC-SHA1-96</span>
      <span class="hero-stat">PBKDF2-HMAC-SHA1 \u00d7 4096</span>
      <span class="hero-stat">@noble/hashes</span>
    </div>
  </section>

  <section class="panel controls" aria-label="Scenario controls">
    <span class="kicker">Step 1 \u2014 Pick a scenario</span>
    <h2>Run a flow</h2>
    <div class="controls-grid">
      <div class="field">
        <label for="scenario">Scenario</label>
        <select id="scenario">
          ${SCENARIOS.map((s) => `<option value="${s.key}">${escape(s.label)} \u00b7 ${escape(s.year)}</option>`).join('')}
        </select>
      </div>
      <div class="field">
        <label for="clock">Clock offset</label>
        <input id="clock" type="range" min="-15" max="15" step="1" value="0" aria-describedby="clock-value" />
      </div>
      <div class="field">
        <label for="clock-value">Skew</label>
        <output id="clock-value" for="clock" aria-live="polite">0 min</output>
      </div>
      <div class="field">
        <label>&nbsp;</label>
        <button id="run" type="button">Run flow \u2192</button>
      </div>
    </div>
    <p id="scenario-blurb" style="margin-top: 14px; color: var(--text-dim); font-size: 12.5px;"></p>
  </section>

  <section id="flow" class="panel" role="region" aria-live="polite" aria-label="Protocol message flow"></section>
  <section id="inspectors" class="grid" role="region" aria-label="Ticket inspector"></section>
  <section id="etype-wrap" role="region" aria-label="Encryption type details"></section>
  <section id="attacks-wrap" role="region" aria-label="Attack outcomes"></section>
`;

  const scenario = byId<HTMLSelectElement>('scenario');
  const clock = byId<HTMLInputElement>('clock');
  const clockValue = byId<HTMLOutputElement>('clock-value');
  const blurb = byId<HTMLElement>('scenario-blurb');
  const flow = byId<HTMLElement>('flow');
  const inspectors = byId<HTMLElement>('inspectors');
  const etypeWrap = byId<HTMLElement>('etype-wrap');
  const attacksWrap = byId<HTMLElement>('attacks-wrap');

  const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
  await kdc.registerUser('alice', 'correct-horse-battery-staple');
  const serviceKey = kdc.registerService('http/web.lab.example', randomHex(32));
  const service = new ServicePrincipal(
    'http/web.lab.example',
    'LAB.EXAMPLE',
    Array.from(serviceKey).map((v) => v.toString(16).padStart(2, '0')).join(''),
  );

  function setScenarioClass(key: ScenarioKey): void {
    flow.classList.remove('scenario-ns', 'scenario-lowe-attack', 'scenario-lowe-fix', 'scenario-kerberos');
    flow.classList.add(`scenario-${key}`);
  }

  function flowHeader(meta: ScenarioMeta): string {
    return `
      <span class="kicker">Step 2 \u2014 Message flow</span>
      <h2>${escape(meta.label)} <span style="color: var(--text-dim); font-family: var(--mono); font-size: 0.6em; letter-spacing: 0.1em; margin-left: 10px;">${escape(meta.year)}</span></h2>
      <p style="color: var(--text-dim); margin-bottom: 16px;">${escape(meta.blurb)}</p>`;
  }

  async function runScenario(): Promise<void> {
    const baseNow = Date.now();
    const offset = Number.parseInt(clock.value, 10) * 60 * 1000;
    const nowMs = baseNow + offset;
    clockValue.textContent = `${clock.value} min`;

    const key = scenario.value as ScenarioKey;
    const meta = SCENARIOS.find((s) => s.key === key) ?? SCENARIOS[0];
    blurb.textContent = meta.blurb;
    setScenarioClass(key);

    if (key === 'ns') {
      const keys = await buildNsKeys();
      const ns = await runNeedhamSchroeder(keys);
      flow.innerHTML = `${flowHeader(meta)}${renderNsFlow(ns.messages)}${resultLine(ns.accepted, ns.accepted ? 'Bob accepted Alice as authenticated.' : 'Bob rejected the run.')}`;
      inspectors.innerHTML = '';
      etypeWrap.innerHTML = '';
      attacksWrap.innerHTML = '';
      return;
    }

    if (key === 'lowe-attack') {
      const keys = await buildNsKeys();
      const lowe = await runLoweAttack(keys);
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(lowe.messages)}` +
        resultLine(!lowe.bobAccepted, `Bob accepted forged run: ${lowe.bobAccepted}. Bob believes peer = ${lowe.bobBelievesPeer}; Alice believes peer = ${lowe.aliceBelievesPeer}.`);
      inspectors.innerHTML = '';
      etypeWrap.innerHTML = '';
      attacksWrap.innerHTML = '';
      return;
    }

    if (key === 'lowe-fix') {
      const keys = await buildNsKeys();
      const fixed = await runNeedhamSchroederWithLoweFix(keys);
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(fixed.messages)}` +
        resultLine(fixed.accepted, `Accepted: ${fixed.accepted}. Identity binding in message 2 blocks substitution.`);
      inspectors.innerHTML = '';
      etypeWrap.innerHTML = '';
      attacksWrap.innerHTML = '';
      return;
    }

    const kerberos = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', nowMs);
    flow.innerHTML =
      `${flowHeader(meta)}${renderKerberosFlow(kerberos.records)}` +
      resultLine(kerberos.apAccepted, `AP exchange accepted: ${kerberos.apAccepted}.`);
    inspectors.innerHTML =
      `<div class="panel"><span class="kicker">TGT</span><h3>Ticket-Granting Ticket</h3>${renderTicketInspector('TGT', kerberos.tgt.cipher)}</div>` +
      `<div class="panel"><span class="kicker">Service Ticket</span><h3>HTTP service ticket</h3>${renderTicketInspector('Service Ticket', kerberos.serviceTicket.cipher)}</div>`;
    etypeWrap.innerHTML = `<div class="panel"><span class="kicker">Step 3 \u2014 Crypto detail</span><h2>Encryption type</h2>${await renderETypePanel(serviceKey)}</div>`;
    attacksWrap.innerHTML = `<div class="panel"><span class="kicker">Step 4 \u2014 Attack panel</span><h2>What can go wrong</h2><div class="attack-list">${await renderAttackPanel(nowMs, Date.now() + 4 * 60 * 60 * 1000)}</div></div>`;
  }

  byId<HTMLButtonElement>('run').addEventListener('click', () => { void runScenario(); });
  clock.addEventListener('input', () => { void runScenario(); });
  scenario.addEventListener('change', () => { void runScenario(); });

  await runScenario();
}
