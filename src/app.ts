import { renderAttackPanel } from './ui/attack-panel';
import { renderETypePanel } from './ui/etype-panel';
import { renderKerberosFlow, renderNsFlow } from './ui/message-flow';
import { renderTicketInspector } from './ui/ticket-inspector';
import { buildNsKeys, runNeedhamSchroeder } from './protocols/needham-schroeder';
import { runNeedhamSchroederWithLoweFix } from './protocols/lowe-fix';
import { runLoweAttack } from './attacks/lowe-attack';
import { KeyDistributionCenter, type TicketBody } from './principals/kdc';
import { ServicePrincipal } from './principals/service';
import { runKerberosV5, type KerberosRun } from './protocols/kerberos-v5';
import { decryptAes256CtsHmacSha196, encryptAes256CtsHmacSha196 } from './crypto/etype-aes256';

type ScenarioKey = 'ns' | 'lowe-attack' | 'lowe-fix' | 'kerberos';

interface ScenarioMeta {
  key: ScenarioKey;
  label: string;
  year: string;
  blurb: string;
}

const SCENARIOS: ScenarioMeta[] = [
  { key: 'ns', label: 'Needham-Schroeder', year: '1978', blurb: 'Original public-key protocol — looks secure for 17 years.' },
  { key: 'lowe-attack', label: 'Lowe Attack', year: '1995', blurb: 'Gavin Lowe\u2019s man-in-the-middle on NSPK, found by FDR model checker.' },
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

function fromHex(input: string): Uint8Array {
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const decoder = new TextDecoder();

const LOWE_DIFF = `<div class="diff" aria-label="Lowe fix diff">
  <div class="row del"><span class="sigil">−</span><span class="text">B → A : { N<sub>a</sub>, N<sub>b</sub> }<sub>pk(A)</sub></span></div>
  <div class="row add"><span class="sigil">+</span><span class="text">B → A : { N<sub>a</sub>, N<sub>b</sub>, <b>B</b> }<sub>pk(A)</sub></span></div>
</div>`;

function explainerFor(key: ScenarioKey, accepted: boolean, extra?: string): string {
  if (key === 'ns') {
    return `<div class="explainer"><h3>What just happened</h3>
      <p>Three messages, two parties, three nonces. Alice and Bob each end up convinced they share fresh secrets — and on a closed network they do. The protocol authenticates correctly when no one is in the middle.</p>
      <p><b>The catch:</b> message 2 (<code>{N<sub>a</sub>, N<sub>b</sub>}<sub>pk(A)</sub></code>) doesn\u2019t name Bob. If Alice was actually talking to a third party, she\u2019d still accept the response as if it were Bob\u2019s. Switch to <em>Lowe Attack</em> to watch that get exploited.</p>
    </div>`;
  }
  if (key === 'lowe-attack') {
    return `<div class="explainer"><h3>Why this works (1995)</h3>
      <p>Alice voluntarily initiates a session with Mallory — a perfectly legal thing to do. Mallory then opens a parallel session with Bob, impersonating Alice, and uses Alice as an oracle to decrypt Bob\u2019s nonce.</p>
      <p>${accepted
        ? '<b>Bob accepted the run as Alice</b>, even though Alice never tried to talk to Bob. Mallory now holds both nonces and can speak as Alice on Bob\u2019s session.'
        : 'Bob rejected the run.'} ${extra ?? ''}</p>
      <p>Found by Gavin Lowe at Oxford using the FDR refinement checker — 17 years after Needham &amp; Schroeder published the protocol.</p>
    </div>`;
  }
  if (key === 'lowe-fix') {
    return `<div class="explainer"><h3>The one-line patch</h3>
      <p>Add Bob\u2019s identity to message 2. Alice now decrypts <code>{N<sub>a</sub>, N<sub>b</sub>, B}<sub>pk(A)</sub></code> and verifies the embedded name matches her intended peer. If Mallory tries to relay, the name inside is "Bob" but Alice was talking to Mallory — mismatch, abort.</p>
      ${LOWE_DIFF}
      <p>${accepted ? '<b>Run accepted</b> — identity binding holds when Alice and Bob really are talking directly.' : `<b>Run aborted</b> — ${escape(extra ?? 'identity mismatch detected')}.`}</p>
    </div>`;
  }
  return kerberosExplainer(accepted, extra);
}

function kerberosExplainer(accepted: boolean, reason?: string): string {
  const r = (reason ?? '').toLowerCase();
  let why = '';
  if (!accepted) {
    if (r.includes('skew')) {
      why = `<p><b>Why it failed:</b> the authenticator's <code>ctime</code> differed from the service clock by more than 5 minutes. Slide the clock back to <b>0</b> and re-run.</p>`;
    } else if (r.includes('replay')) {
      why = `<p><b>Why it failed:</b> the service's replay cache already contained a (cname, ctime, cusec) tuple matching this authenticator. The first request succeeded; this one is a duplicate.</p>`;
    } else if (r.includes('expired')) {
      why = `<p><b>Why it failed:</b> the service ticket's <code>endtime</code> is in the past. The KDC must mint a new one.</p>`;
    } else {
      why = `<p><b>Why it failed:</b> ${escape(reason ?? 'unknown')}.</p>`;
    }
  }
  return `<div class="explainer"><h3>Why Kerberos is different</h3>
    <p>No public-key crypto in the inner loop, no identity-binding bug to fix — instead, a <b>trusted KDC</b> mints short-lived tickets bound to specific (client, service) pairs. Every authenticator carries a timestamp; the service keeps a replay cache; clocks must agree within 5 minutes.</p>
    <p>${accepted ? '<b>AP exchange accepted</b> — service authenticated the client and replied with mutual auth.' : '<b>AP exchange rejected.</b>'}</p>
    ${why}
    <p>Try sliding the clock past <b>±5 min</b> and re-running. Then click <em>Replay last AP-REQ</em> below the tickets to watch the replay cache fire.</p>
  </div>`;
}

function renderTimeline(active: ScenarioKey): string {
  return `<aside class="timeline" aria-label="Timeline">
    <span class="kicker">47 years</span>
    <ol>
      ${SCENARIOS.map((s) => `<li data-key="${s.key}" class="${s.key === active ? 'active' : ''}" role="button" tabindex="0"${s.key === active ? ' aria-current="true"' : ''}>
          <span class="year">${escape(s.year)}</span>
          <span class="label">${escape(s.label)}</span>
        </li>`).join('')}
    </ol>
  </aside>`;
}

export async function renderApp(root: HTMLElement): Promise<void> {
  root.innerHTML = `
  <section class="hero" aria-labelledby="hero-title">
    <div class="hero-body">
      <div class="hero-left">
        <span class="eyebrow">Authentication Protocol Lab</span>
        <h1 id="hero-title">Forty-seven years of <span>authentication</span>.</h1>
      </div>
      <div class="hero-right">
        <p>Walk the arc from Needham-Schroeder (1978) through Gavin Lowe\u2019s man-in-the-middle (1995) to Kerberos v5 (RFC 4120), with real AES-256-CTS-HMAC-SHA1-96 encryption running in your browser via WebCrypto. Watch tickets get issued, replays get caught, and clock skew kill an exchange.</p>
        <div class="hero-stats">
          <span class="hero-stat">RFC 3961 / 3962</span>
          <span class="hero-stat">RFC 4120</span>
          <span class="hero-stat">AES-256-CTS-HMAC-SHA1-96</span>
          <span class="hero-stat">PBKDF2-HMAC-SHA1 \u00d7 4096</span>
          <span class="hero-stat">@noble/hashes</span>
        </div>
      </div>
    </div>
  </section>

  <div class="layout">
    <div id="timeline-mount"></div>
    <div class="main">
      <section id="selfcheck-panel" class="panel" aria-label="Self-check">
        <span class="kicker">Live verification</span>
        <h2>Self-check</h2>
        <p style="color: var(--text-dim); margin-bottom: 10px; font-size: 12.5px;">These three checks run on every page load against the actual crypto in your browser. If any go red, the demo isn't trustworthy.</p>
        <div id="selfcheck" class="selfcheck"></div>
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
          <div class="field" id="clock-field">
            <label for="clock">Clock offset (Kerberos)</label>
            <input id="clock" type="range" min="-15" max="15" step="1" value="0" aria-describedby="clock-value" />
          </div>
          <div class="field" id="clock-value-field">
            <label for="clock-value">Skew</label>
            <output id="clock-value" for="clock" aria-live="polite">0 min</output>
          </div>
          <div class="field">
            <label>&nbsp;</label>
            <button id="run" type="button">Re-run \u2192</button>
          </div>
        </div>
        <p id="scenario-blurb" style="margin-top: 14px; color: var(--text-dim); font-size: 12.5px;"></p>
      </section>

      <section id="flow" class="panel" role="region" aria-live="polite" aria-label="Protocol message flow"></section>
      <section id="inspectors" class="grid hidden" role="region" aria-label="Ticket inspector"></section>
      <section id="replay-mount" class="panel hidden" aria-label="Replay control"></section>
      <section id="etype-wrap" class="hidden" role="region" aria-label="Encryption type details"></section>
      <section id="attacks-wrap" class="hidden" role="region" aria-label="Attack outcomes"></section>
    </div>
  </div>
`;

  const scenario = byId<HTMLSelectElement>('scenario');
  const clock = byId<HTMLInputElement>('clock');
  const clockField = byId<HTMLElement>('clock-field');
  const clockValueField = byId<HTMLElement>('clock-value-field');
  const clockValue = byId<HTMLOutputElement>('clock-value');
  const blurb = byId<HTMLElement>('scenario-blurb');
  const flow = byId<HTMLElement>('flow');
  const inspectors = byId<HTMLElement>('inspectors');
  const etypeWrap = byId<HTMLElement>('etype-wrap');
  const attacksWrap = byId<HTMLElement>('attacks-wrap');
  const timelineMount = byId<HTMLElement>('timeline-mount');
  const replayMount = byId<HTMLElement>('replay-mount');
  const selfcheckMount = byId<HTMLElement>('selfcheck');

  let lastKerberos: KerberosRun | null = null;

  function paintReplayPanel(replayBadge?: { ok: boolean; text: string }): void {
    if (!lastKerberos || !lastKerberos.apAccepted) {
      replayMount.classList.add('hidden');
      replayMount.innerHTML = '';
      return;
    }
    replayMount.classList.remove('hidden');
    const cacheSize = service.replayCache.size;
    const badge = replayBadge
      ? `<span class="badge ${replayBadge.ok ? 'ok' : 'bad'}">${escape(replayBadge.text)}</span>`
      : '';
    replayMount.innerHTML = `
      <span class="kicker">Replay defense</span>
      <h2>Try to replay the AP-REQ</h2>
      <p style="color: var(--text-dim); font-size: 12.5px;">The service stores <code>(cname, ctime, cusec)</code> for every accepted authenticator. Re-submitting the exact same ciphertext should be rejected even though the cipher and HMAC verify perfectly.</p>
      <div class="action-row">
        <button id="replay-btn" type="button">Replay last AP-REQ</button>
        <span class="hint">Replay cache size: <b>${cacheSize}</b></span>
        ${badge}
      </div>`;
    const btn = document.getElementById('replay-btn');
    if (btn) {
      btn.addEventListener('click', () => {
        if (!lastKerberos) return;
        const { cname, ctime, cusec } = lastKerberos.lastAuth;
        const replayKey = `${cname}:${ctime}:${cusec}`;
        if (service.hasReplay(replayKey)) {
          paintReplayPanel({ ok: false, text: 'rejected: replay cache hit' });
        } else {
          // Genuinely fresh (unlikely — the original AP succeeded so it's already cached)
          service.rememberReplay(replayKey, Date.now());
          paintReplayPanel({ ok: true, text: 'accepted (no prior entry)' });
        }
      });
    }
  }

  async function runSelfCheck(): Promise<void> {
    const checks: { name: string; ok: boolean; msg: string }[] = [];

    // 1. AES-256-CTS-HMAC-SHA1-96 round-trip
    try {
      const k = new Uint8Array(32); crypto.getRandomValues(k);
      const pt = new TextEncoder().encode('the quick brown fox');
      const ct = await encryptAes256CtsHmacSha196(k, 7, pt);
      const out = await decryptAes256CtsHmacSha196(k, 7, ct.raw);
      const ok = out.length === pt.length && out.every((b, i) => b === pt[i]);
      checks.push({ name: 'AES-256-CTS round-trip', ok, msg: ok ? `${ct.raw.length} bytes → ok` : 'mismatch' });
    } catch (e) {
      checks.push({ name: 'AES-256-CTS round-trip', ok: false, msg: String(e) });
    }

    // 2. HMAC tamper detection
    try {
      const k = new Uint8Array(32); crypto.getRandomValues(k);
      const ct = await encryptAes256CtsHmacSha196(k, 7, new TextEncoder().encode('payload'));
      const tampered = ct.raw.slice();
      tampered[tampered.length - 1] ^= 0x01; // flip last bit of HMAC
      let detected = false;
      try { await decryptAes256CtsHmacSha196(k, 7, tampered); }
      catch { detected = true; }
      checks.push({ name: 'HMAC tamper detection', ok: detected, msg: detected ? 'rejected forged ciphertext' : 'FAILED to detect tampering' });
    } catch (e) {
      checks.push({ name: 'HMAC tamper detection', ok: false, msg: String(e) });
    }

    // 3. AS → TGS → AP end-to-end
    try {
      const probeKdc = new KeyDistributionCenter('SELFCHECK');
      await probeKdc.registerUser('probe', 'pw');
      const sk = probeKdc.registerService('svc/probe');
      const svc = new ServicePrincipal('svc/probe', 'SELFCHECK', Array.from(sk).map((v) => v.toString(16).padStart(2, '0')).join(''));
      const run = await runKerberosV5(probeKdc, svc, 'probe', 'pw', Date.now());
      checks.push({ name: 'AS → TGS → AP round-trip', ok: run.apAccepted, msg: run.apAccepted ? `${run.records.length} messages → ok` : (run.apReason ?? 'rejected') });
    } catch (e) {
      checks.push({ name: 'AS → TGS → AP round-trip', ok: false, msg: String(e) });
    }

    selfcheckMount.innerHTML = checks
      .map((c) => `<div class="check ${c.ok ? 'ok' : 'bad'}"><span class="pip" aria-label="${c.ok ? 'pass' : 'fail'}"></span><span class="name">${escape(c.name)}</span><span class="msg">${escape(c.msg)}</span></div>`)
      .join('');
  }

  function paintTimeline(key: ScenarioKey): void {
    timelineMount.innerHTML = renderTimeline(key);
    timelineMount.querySelectorAll<HTMLLIElement>('li[data-key]').forEach((li) => {
      const activate = (): void => {
        const k = li.getAttribute('data-key') as ScenarioKey | null;
        if (!k) return;
        scenario.value = k;
        void runScenario();
      };
      li.addEventListener('click', activate);
      li.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
      });
    });
  }

  const kdc = new KeyDistributionCenter('LAB.EXAMPLE');
  await kdc.registerUser('alice', 'correct-horse-battery-staple');
  const serviceKeyBytes = kdc.registerService('http/web.lab.example', randomHex(32));
  const service = new ServicePrincipal(
    'http/web.lab.example',
    'LAB.EXAMPLE',
    Array.from(serviceKeyBytes).map((v) => v.toString(16).padStart(2, '0')).join(''),
  );

  function setScenarioClass(key: ScenarioKey): void {
    flow.classList.remove('scenario-ns', 'scenario-lowe-attack', 'scenario-lowe-fix', 'scenario-kerberos');
    flow.classList.add(`scenario-${key}`);
  }

  function flowHeader(meta: ScenarioMeta): string {
    return `
      <span class="kicker">Step 2 \u2014 Message flow</span>
      <h2>${escape(meta.label)} <span style="color: var(--text-dim); font-family: var(--mono); font-size: 0.6em; letter-spacing: 0.1em; margin-left: 10px;">${escape(meta.year)}</span></h2>
      <p style="color: var(--text-dim); margin-bottom: 4px;">${escape(meta.blurb)}</p>`;
  }

  async function runScenario(): Promise<void> {
    const baseNow = Date.now();
    const offsetMin = Number.parseInt(clock.value, 10);
    const offset = offsetMin * 60 * 1000;
    const nowMs = baseNow + offset;
    clockValue.textContent = `${offsetMin > 0 ? '+' : ''}${offsetMin} min`;

    const key = scenario.value as ScenarioKey;
    const meta = SCENARIOS.find((s) => s.key === key) ?? SCENARIOS[0];
    blurb.textContent = meta.blurb;
    setScenarioClass(key);
    paintTimeline(key);

    const showClock = key === 'kerberos';
    clockField.classList.toggle('hidden', !showClock);
    clockValueField.classList.toggle('hidden', !showClock);

    if (key === 'ns') {
      const keys = await buildNsKeys();
      const ns = await runNeedhamSchroeder(keys);
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(ns.messages)}` +
        resultLine(ns.accepted, ns.accepted ? 'Bob accepted Alice as authenticated.' : 'Bob rejected the run.') +
        explainerFor(key, ns.accepted);
      inspectors.innerHTML = '';
      inspectors.classList.add('hidden');
      replayMount.innerHTML = '';
      replayMount.classList.add('hidden');
      etypeWrap.innerHTML = '';
      etypeWrap.classList.add('hidden');
      attacksWrap.innerHTML = '';
      attacksWrap.classList.add('hidden');
      return;
    }

    if (key === 'lowe-attack') {
      const keys = await buildNsKeys();
      const lowe = await runLoweAttack(keys);
      const detail = `Alice believed peer = ${lowe.aliceBelievesPeer}. Bob believed peer = ${lowe.bobBelievesPeer}.`;
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(lowe.messages)}` +
        resultLine(!lowe.bobAccepted, `Bob accepted forged run: ${lowe.bobAccepted}. ${detail}`) +
        explainerFor(key, lowe.bobAccepted, detail);
      inspectors.innerHTML = '';
      inspectors.classList.add('hidden');
      replayMount.innerHTML = '';
      replayMount.classList.add('hidden');
      etypeWrap.innerHTML = '';
      etypeWrap.classList.add('hidden');
      attacksWrap.innerHTML = '';
      attacksWrap.classList.add('hidden');
      return;
    }

    if (key === 'lowe-fix') {
      const keys = await buildNsKeys();
      const fixed = await runNeedhamSchroederWithLoweFix(keys);
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(fixed.messages)}` +
        resultLine(fixed.accepted, `Accepted: ${fixed.accepted}. Identity binding in message 2 blocks substitution.`) +
        explainerFor(key, fixed.accepted, fixed.rejectedReason ?? undefined);
      inspectors.innerHTML = '';
      inspectors.classList.add('hidden');
      replayMount.innerHTML = '';
      replayMount.classList.add('hidden');
      etypeWrap.innerHTML = '';
      etypeWrap.classList.add('hidden');
      attacksWrap.innerHTML = '';
      attacksWrap.classList.add('hidden');
      return;
    }

    const kerberos = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', nowMs);
    lastKerberos = kerberos;
    flow.innerHTML =
      `${flowHeader(meta)}${renderKerberosFlow(kerberos.records)}` +
      resultLine(kerberos.apAccepted, kerberos.apAccepted ? 'AP exchange accepted.' : `AP exchange rejected: ${kerberos.apReason ?? 'unknown'}.`) +
      explainerFor(key, kerberos.apAccepted, kerberos.apReason);

    const tgtBody: TicketBody = await kdc.decryptTgt(kerberos.tgt);
    const stClear = await decryptAes256CtsHmacSha196(fromHex(service.keyHex), 2, kerberos.serviceTicket.cipher);
    const stBody: TicketBody = JSON.parse(decoder.decode(stClear));

    inspectors.classList.remove('hidden');
    inspectors.innerHTML =
      `<div class="panel"><span class="kicker">TGT</span><h3>Ticket-Granting Ticket · klist -e</h3>${renderTicketInspector(kerberos.tgt, tgtBody, nowMs)}</div>` +
      `<div class="panel"><span class="kicker">Service Ticket</span><h3>http/web.lab.example · klist -e</h3>${renderTicketInspector(kerberos.serviceTicket, stBody, nowMs)}</div>`;

    paintReplayPanel();

    etypeWrap.classList.remove('hidden');
    etypeWrap.innerHTML = `<div class="panel"><span class="kicker">Step 3 \u2014 Crypto detail</span><h2>Encryption type</h2>${await renderETypePanel(serviceKeyBytes)}</div>`;

    attacksWrap.classList.remove('hidden');
    attacksWrap.innerHTML = `<div class="panel"><span class="kicker">Step 4 \u2014 Attack panel</span><h2>What can go wrong</h2><div class="attack-list">${await renderAttackPanel(nowMs, nowMs + 4 * 60 * 60 * 1000)}</div></div>`;
  }

  byId<HTMLButtonElement>('run').addEventListener('click', () => { void runScenario(); });
  clock.addEventListener('input', () => { void runScenario(); });
  scenario.addEventListener('change', () => { void runScenario(); });

  void runSelfCheck();
  await runScenario();
}
