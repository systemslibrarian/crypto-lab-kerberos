import { renderAttackPanel } from './ui/attack-panel';
import { renderETypePanel } from './ui/etype-panel';
import { renderKerberosFlow, renderNsFlow } from './ui/message-flow';
import { renderTicketInspector } from './ui/ticket-inspector';
import { buildNsKeys, runNeedhamSchroeder } from './protocols/needham-schroeder';
import { runLoweAttackAgainstFix, runNeedhamSchroederWithLoweFix } from './protocols/lowe-fix';
import { runLoweAttack } from './attacks/lowe-attack';
import { KeyDistributionCenter, type TicketBody } from './principals/kdc';
import { ServicePrincipal } from './principals/service';
import { replayApReq, runKerberosV5, type KerberosRun } from './protocols/kerberos-v5';
import { decryptAes256CtsHmacSha196, encryptAes256CtsHmacSha196 } from './crypto/etype-aes256';
import { pbkdf2HmacSha1 } from './crypto/pbkdf2-string2key';
import { dk, hex, utf8Bytes } from './crypto/simplified-profile';

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
  { key: 'lowe-fix', label: 'Lowe Fix', year: '1995', blurb: 'Identity binding in message 2 — the same relay re-run against the patched protocol, where it dies.' },
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
  // The glyph carries the pass/fail state for users who can't perceive the
  // red/green colour (WCAG 1.4.1). The visually-hidden word does the same for
  // screen readers without doubling up the glyph.
  return `<div class="flow-result ${ok ? 'ok' : 'bad'}"><span class="result-glyph" aria-hidden="true">${ok ? '✓' : '✗'}</span><span class="sr-only">${ok ? 'Pass: ' : 'Fail: '}</span>${escape(message)}</div>`;
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
    // `accepted` here means "the attack was blocked" — the flow above is the
    // Lowe relay run against the PATCHED protocol, not an honest exchange.
    return `<div class="explainer"><h3>The one-line patch, under attack</h3>
      <p>Add Bob\u2019s identity to message 2. Alice now decrypts <code>{N<sub>a</sub>, N<sub>b</sub>, B}<sub>pk(A)</sub></code> and checks the embedded name against the peer she actually dialled. If Mallory relays, the name inside is "Bob" but Alice called Mallory — mismatch, abort.</p>
      ${LOWE_DIFF}
      <p>The flow above is <b>Mallory running the identical 1995 relay against the patched protocol</b> — same opening move, same re-seal, same relayed reply. Compare it step for step with <em>Lowe Attack</em>: only message 2 changed.</p>
      <p>${accepted
        ? `<b>The attack dies at step 4</b> — ${escape(extra ?? 'identity mismatch')}. Alice never returns N<sub>b</sub>, so Mallory has nothing to forward and Bob is never fooled: steps 5 and 6 of the attack simply never happen.`
        : '<b>The attack completed</b> — the identity check did not fire.'}</p>
    </div>`;
  }
  return kerberosExplainer(accepted, extra);
}

// Anchored to the scenario change: the single biggest conceptual jump in the lab
// is public-key (NS/Lowe) -> symmetric-key + trusted KDC (Kerberos). Without this
// signpost a newcomer carries an "it's all one evolving protocol" model into the
// hardest section. Shown only for the Kerberos scenario, above the swimlane.
const KERBEROS_SIGNPOST = `<div class="signpost" role="note" aria-label="The cryptography just changed">
  <span class="signpost-icon" aria-hidden="true">⇄</span>
  <div>
    <b>Heads up — the cryptography just changed.</b> Needham-Schroeder used
    <em>public keys, one keypair per party</em>; the fix was to patch an
    identity-binding bug in one message. Kerberos throws that model out: a single
    <b>trusted Key Distribution Center (KDC)</b> shares a <em>symmetric</em>
    long-term key with every principal and hands out short-lived tickets. Different
    trust model, no per-party public keys, no identity-binding bug to patch — the
    defenses below (replay cache, clock skew, ticket expiry) are what a KDC needs
    instead.
  </div>
</div>`;

// Three-box "why three round-trips" primer. Progressive disclosure: instead of
// dropping all six Kerberos messages at once, name the three exchanges first.
const KERBEROS_ORIENTATION = `<div class="orient" aria-label="The three Kerberos exchanges">
  <span class="kicker">First, the shape — why three round-trips</span>
  <div class="orient-grid">
    <div class="orient-card">
      <span class="orient-tag">AS</span>
      <b>Prove your password, once.</b>
      <p>The <em>Authentication Service</em> checks your key (derived from your password) and issues a <b>TGT</b> — a ticket that says “this client is authenticated.” You do this a single time per login.</p>
    </div>
    <div class="orient-card">
      <span class="orient-tag">TGS</span>
      <b>Trade the TGT for a service ticket.</b>
      <p>The <em>Ticket-Granting Service</em> takes your TGT and mints a <b>service ticket</b> for one specific service. Your password is never touched again — the TGT stands in for it.</p>
    </div>
    <div class="orient-card">
      <span class="orient-tag">AP</span>
      <b>Present the ticket to the service.</b>
      <p>The <em>Application exchange</em> hands the service ticket to the server with a fresh, timestamped <b>authenticator</b>. This is where replay and clock-skew defenses fire. Watch below.</p>
    </div>
  </div>
  <p class="orient-foot">Splitting it three ways means your password proves identity <b>once</b>, then a cache of tickets does the rest — that is the whole point of single sign-on.</p>
</div>`;

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

// Honest scope statement, on screen rather than only in the README. A teaching
// demo earns trust by naming what it is NOT, and "raw bytes" in this lab means
// JSON — a reader deserves to be told that without having to read the source.
interface ScopeCard {
  heading: string;
  bullets: string[];
}

const SCOPE: ScopeCard[] = [
  {
    heading: 'What this models faithfully',
    bullets: [
      'aes256-cts-hmac-sha1-96 (etype 18) as specified: CTS-CBC over AES-256 plus a truncated HMAC-SHA1-96, with the RFC 3961 DK/DR key derivation and the RFC 4120 §7.5.1 key usage numbers.',
      'string-to-key: PBKDF2-HMAC-SHA1 at 4096 iterations then n-fold/DK, checked live on every page load against the published RFC 3962 §B vector.',
      'The AS / TGS / AP exchanges end to end, with each ticket encrypted under a key its holder cannot read (the krbtgt key for the TGT, the service key for the service ticket).',
      'Pre-authentication: PA-ENC-TIMESTAMP (padata-type 2, key usage 1) is built by the client and verified by the KDC before any AS-REP is issued. The <code>pre-authent</code> ticket flag is set only when that verification actually happened.',
      'The AS-REP nonce echo, the (cname, ctime, cusec) replay cache, the ±5-minute clock-skew check, and ticket starttime/endtime validation — each rejects real ciphertext, not a simulated failure.',
      'Needham-Schroeder over real RSA-OAEP-2048, Lowe’s relay against it, and the same relay against the patched protocol.',
    ],
  },
  {
    heading: 'What this deliberately does NOT model',
    bullets: [
      '<b>ASN.1/DER.</b> Ticket bodies, authenticators, and everything shown under “Raw bytes” are JSON that is then encrypted for real. RFC 4120 puts DER on the wire; the ciphertext here is genuine, the encoding inside it is not.',
      '<b>One realm, no cross-realm.</b> There is no inter-realm krbtgt, no referral chasing, no trust hierarchy.',
      '<b>No PAC.</b> The Microsoft AD authorization-data blob (group SIDs and its signatures) is absent, so nothing here shows how Kerberos carries authorization rather than authentication.',
      'No KRB-ERROR messages on the wire, no KDC option negotiation, no renewable/proxiable/forwardable ticket handling.',
      'No network at all: no UDP/TCP port 88, no DNS SRV discovery, no credential cache on disk — the <code>klist -e</code> inspector is a rendering, not a real ccache.',
      'One encryption type (18) and one kvno. No etype negotiation, no key rotation, no PKINIT, no FAST armoring, no OTP or smartcard pre-auth types.',
    ],
  },
  {
    heading: 'Where exactness is compressed for teaching',
    bullets: [
      'The AS exchange runs on the KDC clock: the client’s PA-ENC-TIMESTAMP is stamped with it, so the clock slider demonstrates skew at the AP exchange, where the threat panel explains it. A real KDC would <em>also</em> refuse a skewed AS-REQ with <code>KDC_ERR_PREAUTH_FAILED</code>.',
      'The KDC and the service share one clock; the slider skews only the client relative to that pair.',
      'The 1978 and 1995 scenarios use RSA-OAEP because that is what the browser offers. Needham-Schroeder predates OAEP; the relay property the attack turns on is unaffected by the padding.',
      'The replay cache is an in-memory Map belonging to one service process, pruned by the skew window. Real deployments need this shared across every replica of a service.',
      'The AS-REP-roasting exhibit in the threat panel cracks a deliberately weak password from a four-word list. Real offline cracking runs billions of candidates against the same ciphertext — the mechanism is identical, the scale is not.',
    ],
  },
];

function renderScopePanel(): string {
  const cards = SCOPE.map(
    (s) => `<div class="scope-card">
      <h3>${escape(s.heading)}</h3>
      <ul class="scope-list">${s.bullets.map((b) => `<li>${b}</li>`).join('')}</ul>
    </div>`,
  ).join('');
  return `<span class="kicker">Honest limits</span>
    <h2>What this demo is, and is not</h2>
    <p style="color: var(--text-dim); font-size: 12.5px; margin-bottom: 10px;">The cryptography below the protocol is real and vector-checked. The protocol encoding above it is not RFC 4120 on the wire. Both statements matter, so both are on screen.</p>
    <div class="scope-grid">${cards}</div>`;
}

function renderTimeline(active: ScenarioKey): string {
  return `<aside class="timeline" aria-label="Timeline">
    <span class="kicker">47 years</span>
    <ol>
      ${SCENARIOS.map((s) => `<li data-key="${s.key}" class="${s.key === active ? 'active' : ''}">
          <button type="button" class="timeline-step"${s.key === active ? ' aria-current="true"' : ''}>
            <span class="year">${escape(s.year)}</span>
            <span class="label">${escape(s.label)}</span>
          </button>
        </li>`).join('')}
    </ol>
  </aside>`;
}

export async function renderApp(root: HTMLElement): Promise<void> {
  root.innerHTML = `
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Kerberos</h1>
      <p class="cl-hero-sub">Needham-Schroeder \u2192 Lowe fix \u2192 Kerberos v5 \u00b7 RFC 4120</p>
      <p class="cl-hero-desc">Step through the arc from Needham-Schroeder (1978) and Lowe\u2019s man-in-the-middle fix (1995) to Kerberos v5, watching a KDC issue AES-256 tickets while replays and clock skew get rejected in real WebCrypto.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Every domain login and single sign-on trusts a third party you never see. A subtle protocol flaw lets one attacker impersonate anyone \u2014 which is why Lowe\u2019s fix and Kerberos\u2019 replay and clock-skew defenses exist.</p>
    </aside>
  </header>

  <div class="layout">
    <div id="timeline-mount"></div>
    <div class="main">
      <section id="selfcheck-panel" class="panel" aria-label="Self-check">
        <span class="kicker">Live verification</span>
        <h2>Self-check</h2>
        <p style="color: var(--text-dim); margin-bottom: 10px; font-size: 12.5px;">These checks run on every page load against the actual crypto in your browser — including a published <b>RFC 3962 §B</b> known-answer vector. If any go red, the demo isn't trustworthy.</p>
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
            <input id="clock" type="range" min="-15" max="15" step="1" value="0" aria-describedby="clock-value clock-status" list="skew-ticks" />
            <datalist id="skew-ticks">
              <option value="-5"></option>
              <option value="0"></option>
              <option value="5"></option>
            </datalist>
            <div class="skew-scale" aria-hidden="true">
              <span class="skew-mark" style="left: 33.33%;">−5</span>
              <span class="skew-mark" style="left: 66.66%;">+5</span>
              <span class="skew-band"></span>
            </div>
          </div>
          <div class="field" id="clock-value-field">
            <label for="clock-value">Skew</label>
            <output id="clock-value" for="clock" aria-live="polite">0 min</output>
            <span id="clock-status" class="skew-badge ok" role="status">
              <span class="skew-badge-glyph" aria-hidden="true">✓</span> within ±5 min tolerance
            </span>
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
      <section id="scope-panel" class="panel" aria-label="Scope and limitations"></section>
    </div>
  </div>
`;

  byId<HTMLElement>('scope-panel').innerHTML = renderScopePanel();

  const scenario = byId<HTMLSelectElement>('scenario');
  const clock = byId<HTMLInputElement>('clock');
  const clockField = byId<HTMLElement>('clock-field');
  const clockValueField = byId<HTMLElement>('clock-value-field');
  const clockValue = byId<HTMLOutputElement>('clock-value');
  const clockStatus = byId<HTMLElement>('clock-status');

  // Self-teaching skew badge: turns the ±5 min boundary into something you SEE as
  // you drag, so the defense is discoverable without having to fail a run first.
  function paintSkewBadge(offsetMin: number): void {
    const withinTolerance = Math.abs(offsetMin) <= 5;
    clockStatus.classList.toggle('ok', withinTolerance);
    clockStatus.classList.toggle('bad', !withinTolerance);
    clockStatus.innerHTML = withinTolerance
      ? '<span class="skew-badge-glyph" aria-hidden="true">✓</span> within ±5 min tolerance'
      : '<span class="skew-badge-glyph" aria-hidden="true">✗</span> SKEW — outside ±5 min, AP will reject';
  }
  const blurb = byId<HTMLElement>('scenario-blurb');
  const flow = byId<HTMLElement>('flow');
  const inspectors = byId<HTMLElement>('inspectors');
  const etypeWrap = byId<HTMLElement>('etype-wrap');
  const attacksWrap = byId<HTMLElement>('attacks-wrap');
  const timelineMount = byId<HTMLElement>('timeline-mount');
  const replayMount = byId<HTMLElement>('replay-mount');
  const selfcheckMount = byId<HTMLElement>('selfcheck');

  let lastKerberos: KerberosRun | null = null;
  // Dragging the clock slider (or rapid clicks) fires runScenario() repeatedly,
  // and each run is full of awaits. Without this, a slower earlier run can finish
  // after a newer one and paint stale output. Each run takes a token; a run only
  // paints while it is still the latest.
  let runToken = 0;

  function paintReplayPanel(replayBadge?: { ok: boolean; text: string; note: string }): void {
    if (!lastKerberos || !lastKerberos.apAccepted) {
      replayMount.classList.add('hidden');
      replayMount.innerHTML = '';
      return;
    }
    replayMount.classList.remove('hidden');
    const cacheSize = service.replayCache.size;
    const apReqBytes = lastKerberos.lastApReq?.length ?? 0;
    const badge = replayBadge
      ? `<span class="badge ${replayBadge.ok ? 'ok' : 'bad'}">${escape(replayBadge.text)}</span>`
      : '';
    const note = replayBadge ? `<p class="replay-note">${escape(replayBadge.note)}</p>` : '';
    replayMount.innerHTML = `
      <span class="kicker">Replay defense</span>
      <h2>Try to replay the AP-REQ</h2>
      <p style="color: var(--text-dim); font-size: 12.5px;">The service stores <code>(cname, ctime, cusec)</code> for every accepted authenticator. This button re-submits the <b>${apReqBytes} captured AP-REQ bytes</b> from the run above — the same ciphertext, unmodified — to the same service. It decrypts and its HMAC verifies exactly as before; it is refused anyway, purely on freshness.</p>
      <div class="action-row">
        <button id="replay-btn" type="button">Replay last AP-REQ</button>
        <span class="hint">Replay cache size: <b>${cacheSize}</b></span>
        ${badge}
      </div>
      ${note}`;
    const btn = document.getElementById('replay-btn');
    if (btn) {
      btn.addEventListener('click', () => {
        void (async () => {
          const run = lastKerberos;
          if (!run || !run.lastApReq) return;
          // A real replay: the captured authenticator ciphertext goes back to
          // the service, which decrypts it under the ticket session key and
          // verifies the HMAC-SHA1-96 tag before the freshness check ever runs.
          const replayed = await replayApReq(
            service,
            run.serviceTicket,
            run.lastAuth.cname,
            run.clientSvcKey,
            run.lastApReq,
            run.serviceNowMs,
          );
          const verified = replayed.cryptoVerified
            ? `AES-256-CTS decrypt + HMAC-SHA1-96 verify on ${run.lastApReq.length} resubmitted bytes: OK`
            : 'the service could not decrypt the resubmitted bytes';
          paintReplayPanel(
            replayed.accepted
              ? { ok: true, text: 'accepted', note: `${verified} — and no cache entry matched, so it was accepted.` }
              : {
                  ok: false,
                  text: `rejected: ${replayed.reason ?? 'unknown'}`,
                  note: `${verified} — the cryptography passed. Rejected afterwards: (cname, ctime, cusec) = (${run.lastAuth.cname}, ${run.lastAuth.ctime}, ${run.lastAuth.cusec}) was already in the replay cache.`,
                },
          );
        })();
      });
    }
  }

  async function runSelfCheck(): Promise<void> {
    const checks: { name: string; ok: boolean; msg: string }[] = [];

    // 0. RFC 3962 §B string-to-key known-answer vector — proves the in-browser
    //    derivation (PBKDF2 → n-fold → DR/DK) interoperates with real Kerberos,
    //    not merely with itself.
    try {
      const tkey = await pbkdf2HmacSha1('password', 'ATHENA.MIT.EDUraeburn', 1200);
      const got = hex(await dk(tkey, utf8Bytes('kerberos')));
      const want = '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a';
      const ok = got === want;
      checks.push({ name: 'RFC 3962 §B s2k vector', ok, msg: ok ? `matches ${want.slice(0, 8)}…` : 'MISMATCH' });
    } catch (e) {
      checks.push({ name: 'RFC 3962 §B s2k vector', ok: false, msg: String(e) });
    }

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
      .map((c) => `<div class="check ${c.ok ? 'ok' : 'bad'}"><span class="pip" aria-hidden="true">${c.ok ? '✓' : '✗'}</span><span class="sr-only">${c.ok ? 'Pass:' : 'Fail:'}</span><span class="name">${escape(c.name)}</span><span class="msg">${escape(c.msg)}</span></div>`)
      .join('');
  }

  function paintTimeline(key: ScenarioKey): void {
    timelineMount.innerHTML = renderTimeline(key);
    timelineMount.querySelectorAll<HTMLButtonElement>('.timeline-step').forEach((btn) => {
      // Native <button>, so Enter/Space activation and focus come for free.
      btn.addEventListener('click', () => {
        const k = btn.closest('li')?.getAttribute('data-key') as ScenarioKey | null;
        if (!k) return;
        scenario.value = k;
        void runScenario();
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
    const myToken = ++runToken;
    const superseded = (): boolean => myToken !== runToken;

    // The KDC and service run on the true clock (baseNow); the slider skews the
    // client's clock relative to it, which is what drives the AP skew defense.
    const baseNow = Date.now();
    const offsetMin = Number.parseInt(clock.value, 10);
    const offset = offsetMin * 60 * 1000;
    const clientNowMs = baseNow + offset;
    const nowMs = baseNow;
    clockValue.textContent = `${offsetMin > 0 ? '+' : ''}${offsetMin} min`;
    paintSkewBadge(offsetMin);

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
      if (superseded()) return;
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(ns.messages, 'scenario-ns')}` +
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
      if (superseded()) return;
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(lowe.messages, 'scenario-lowe-attack')}` +
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
      // The point of the fix is what it does to the ATTACK, so that is what the
      // flow shows: Mallory's relay, run against the patched protocol. The
      // honest run is computed too, to prove the patch didn't break the
      // protocol for legitimate parties — both results are live.
      const underAttack = await runLoweAttackAgainstFix(keys);
      const honest = await runNeedhamSchroederWithLoweFix(keys);
      if (superseded()) return;
      flow.innerHTML =
        `${flowHeader(meta)}${renderNsFlow(underAttack.messages, 'scenario-lowe-fix')}` +
        resultLine(
          underAttack.aliceAborted && !underAttack.bobAccepted,
          underAttack.aliceAborted
            ? `Attack blocked at step 4 — ${underAttack.rejectedReason}. Bob accepted forged run: ${underAttack.bobAccepted}.`
            : `Attack succeeded: Bob accepted forged run: ${underAttack.bobAccepted}.`,
        ) +
        resultLine(
          honest.accepted,
          honest.accepted
            ? 'Honest direct run (Alice to Bob, no Mallory) still completes in 3 messages — the patch does not break legitimate use.'
            : `Honest direct run rejected: ${honest.rejectedReason}.`,
        ) +
        explainerFor(key, underAttack.aliceAborted, underAttack.rejectedReason ?? undefined);
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

    const kerberos = await runKerberosV5(kdc, service, 'alice', 'correct-horse-battery-staple', clientNowMs, nowMs);
    if (superseded()) return;
    lastKerberos = kerberos;
    flow.innerHTML =
      `${flowHeader(meta)}${KERBEROS_SIGNPOST}${KERBEROS_ORIENTATION}${renderKerberosFlow(kerberos.records)}` +
      resultLine(kerberos.apAccepted, kerberos.apAccepted ? 'AP exchange accepted.' : `AP exchange rejected: ${kerberos.apReason ?? 'unknown'}.`) +
      explainerFor(key, kerberos.apAccepted, kerberos.apReason);

    const tgtBody: TicketBody = await kdc.decryptTgt(kerberos.tgt);
    const stClear = await decryptAes256CtsHmacSha196(fromHex(service.keyHex), 2, kerberos.serviceTicket.cipher);
    const stBody: TicketBody = JSON.parse(decoder.decode(stClear));
    if (superseded()) return;

    inspectors.classList.remove('hidden');
    inspectors.innerHTML =
      `<div class="panel"><span class="kicker">TGT</span><h3>Ticket-Granting Ticket · klist -e</h3>${renderTicketInspector(kerberos.tgt, tgtBody, nowMs)}</div>` +
      `<div class="panel"><span class="kicker">Service Ticket</span><h3>http/web.lab.example · klist -e</h3>${renderTicketInspector(kerberos.serviceTicket, stBody, nowMs)}</div>`;

    paintReplayPanel();

    const etypeHtml = await renderETypePanel(serviceKeyBytes);
    if (superseded()) return;
    etypeWrap.classList.remove('hidden');
    etypeWrap.innerHTML = `<div class="panel"><span class="kicker">Step 3 \u2014 Crypto detail</span><h2>Encryption type</h2>${etypeHtml}</div>`;

    const attacksHtml = await renderAttackPanel(nowMs, nowMs + 4 * 60 * 60 * 1000);
    if (superseded()) return;
    attacksWrap.classList.remove('hidden');
    attacksWrap.innerHTML = `<div class="panel"><span class="kicker">Step 4 \u2014 Threat model</span><h2>What can go wrong</h2><p style="color: var(--text-dim); font-size: 12.5px; margin-bottom: 4px;">Grouped by the defense that stops each attack. Each card opens to show what an attacker tries and what Kerberos does about it. Hover the <span class="jargon" style="cursor:help;">dotted terms</span> for a definition.</p><div class="defense-groups">${attacksHtml}</div></div>`;
  }

  byId<HTMLButtonElement>('run').addEventListener('click', () => { void runScenario(); });
  clock.addEventListener('input', () => {
    // Repaint the badge synchronously on every drag tick so the ±5 min boundary is
    // felt live, even though the full crypto re-run is async and debounced by token.
    paintSkewBadge(Number.parseInt(clock.value, 10));
    clockValue.textContent = `${Number.parseInt(clock.value, 10) > 0 ? '+' : ''}${Number.parseInt(clock.value, 10)} min`;
    void runScenario();
  });
  scenario.addEventListener('change', () => { void runScenario(); });

  void runSelfCheck();
  await runScenario();
}
